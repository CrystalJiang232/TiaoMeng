#pragma once

#include <boost/asio.hpp>
#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/json.hpp>
#include <memory>
#include <unordered_map>
#include <string>
#include <string_view>
#include <vector>
#include <deque>
#include <cstddef>
#include <span>
#include <functional>
#include <optional>
#include <expected>
#include <bit>
#include <atomic>

#include <print>
#include <algorithm>
#include <ranges>

#include "cipher.hpp"
#include "msg.hpp"
#include "router.hpp"
#include "event_handler.hpp"

namespace net = boost::asio;
using tcp = net::ip::tcp;

class Connection;
class Server;
class Router;

enum class ConnState: uint8_t
{
    Connected,
    Handshaking,
    Established,
    Authenticated,  // New state after successful auth
    Closing,        // Reserved for async I/O: connection closing yet draining messages
    Rekeying,       // Reserved for round session key
};

// Request actions for business logic
enum class RequestAction : uint8_t
{
    Auth = 0x01,
    Command = 0x02,
    Broadcast = 0x03,
    Logout = 0x04,
    // Placeholder for future actions
};

class Server
{
public:
    Server(net::io_context& io, unsigned short port);
    void start();
    void remove_connection(std::string_view id);
    void broadcast(const Msg& msg, std::string_view exclude_id = "");
    Router* get_router() 
    { 
        return router.get(); 
    }

private:
    net::awaitable<void> do_accept();
    
    net::io_context& io_ctx;
    tcp::acceptor acceptor;
    std::unordered_map<std::string, std::shared_ptr<Connection>> connections;
    std::unique_ptr<Router> router;

};

class Connection : public std::enable_shared_from_this<Connection>
{
public:
    enum class CloseMode {
        DrainPipe,      // Graceful: drain queue, send error at end
        BestEffort,     // Quick: queue error, remove immediately  
        CancelOthers,   // Forceful: cancel I/O, send error, close
        Abort           // Immediate: cancel I/O, close (no error sent)
    };
    
    // Failure tracker for security monitoring
    struct FailureTracker
    {
        static constexpr size_t max_failures = 10;
        size_t count = 0;
        
        // Returns true if threshold exceeded
        bool record() 
        { 
            ++count; 
            return count >= max_failures; 
        }
        
        void reset() { count = 0; }
        bool threshold_exceeded() const { return count >= max_failures; }
    };

    Connection(tcp::socket, Server*, std::string);
    ~Connection() noexcept;
    void start();
    void send(const Msg& msg);
    void send_encrypted(const boost::json::object& json_obj, MsgType type = encrypted_response);
    void send_encrypted(const Msg& msg);
    std::string_view get_id() const { return id; }
    ConnState getstate() const {return state;}
    void setstate(ConnState newstate) {state = newstate;}

    void close(std::string_view err = "", CloseMode mode = CloseMode::CancelOthers);
    
    // Pipe health tracking
    void mark_pipe_dead() { dead_pipe.store(true); }
    bool is_pipe_dead() const { return dead_pipe.load() || !socket.is_open(); }
    
    // Cleanup helper
    void shutdown() noexcept;
    
    [[nodiscard]] bool has_session_key() const { return sess.is_established(); }
    [[nodiscard]] std::span<const uint8_t> session_key() const { return sess.key(); }
    [[nodiscard]] bool is_authenticated() const { return state == ConnState::Authenticated; }
    
    // Failure tracking
    bool record_failure() { return fail_tracker.record(); }
    void reset_failures() { fail_tracker.reset(); }
    
private:
    net::awaitable<void> read_header();
    net::awaitable<void> read_body(uint32_t len);
    net::awaitable<void> write();
    net::awaitable<void> close_async(std::string_view = "", CloseMode = CloseMode::BestEffort);
    
    // I/O cancellation helpers
    void cancel_all_io();
    void clear_write_queue();
    
    // Handshake handlers
    net::awaitable<void> handle_handshake(const Msg& msg);
    net::awaitable<void> handle_encrypted(const Msg& msg);
    
    // Request handler (new)
    net::awaitable<void> handle_request(const boost::json::object& request);
    
    // Action handlers are now in EventHandler namespace
    // Friend declaration to allow EventHandler access to private members if needed
    friend void EventHandler::handle_auth(std::shared_ptr<Connection>, const boost::json::object&);
    friend void EventHandler::handle_command(std::shared_ptr<Connection>, const boost::json::object&);
    friend void EventHandler::handle_broadcast(std::shared_ptr<Connection>, const boost::json::object&);
    friend void EventHandler::handle_logout(std::shared_ptr<Connection>);
    
    // Bidirectional KEM state
    Kyber768 kem;
    std::optional<Kyber768::keypair_t> kp;
    std::optional<Kyber768::shared_secret_t> ss_local;
    std::optional<Kyber768::shared_secret_t> ss_remote;
    SessionKey sess;
    std::optional<Kyber768::key_t> client_pk;
    std::optional<Kyber768::shared_secret_t> ss_A;

    tcp::socket socket;
    Server* server;
    std::string id;
    std::vector<std::byte> read_buf;
    std::vector<std::byte> write_buf;
    std::deque<Msg> write_queue;

    ConnState state;
    bool write_in_progress = false;
    FailureTracker fail_tracker;
    std::atomic<bool> dead_pipe{false};  // Track pipe health
};

template<>
struct std::formatter<tcp::socket>
{
    constexpr auto parse(std::format_parse_context& fpc)
    {
        return fpc.begin();
    }

    auto format(const tcp::socket& socket,std::format_context& fc) const
    {
        return std::format_to(fc.out(),"{}:{}",socket.remote_endpoint().address().to_string(),
        std::to_string(socket.remote_endpoint().port()));
    }
};
