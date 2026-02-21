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
#include "event_handler.hpp"

namespace net = boost::asio;
using tcp = net::ip::tcp;

class Connection;
class Server;

enum class ConnState: uint8_t
{
    Connected,
    Handshaking,
    Established,
    Authenticated,
    Closing,
    Rekeying,
};

enum class RequestAction : uint8_t
{
    Auth = 0x01,
    Command = 0x02,
    Broadcast = 0x03,
    Logout = 0x04,
};

class Server
{
public:
    Server(net::io_context& io, unsigned short port);
    void start();
    void remove_connection(std::string_view id);
    void broadcast(const Msg& msg, std::string_view exclude_id = "");

private:
    net::awaitable<void> do_accept();
    
    net::io_context& io_ctx;
    tcp::acceptor acceptor;
    std::unordered_map<std::string, std::shared_ptr<Connection>> connections;
};

class Connection : public std::enable_shared_from_this<Connection>
{
public:
    enum class CloseMode
    {
        DrainPipe,
        BestEffort,
        CancelOthers,
        Abort
    };
    
    struct FailureTracker
    {
        static constexpr size_t max_failures = 5;
        size_t count = 0;
        
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
    
    void mark_pipe_dead() { dead_pipe.store(true); }
    bool is_pipe_dead() const { return dead_pipe.load() || !socket.is_open(); }
    void shutdown() noexcept;
    
    [[nodiscard]] bool has_session_key() const { return sess.is_established(); }
    [[nodiscard]] std::span<const uint8_t> session_key() const { return sess.key(); }
    [[nodiscard]] bool is_authenticated() const { return state == ConnState::Authenticated; }
    
    bool record_failure() { return fail_tracker.record(); }
    void reset_failures() { fail_tracker.reset(); }

    void send_raw_error(std::string_view err, CloseMode mode = CloseMode::CancelOthers);
    [[nodiscard]] bool send_error(std::string_view err, CloseMode mode = CloseMode::CancelOthers);
    
private:
    net::awaitable<void> read_header();
    net::awaitable<void> read_body(uint32_t len);
    net::awaitable<void> write();
    net::awaitable<void> close_async(std::string_view = "", CloseMode = CloseMode::BestEffort);
    
    void cancel_all_io();
    void clear_write_queue();
    
    net::awaitable<void> handle_handshake(const Msg& msg);
    net::awaitable<void> handle_encrypted(const Msg& msg);
    net::awaitable<void> handle_request(const boost::json::object& request);
    
    EventHandler evt_hdl;
    
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
    std::atomic<bool> dead_pipe{false};
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
