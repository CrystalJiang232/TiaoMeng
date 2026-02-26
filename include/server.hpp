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
#include <shared_mutex>

#include "fundamentals/types.hpp"
#include "crypto/kyber768.hpp"
#include "crypto/session_key.hpp"
#include "crypto/utils.hpp"
#include "logger/metrics.hpp"
#include "json_utils.hpp"
#include "event_handler.hpp"
#include "threadpool/threadpool.hpp"

// Forward declaration
class Config;

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

class ConnectionsMap
{
public:
    void insert(std::string id, std::shared_ptr<Connection> conn);
    void erase(std::string_view id);
    [[nodiscard]] std::shared_ptr<Connection> find(std::string_view id) const;
    [[nodiscard]] std::vector<std::shared_ptr<Connection>> snapshot() const;
    [[nodiscard]] size_t size() const;

private:
    mutable std::shared_mutex mtx;
    std::unordered_map<std::string, std::shared_ptr<Connection>> conns;
};

class Server
{
public:
    Server(net::io_context& io, const Config& config);
    ~Server();
    void start();
    void remove_connection(std::string_view id);
    void broadcast(const Msg& msg, std::string_view exclude_id = "");
    
    [[nodiscard]] ThreadPool& cpu_pool() { return tp; }
    [[nodiscard]] const ThreadPool& cpu_pool() const { return tp; }
    
    [[nodiscard]] ServerMetrics& metrics() { return mts; }
    [[nodiscard]] const ServerMetrics& metrics() const { return mts; }

    [[nodiscard]] size_t connection_count() const { return connections.size(); }

private:
    net::awaitable<void> do_accept();
    void setup_signal_handlers();
    void on_signal(int signal);
    
    net::io_context& io_ctx;
    tcp::acceptor acceptor;
    net::signal_set signals;
    net::signal_set metrics_signals;
    ConnectionsMap connections;
    const Config& cfg;
    ServerMetrics mts;
    ThreadPool tp;
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
        const size_t max_failures = 5;
        std::atomic<size_t> count{0};
        
        explicit FailureTracker(size_t max_fail = 5) : max_failures(max_fail) {}
        
        [[nodiscard("record() returns whether count has exceeded max failure after pre self-increment.")]] bool record()
        {
            return ++count >= max_failures;
        }
        
        void reset() { count.store(0, std::memory_order_relaxed); }
        [[nodiscard]] bool threshold_exceeded() const { return count.load(std::memory_order_relaxed) >= max_failures; }
    };

    Connection(tcp::socket, Server*, std::string, const Config& config, net::io_context& io);
    ~Connection() noexcept;
    void start();
    void send(const Msg& msg);
    void send_encrypted(const boost::json::object& json_obj, MsgType type = encrypted_response);
    void send_encrypted(const Msg& msg);
    [[nodiscard]] std::string_view get_id() const { return id; }
    [[nodiscard]] ConnState getstate() const { return state.load(std::memory_order_acquire); }
    void setstate(ConnState newstate) { state.store(newstate, std::memory_order_release); }

    void close(CloseMode mode = CloseMode::CancelOthers);
    
    void mark_pipe_dead() { dead_pipe.store(true); }
    [[nodiscard]] bool is_pipe_dead() const { return dead_pipe.load() || !socket.is_open(); }
    void shutdown() noexcept;
    
    [[nodiscard]] bool has_session_key() const { return sess.is_established(); }
    [[nodiscard]] std::span<const uint8_t> session_key() const { return sess.key(); }
    [[nodiscard]] bool is_authenticated() const { return state == ConnState::Authenticated; }
    
    bool record_failure() { return fail_tracker.record(); }
    void reset_failures() { fail_tracker.reset(); }

    void send_raw_error(std::string_view err, CloseMode mode = CloseMode::CancelOthers);
    [[nodiscard("Do not discard send_error's value: caller is responsible for co_return upon this function returning true to prevent connection leakage. Use std::ignore or void cast for explicit schematics.")]]
    bool send_error(std::string_view err, CloseMode mode = CloseMode::CancelOthers, bool force_close = false);
    void reset_session_timer();
    
private:
    struct IoResult
    {
        boost::system::error_code ec;
        size_t bytes = 0;
        bool timed_out = false;
    };
    
    net::awaitable<void> read_header();
    net::awaitable<void> read_body(uint32_t len);
    net::awaitable<void> write();
    net::awaitable<void> close_async(CloseMode mode = CloseMode::BestEffort);
    
    net::awaitable<IoResult> read_with_timeout(net::mutable_buffer buf, std::chrono::seconds timeout);
    net::awaitable<IoResult> write_with_timeout(const Msg& msg, std::chrono::seconds timeout);
    void on_global_timeout();
    void reset_global_timer(std::chrono::seconds duration);
    void cancel_global_timer();
    
    void cancel_all_io();
    void clear_write_queue();
    
    net::awaitable<void> handle_handshake(const Msg& msg);
    net::awaitable<void> handle_encrypted(const Msg& msg);
    net::awaitable<void> handle_request(const boost::json::object& request);
    
    EventHandler evt_hdl;
    
    crypto::Kyber768 kem;
    std::optional<crypto::Kyber768::keypair_t> kp;
    std::optional<crypto::Kyber768::shared_secret_t> ss_local;
    std::optional<crypto::Kyber768::shared_secret_t> ss_remote;
    crypto::SessionKey sess;
    std::optional<crypto::Kyber768::key_t> client_pk;
    std::optional<crypto::Kyber768::shared_secret_t> ss_A;

    net::strand<net::any_io_executor> strand;
    tcp::socket socket;
    Server* server;
    std::string id;
    std::vector<std::byte> read_buf;
    std::vector<std::byte> write_buf;
    mutable std::mutex write_mtx;
    std::deque<Msg> write_queue;

    std::atomic<ConnState> state;
    std::atomic<bool> write_in_progress{false};
    FailureTracker fail_tracker;
    std::atomic<bool> dead_pipe{false};
    const Config& cfg;
    net::steady_timer global_timer;

    friend class EventHandler;
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
