#pragma once

#include <boost/asio.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/json.hpp>
#include <expected>
#include <optional>
#include <deque>
#include <mutex>
#include <atomic>

#include "client/client_config.hpp"
#include "client/metrics.hpp"
#include "fundamentals/types.hpp"
#include "crypto/kyber768.hpp"
#include "crypto/session_key.hpp"

namespace net = boost::asio;
using tcp = net::ip::tcp;
namespace json = boost::json;

enum class ClientState : uint8_t
{
    Disconnected,
    Connecting,
    HandshakeStep1,
    HandshakeStep2,
    Established,
    Authenticated,
    Closing
};

class Client : public std::enable_shared_from_this<Client>
{
public:
    struct IoResult
    {
        boost::system::error_code ec;
        size_t bytes = 0;
    };

    explicit Client(const ClientConfig& cfg);
    explicit Client(const ClientConfig& cfg, net::io_context& external_io);
    ~Client() noexcept;

    Client(const Client&) = delete;
    Client& operator=(const Client&) = delete;
    Client(Client&&) = delete;
    Client& operator=(Client&&) = delete;

    // Async API (Phase 1)
    [[nodiscard]] net::awaitable<std::expected<void, std::string>> async_connect();
    [[nodiscard]] net::awaitable<std::expected<void, std::string>> async_disconnect();
    [[nodiscard]] net::awaitable<std::expected<void, std::string>> async_handshake();
    [[nodiscard]] net::awaitable<std::expected<void, std::string>> async_auth(
        std::string_view username, std::string_view password);
    [[nodiscard]] net::awaitable<std::expected<json::object, std::string>> async_send_command(
        const json::object& data);
    [[nodiscard]] net::awaitable<std::expected<json::object, std::string>> async_send_broadcast(
        std::string_view message);
    [[nodiscard]] net::awaitable<std::expected<void, std::string>> async_logout();
    
    // Main loop for load test
    [[nodiscard]] net::awaitable<void> run(
        std::optional<std::reference_wrapper<MetricsCollector>> metrics = std::nullopt);

    // Sync API (Phase 2)
    // WARNING: Sync API requires Client to own its io_context (default constructor).
    // Using these with external io_context (Client(cfg, external_io)) will deadlock
    // unless io_context is already running in another thread. Use async_* methods instead.
    // TODO: Consider adding std::unexpected return for external io_context misuse.
    [[nodiscard]] std::expected<void, std::string> connect();
    [[nodiscard]] std::expected<void, std::string> disconnect();
    [[nodiscard]] std::expected<void, std::string> handshake();
    [[nodiscard]] std::expected<void, std::string> authenticate(
        std::string_view username, std::string_view password);
    [[nodiscard]] std::expected<json::object, std::string> send_command(
        const json::object& data);
    [[nodiscard]] std::expected<json::object, std::string> send_broadcast(
        std::string_view message);
    [[nodiscard]] std::expected<void, std::string> logout();
    void run_interactive();

    // State inspection
    [[nodiscard]] ClientState getState() const { return state.load(std::memory_order_acquire); }
    [[nodiscard]] bool is_connected() const;
    [[nodiscard]] bool is_established() const { return cipher.is_established(); }
    [[nodiscard]] bool is_authenticated() const;

private:
    // Core I/O (server pattern)
    [[nodiscard]] net::awaitable<std::optional<IoResult>> readWithTimeout(
        net::mutable_buffer buf, std::chrono::seconds timeout);
    [[nodiscard]] net::awaitable<std::optional<IoResult>> writeWithTimeout(
        net::const_buffer buf, std::chrono::seconds timeout);
    
    [[nodiscard]] net::awaitable<std::expected<Msg, std::string>> read_msg(std::chrono::seconds timeout);
    [[nodiscard]] net::awaitable<std::expected<void, std::string>> send_msg(const Msg& msg);
    
    // Handshake steps (client-side initiator)
    [[nodiscard]] net::awaitable<std::expected<void, std::string>> handshakeStep1();
    [[nodiscard]] net::awaitable<std::expected<void, std::string>> handshakeStep2();
    [[nodiscard]] net::awaitable<std::expected<void, std::string>> handshakeStep3();
    
    // Loops
    [[nodiscard]] net::awaitable<void> readLoop();
    [[nodiscard]] net::awaitable<void> writeLoop();
    [[nodiscard]] net::awaitable<bool> sendLoop(
        const ClientConfig& cfg, MetricsCollector& mts);
    
    // Write queue management
    void enqueue_msg(const Msg& msg);
    
    // State management
    void setState(ClientState new_state);
    void shutdown() noexcept;
    void clearCrypto() noexcept;
    
    // Members
    const ClientConfig cfg;
    bool owns_io_ctx;
    
    // I/O
    std::optional<net::io_context> io_ctx_storage;
    net::io_context& io_ctx;
    net::strand<net::any_io_executor> strand;
    tcp::socket sock;
    
    // Crypto
    crypto::Kyber768 kem;
    crypto::SessionKey cipher;
    std::optional<crypto::Kyber768::keypair_t> kp;
    std::optional<crypto::Kyber768::shared_secret_t> ss_local;
    std::optional<crypto::Kyber768::shared_secret_t> ss_remote;
    
    // State
    std::atomic<ClientState> state{ClientState::Disconnected};
    
    // Buffers
    std::vector<std::byte> read_buf;
    
    // Write queue
    std::deque<Msg> write_queue;
    std::mutex write_mtx;
    std::atomic<bool> write_in_progress{false};
    
    // Metrics reference (optional)
    std::optional<std::reference_wrapper<MetricsCollector>> metrics;
};
