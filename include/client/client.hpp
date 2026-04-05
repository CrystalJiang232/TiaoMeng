#pragma once

#include <boost/asio.hpp>
#include <boost/json.hpp>
#include <string>
#include <string_view>
#include <cstdint>
#include <span>
#include <expected>
#include "fundamentals/types.hpp"
#include "crypto/kyber768.hpp"
#include "crypto/session_key.hpp"

namespace net = boost::asio;
using tcp = net::ip::tcp;

class Client
{
public:
    enum class State
    {
        Disconnected,
        Connected,
        Handshaking,
        Established,
        Authenticated
    };

    Client(std::string host, uint16_t port);
    ~Client() noexcept;

    Client(const Client&) = delete;
    Client& operator=(const Client&) = delete;
    Client(Client&&) noexcept = default;
    Client& operator=(Client&&) noexcept = default;

    [[nodiscard]] std::expected<void, std::string> connect();
    [[nodiscard]] std::expected<void, std::string> disconnect();

    [[nodiscard]] std::expected<void, std::string> perform_handshake();
    [[nodiscard]] std::expected<void, std::string> authenticate(std::string_view username, std::string_view password);

    [[nodiscard]] std::expected<boost::json::object, std::string> send_command(const boost::json::object& data);
    [[nodiscard]] std::expected<boost::json::object, std::string> send_broadcast(std::string_view message);
    [[nodiscard]] std::expected<void, std::string> logout();

    [[nodiscard]] State get_state() const { return state; }
    [[nodiscard]] bool is_connected() const { return state != State::Disconnected; }
    [[nodiscard]] bool is_authenticated() const { return state == State::Authenticated; }

    [[nodiscard]] std::expected<void, std::string> process_command(std::string_view line);
    void run_interactive_loop();

private:
    [[nodiscard]] net::awaitable<std::expected<void, std::string>> do_connect();
    [[nodiscard]] net::awaitable<std::expected<void, std::string>> do_handshake();
    [[nodiscard]] net::awaitable<std::expected<void, std::string>> do_authenticate(std::string_view username, std::string_view password);
    [[nodiscard]] net::awaitable<std::expected<boost::json::object, std::string>> do_send_command(const boost::json::object& data);
    [[nodiscard]] net::awaitable<std::expected<boost::json::object, std::string>> do_send_broadcast(std::string_view message);
    [[nodiscard]] net::awaitable<std::expected<void, std::string>> do_logout();
    [[nodiscard]] net::awaitable<std::expected<boost::json::object, std::string>> recv_response(std::chrono::seconds timeout);
    [[nodiscard]] net::awaitable<std::expected<Msg, std::string>> recv_msg(std::chrono::seconds timeout);

    [[nodiscard]] std::expected<void, std::string> send_raw(std::span<const std::byte> payload, MsgType type);

    void change_state(State new_state);
    void shutdown() noexcept;

    net::io_context io_ctx;
    std::string host;
    uint16_t port;

    tcp::socket sock;
    crypto::Kyber768 kem;
    crypto::SessionKey cipher;

    std::optional<crypto::Kyber768::keypair_t> kp;
    std::optional<crypto::Kyber768::shared_secret_t> ss_local;
    std::optional<crypto::Kyber768::shared_secret_t> ss_remote;

    State state;
};
