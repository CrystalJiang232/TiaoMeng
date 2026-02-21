#pragma once

#include <boost/asio.hpp>
#include <boost/json.hpp>
#include <string>
#include <string_view>
#include <cstdint>
#include <span>
#include <optional>
#include <expected>
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

    Client(net::io_context& io, std::string host, unsigned short port);
    ~Client() noexcept;

    Client(const Client&) = delete;
    Client& operator=(const Client&) = delete;
    Client(Client&&) noexcept = default;
    Client& operator=(Client&&) noexcept = default;

    [[nodiscard]] bool connect();
    void disconnect();
    
    [[nodiscard]] bool perform_handshake();
    [[nodiscard]] bool authenticate(std::string_view username, std::string_view password);
    
    [[nodiscard]] bool send_command(const boost::json::object& data);
    [[nodiscard]] bool send_broadcast(const boost::json::object& data);
    [[nodiscard]] bool logout();
    
    [[nodiscard]] std::optional<boost::json::object> recv_response(int timeout_sec = 5);
    
    [[nodiscard]] State get_state() const { return state; }
    [[nodiscard]] bool is_connected() const { return state != State::Disconnected; }
    [[nodiscard]] bool is_authenticated() const { return state == State::Authenticated; }

private:
    [[nodiscard]] bool send_json_request(std::string_view action, const boost::json::object& data);
    [[nodiscard]] std::optional<boost::json::object> parse_json_response(std::span<const uint8_t> data);
    
    void change_state(State new_state);
    void shutdown() noexcept;
    
    net::io_context& io_ctx;
    std::string host;
    unsigned short port;
    
    std::unique_ptr<tcp::socket> socket;
    std::unique_ptr<crypto::Kyber768> kem;
    std::unique_ptr<crypto::SessionKey> cipher;
    
    State state;
    std::vector<uint8_t> read_buf;
};
