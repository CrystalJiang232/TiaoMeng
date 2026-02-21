#include "client.hpp"
#include "msg.hpp"
#include <boost/asio.hpp>
#include <boost/json.hpp>
#include <algorithm>
#include <ranges>

namespace json = boost::json;
using namespace boost::asio;

Client::Client(net::io_context& io, std::string host, unsigned short port)
    : io_ctx(io)
    , host(std::move(host))
    , port(port)
    , state(State::Disconnected)
{
}

Client::~Client() noexcept
{
    shutdown();
}

bool Client::connect()
{
    if (state != State::Disconnected)
    {
        return false;
    }
    
    try
    {
        tcp::resolver resolver(io_ctx);
        auto endpoints = resolver.resolve(host, std::to_string(port));
        
        socket = std::make_unique<tcp::socket>(io_ctx);
        boost::asio::connect(*socket, endpoints);
        
        change_state(State::Connected);
        return true;
    }
    catch (...)
    {
        return false;
    }
}

void Client::disconnect()
{
    shutdown();
}

bool Client::perform_handshake()
{
    if (state != State::Connected)
    {
        return false;
    }
    
    kem = std::make_unique<crypto::Kyber768>();
    auto kp_result = kem->generate_keypair();
    if (!kp_result)
    {
        return false;
    }
    
    change_state(State::Handshaking);
    
    // TODO: Complete handshake implementation
    // This is a skeleton - full implementation needed
    
    return false;
}

bool Client::authenticate(std::string_view username, std::string_view password)
{
    if (state != State::Established)
    {
        return false;
    }
    
    json::object auth_data;
    auth_data["username"] = std::string(username);
    auth_data["password"] = std::string(password);
    
    if (!send_json_request("auth", auth_data))
    {
        return false;
    }
    
    auto response = recv_response();
    if (!response)
    {
        return false;
    }
    
    auto status_it = response->find("status");
    if (status_it == response->end())
    {
        return false;
    }
    
    if (status_it->value().as_string() == "Success")
    {
        change_state(State::Authenticated);
        return true;
    }
    
    return false;
}

bool Client::send_command(const json::object& data)
{
    return send_json_request("command", data);
}

bool Client::send_broadcast(const json::object& data)
{
    return send_json_request("broadcast", data);
}

bool Client::logout()
{
    if (state != State::Authenticated)
    {
        return false;
    }
    
    json::object empty_data;
    if (!send_json_request("logout", empty_data))
    {
        return false;
    }
    
    auto response = recv_response();
    if (!response)
    {
        return false;
    }
    
    auto status_it = response->find("status");
    if (status_it != response->end() && status_it->value().as_string() == "Success")
    {
        change_state(State::Established);
        return true;
    }
    
    return false;
}

std::optional<json::object> Client::recv_response(int timeout_sec)
{
    (void)timeout_sec;
    return std::nullopt;
}

bool Client::send_json_request(std::string_view action, const json::object& data)
{
    (void)action;
    (void)data;
    return false;
}

std::optional<json::object> Client::parse_json_response(std::span<const uint8_t> data)
{
    (void)data;
    return std::nullopt;
}

void Client::change_state(State new_state)
{
    state = new_state;
}

void Client::shutdown() noexcept
{
    try
    {
        if (socket && socket->is_open())
        {
            boost::system::error_code ec;
            socket->close(ec);
        }
        socket.reset();
        kem.reset();
        cipher.reset();
        state = State::Disconnected;
    }
    catch (...)
    {
    }
}
