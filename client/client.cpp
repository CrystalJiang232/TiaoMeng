#include "client/client.hpp"

#include "fundamentals/bytes.hpp"
#include "fundamentals/msg_serialize.hpp"
#include "fundamentals/json_utils.hpp"
#include "crypto/utils.hpp"
#include <boost/asio.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <ranges>
#include <format>
#include <print>
#include <iostream>
#include <sstream>

namespace json = boost::json;
using namespace bytes;
using namespace msg;
using net::experimental::awaitable_operators::operator||;

Client::Client(std::string h, uint16_t p)
    : host(std::move(h))
    , port(p)
    , sock(io_ctx)
    , state(State::Disconnected)
{
}

Client::~Client() noexcept
{
    shutdown();
}

std::expected<void, std::string> Client::connect()
{
    if (state != State::Disconnected)
    {
        return std::unexpected("Already connected");
    }

    auto result = net::co_spawn(io_ctx, do_connect(), net::use_future);
    io_ctx.run();
    io_ctx.restart();

    if (!result.valid())
    {
        return std::unexpected("Connection operation failed");
    }

    auto ret = result.get();
    if (!ret)
    {
        return ret;
    }

    change_state(State::Connected);
    return {};
}

net::awaitable<std::expected<void, std::string>> Client::do_connect()
{
    tcp::resolver resolver(io_ctx);
    auto [ec, results] = co_await resolver.async_resolve(host, std::to_string(port), net::as_tuple(net::use_awaitable));

    if (ec)
    {
        co_return std::unexpected(std::format("Resolve failed: {}", ec.message()));
    }

    auto [ec2, ep] = co_await net::async_connect(sock, results, net::as_tuple(net::use_awaitable));

    if (ec2)
    {
        co_return std::unexpected(std::format("Connect failed: {}", ec2.message()));
    }

    co_return std::expected<void, std::string>{};
}

std::expected<void, std::string> Client::disconnect()
{
    shutdown();
    return {};
}

std::expected<void, std::string> Client::perform_handshake()
{
    if (state != State::Connected)
    {
        return std::unexpected("Must be connected before handshake");
    }

    change_state(State::Handshaking);

    auto result = net::co_spawn(io_ctx, do_handshake(), net::use_future);
    io_ctx.run();
    io_ctx.restart();

    if (!result.valid())
    {
        change_state(State::Connected);
        return std::unexpected("Handshake operation failed");
    }

    auto ret = result.get();
    if (!ret)
    {
        change_state(State::Connected);
        return ret;
    }

    change_state(State::Established);
    return {};
}

net::awaitable<std::expected<void, std::string>> Client::do_handshake()
{
    auto kp_opt = kem.generate_keypair();
    if (!kp_opt)
    {
        co_return std::unexpected("Keypair generation failed");
    }

    kp = std::move(*kp_opt);

    auto step1 = msg::make(to_bytes<uint8_t>(kp->public_key), plaintext_handshake);
    if (!step1)
    {
        co_return std::unexpected("Failed to create handshake message");
    }

    auto [ec1, n1] = co_await net::async_write(sock, net::buffer(msg::serialize(*step1)), net::as_tuple(net::use_awaitable));
    if (ec1)
    {
        co_return std::unexpected(std::format("Handshake step1 write failed: {}", ec1.message()));
    }

    auto step2_result = co_await recv_msg(std::chrono::seconds(30));
    if (!step2_result)
    {
        co_return std::unexpected(step2_result.error());
    }

    auto step2 = std::move(*step2_result);
    size_t expected_size = crypto::Kyber768::public_key_size + crypto::Kyber768::ciphertext_size;
    if (step2.payload.size() < expected_size)
    {
        co_return std::unexpected("Invalid handshake response size");
    }

    std::span<const uint8_t> server_pk(
        reinterpret_cast<const uint8_t*>(step2.payload.data()),
        crypto::Kyber768::public_key_size
    );
    std::span<const uint8_t> server_ct(
        reinterpret_cast<const uint8_t*>(step2.payload.data()) + crypto::Kyber768::public_key_size,
        crypto::Kyber768::ciphertext_size
    );

    auto decap = kem.decapsulate(server_ct, kp->secret_key);
    if (!decap)
    {
        co_return std::unexpected("Decapsulation failed");
    }

    ss_local = std::move(*decap);

    auto encap = kem.encapsulate(server_pk);
    if (!encap)
    {
        co_return std::unexpected("Encapsulation failed");
    }

    ss_remote = std::move(encap->shared_secret);

    auto step3 = msg::make(to_bytes<uint8_t>(encap->ciphertext), plaintext_handshake);
    if (!step3)
    {
        co_return std::unexpected("Failed to create step3 message");
    }

    auto [ec3, n3] = co_await net::async_write(sock, net::buffer(msg::serialize(*step3)), net::as_tuple(net::use_awaitable));
    if (ec3)
    {
        co_return std::unexpected(std::format("Handshake step3 write failed: {}", ec3.message()));
    }

    cipher.complete_handshake(
        std::span<const uint8_t>(ss_remote->data(), ss_remote->size()),
        std::span<const uint8_t>(ss_local->data(), ss_local->size())
    );

    crypto::secure_clear(kp->secret_key);

    auto step4_result = co_await recv_msg(std::chrono::seconds(30));
    if (!step4_result)
    {
        co_return std::unexpected(step4_result.error());
    }

    auto step4 = std::move(*step4_result);
    auto decrypted = cipher.decrypt(
        std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(step4.payload.data()), step4.payload.size())
    );

    if (!decrypted)
    {
        co_return std::unexpected("Failed to decrypt handshake response");
    }

    std::string json_str(reinterpret_cast<const char*>(decrypted->data()), decrypted->size());
    json::error_code jec;
    auto parsed = json::parse(json_str, jec);

    if (jec || !parsed.is_object())
    {
        co_return std::unexpected("Invalid JSON in handshake response");
    }

    auto status = json_utils::extract_str(parsed.as_object(), "status");
    if (!status || *status != "ConnectionReady")
    {
        co_return std::unexpected(std::format("Unexpected handshake status: {}", status.value_or("<missing>")));
    }

    co_return std::expected<void, std::string>{};
}

std::expected<void, std::string> Client::authenticate(std::string_view username, std::string_view password)
{
    if (state != State::Established)
    {
        return std::unexpected("Must complete handshake before auth");
    }

    auto result = net::co_spawn(io_ctx, do_authenticate(username, password), net::use_future);
    io_ctx.run();
    io_ctx.restart();

    if (!result.valid())
    {
        return std::unexpected("Auth operation failed");
    }

    auto ret = result.get();
    if (!ret)
    {
        return ret;
    }

    change_state(State::Authenticated);
    return {};
}

net::awaitable<std::expected<void, std::string>> Client::do_authenticate(std::string_view username, std::string_view password)
{
    json::object req{{"action", "auth"}, {"username", std::string(username)}, {"password", std::string(password)}};
    auto json_str = json::serialize(req);
    std::vector<uint8_t> plaintext(json_str.begin(), json_str.end());

    auto encrypted = cipher.encrypt(plaintext);
    if (!encrypted)
    {
        co_return std::unexpected("Encryption failed");
    }

    auto payload = *encrypted
        | std::views::transform([](uint8_t x) { return bytes::int2byte(x); })
        | std::ranges::to<Msg::payload_t>();

    auto msg_result = msg::make(payload, encrypted_request);
    if (!msg_result)
    {
        co_return std::unexpected("Failed to create auth message");
    }

    auto [ec, n] = co_await net::async_write(sock, net::buffer(msg::serialize(*msg_result)), net::as_tuple(net::use_awaitable));
    if (ec)
    {
        co_return std::unexpected(std::format("Auth write failed: {}", ec.message()));
    }

    auto resp_result = co_await recv_response(std::chrono::seconds(30));
    if (!resp_result)
    {
        co_return std::unexpected(resp_result.error());
    }

    auto status = json_utils::extract_str(*resp_result, "status");
    if (!status || *status != "Success")
    {
        co_return std::unexpected(std::format("Auth failed: {}", status.value_or("<missing>")));
    }

    co_return std::expected<void, std::string>{};
}

std::expected<json::object, std::string> Client::send_command(const json::object& data)
{
    if (state != State::Authenticated)
    {
        return std::unexpected("Must be authenticated");
    }

    auto result = net::co_spawn(io_ctx, do_send_command(data), net::use_future);
    io_ctx.run();
    io_ctx.restart();

    if (!result.valid())
    {
        return std::unexpected("Command operation failed");
    }

    return result.get();
}

net::awaitable<std::expected<json::object, std::string>> Client::do_send_command(const json::object& data)
{
    json::object req = data;
    req["action"] = "command";

    auto json_str = json::serialize(req);
    std::vector<uint8_t> plaintext(json_str.begin(), json_str.end());

    auto encrypted = cipher.encrypt(plaintext);
    if (!encrypted)
    {
        co_return std::unexpected("Encryption failed");
    }

    auto payload = *encrypted
        | std::views::transform([](uint8_t x) { return bytes::int2byte(x); })
        | std::ranges::to<Msg::payload_t>();

    auto msg_result = msg::make(payload, encrypted_request);
    if (!msg_result)
    {
        co_return std::unexpected("Failed to create command message");
    }

    auto [ec, n] = co_await net::async_write(sock, net::buffer(msg::serialize(*msg_result)), net::as_tuple(net::use_awaitable));
    if (ec)
    {
        co_return std::unexpected(std::format("Command write failed: {}", ec.message()));
    }

    co_return co_await recv_response(std::chrono::seconds(30));
}

std::expected<json::object, std::string> Client::send_broadcast(std::string_view message)
{
    if (state != State::Authenticated)
    {
        return std::unexpected("Must be authenticated");
    }

    auto result = net::co_spawn(io_ctx, do_send_broadcast(message), net::use_future);
    io_ctx.run();
    io_ctx.restart();

    if (!result.valid())
    {
        return std::unexpected("Broadcast operation failed");
    }

    return result.get();
}

net::awaitable<std::expected<json::object, std::string>> Client::do_send_broadcast(std::string_view message)
{
    json::object req{{"action", "broadcast"}, {"message", std::string(message)}};

    auto json_str = json::serialize(req);
    std::vector<uint8_t> plaintext(json_str.begin(), json_str.end());

    auto encrypted = cipher.encrypt(plaintext);
    if (!encrypted)
    {
        co_return std::unexpected("Encryption failed");
    }

    auto payload = *encrypted
        | std::views::transform([](uint8_t x) { return bytes::int2byte(x); })
        | std::ranges::to<Msg::payload_t>();

    auto msg_result = msg::make(payload, encrypted_request);
    if (!msg_result)
    {
        co_return std::unexpected("Failed to create broadcast message");
    }

    auto [ec, n] = co_await net::async_write(sock, net::buffer(msg::serialize(*msg_result)), net::as_tuple(net::use_awaitable));
    if (ec)
    {
        co_return std::unexpected(std::format("Broadcast write failed: {}", ec.message()));
    }

    co_return co_await recv_response(std::chrono::seconds(30));
}

std::expected<void, std::string> Client::logout()
{
    if (state != State::Authenticated)
    {
        return std::unexpected("Not authenticated");
    }

    auto result = net::co_spawn(io_ctx, do_logout(), net::use_future);
    io_ctx.run();
    io_ctx.restart();

    if (!result.valid())
    {
        return std::unexpected("Logout operation failed");
    }

    auto ret = result.get();
    if (!ret)
    {
        return ret;
    }

    change_state(State::Established);
    return {};
}

net::awaitable<std::expected<void, std::string>> Client::do_logout()
{
    json::object req{{"action", "logout"}};
    auto json_str = json::serialize(req);
    std::vector<uint8_t> plaintext(json_str.begin(), json_str.end());

    auto encrypted = cipher.encrypt(plaintext);
    if (!encrypted)
    {
        co_return std::unexpected("Encryption failed");
    }

    auto payload = *encrypted
        | std::views::transform([](uint8_t x) { return bytes::int2byte(x); })
        | std::ranges::to<Msg::payload_t>();

    auto msg_result = msg::make(payload, encrypted_request);
    if (!msg_result)
    {
        co_return std::unexpected("Failed to create logout message");
    }

    auto [ec, n] = co_await net::async_write(sock, net::buffer(msg::serialize(*msg_result)), net::as_tuple(net::use_awaitable));
    if (ec)
    {
        co_return std::unexpected(std::format("Logout write failed: {}", ec.message()));
    }

    auto resp_result = co_await recv_response(std::chrono::seconds(30));
    if (!resp_result)
    {
        co_return std::unexpected(resp_result.error());
    }

    co_return std::expected<void, std::string>{};
}

net::awaitable<std::expected<json::object, std::string>> Client::recv_response(std::chrono::seconds timeout)
{
    auto msg_result = co_await recv_msg(timeout);
    if (!msg_result)
    {
        co_return std::unexpected(msg_result.error());
    }

    auto msg = std::move(*msg_result);
    auto decrypted = cipher.decrypt(
        std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(msg.payload.data()), msg.payload.size())
    );

    if (!decrypted)
    {
        co_return std::unexpected("Decryption failed");
    }

    std::string json_str(decrypted->begin(), decrypted->end());
    json::error_code jec;
    auto parsed = json::parse(json_str, jec);

    if (jec || !parsed.is_object())
    {
        co_return std::unexpected("Invalid JSON in response");
    }

    co_return parsed.as_object();
}

net::awaitable<std::expected<Msg, std::string>> Client::recv_msg(std::chrono::seconds timeout)
{
    net::steady_timer timer(io_ctx);
    timer.expires_after(timeout);

    auto read_op = [&]() -> net::awaitable<std::expected<Msg, std::string>>
    {
        std::array<std::byte, 5> hdr{};
        auto [ec1, n1] = co_await net::async_read(sock, net::buffer(hdr), net::as_tuple(net::use_awaitable));
        timer.cancel();

        if (ec1 || n1 != 5)
        {
            co_return std::unexpected(std::format("Header read failed: {} (read {} bytes)", ec1.message(), n1));
        }

        uint32_t len = bytes::to_int(hdr);
        if (len < 5 || len > Msg::max_len)
        {
            co_return std::unexpected("Invalid message length");
        }

        std::vector<std::byte> buf(len);
        std::ranges::copy(hdr, buf.begin());
        size_t body_len = len - 5;

        if (body_len > 0)
        {
            auto [ec2, n2] = co_await net::async_read(sock, net::buffer(buf.data() + 5, body_len), net::as_tuple(net::use_awaitable));
            if (ec2 || n2 != body_len)
            {
                co_return std::unexpected(std::format("Body read failed: {} (read {} bytes)", ec2.message(), n2));
            }
        }

        auto parsed = msg::parse(buf);
        if (!parsed)
        {
            co_return std::unexpected("Message parse failed");
        }

        co_return *parsed;
    };

    auto timer_op = [&]() -> net::awaitable<std::expected<Msg, std::string>>
    {
        std::ignore = co_await timer.async_wait(net::as_tuple(net::use_awaitable));
        co_return std::unexpected("Receive timeout");
    };

    auto result = co_await (read_op() || timer_op());
    co_return std::get<0>(result);
}

void Client::change_state(State new_state)
{
    state = new_state;
}

void Client::shutdown() noexcept
{
    boost::system::error_code ec;
    sock.cancel(ec);
    sock.close(ec);

    if (ss_local)
    {
        crypto::secure_clear(*ss_local);
    }
    if (ss_remote)
    {
        crypto::secure_clear(*ss_remote);
    }
    if (kp)
    {
        crypto::secure_clear(kp->secret_key);
    }

    cipher.clear();
    change_state(State::Disconnected);
}

std::expected<void, std::string> Client::process_command(std::string_view line)
{
    std::string trimmed(line);
    trimmed.erase(0, trimmed.find_first_not_of(" \t\r\n"));
    trimmed.erase(trimmed.find_last_not_of(" \t\r\n") + 1);

    if (trimmed.empty())
    {
        return {};
    }

    std::istringstream iss(trimmed);
    std::string cmd;
    iss >> cmd;

    if (cmd == "help")
    {
        std::println("Available commands:");
        std::println("  connect [host] [port]  - Connect to server (uses config if no args)");
        std::println("  auth <user> <pass>     - Authenticate with credentials");
        std::println("  command <json>         - Send command request");
        std::println("  broadcast <message>    - Send broadcast message");
        std::println("  logout                 - Logout current session");
        std::println("  disconnect             - Close connection");
        std::println("  quit/exit              - Exit interactive mode");
        std::println("  help                   - Show this help");
        return {};
    }

    if (cmd == "quit" || cmd == "exit")
    {
        return std::unexpected("QUIT");
    }

    if (cmd == "connect")
    {
        std::string new_host;
        uint16_t new_port = 0;
        iss >> new_host >> new_port;

        if (!new_host.empty())
        {
            host = new_host;
        }
        if (new_port != 0)
        {
            port = new_port;
        }

        auto result = connect();
        if (!result)
        {
            std::println("Connect failed: {}", result.error());
            return {};
        }

        result = perform_handshake();
        if (!result)
        {
            std::println("Handshake failed: {}", result.error());
            std::ignore = disconnect();
            return {};
        }

        std::println("Connected and handshake completed. Use 'auth <user> <pass>' to authenticate.");
        return {};
    }

    if (cmd == "auth")
    {
        std::string username, password;
        iss >> username >> password;

        if (username.empty() || password.empty())
        {
            std::print("Username: ");
            std::flush(std::cout);
            std::getline(std::cin, username);
            username.erase(0, username.find_first_not_of(" \t\r\n"));
            username.erase(username.find_last_not_of(" \t\r\n") + 1);

            std::print("Password: ");
            std::flush(std::cout);
            std::getline(std::cin, password);
        }

        if (username.empty() || password.empty())
        {
            std::println("Error: Username and password required");
            return {};
        }

        auto result = authenticate(username, password);
        if (!result)
        {
            std::println("Auth failed: {}", result.error());
            return {};
        }

        std::println("Authenticated successfully.");
        return {};
    }

    if (cmd == "command")
    {
        std::string json_str;
        std::getline(iss, json_str);
        json_str.erase(0, json_str.find_first_not_of(" \t"));

        if (json_str.empty())
        {
            std::println("Error: JSON payload required");
            return {};
        }

        json::error_code jec;
        auto parsed = json::parse(json_str, jec);
        if (jec || !parsed.is_object())
        {
            std::println("Error: Invalid JSON");
            return {};
        }

        auto result = send_command(parsed.as_object());
        if (!result)
        {
            std::println("Command failed: {}", result.error());
            return {};
        }

        std::println("Response: {}", json::serialize(*result));
        return {};
    }

    if (cmd == "broadcast")
    {
        std::string message;
        std::getline(iss, message);
        message.erase(0, message.find_first_not_of(" \t"));

        if (message.empty())
        {
            std::println("Error: Message required");
            return {};
        }

        auto result = send_broadcast(message);
        if (!result)
        {
            std::println("Broadcast failed: {}", result.error());
            return {};
        }

        std::println("Response: {}", json::serialize(*result));
        return {};
    }

    if (cmd == "logout")
    {
        auto result = logout();
        if (!result)
        {
            std::println("Logout failed: {}", result.error());
            return {};
        }

        std::println("Logged out successfully.");
        return {};
    }

    if (cmd == "disconnect")
    {
        auto result = disconnect();
        if (!result)
        {
            std::println("Disconnect failed: {}", result.error());
            return {};
        }

        std::println("Disconnected.");
        return {};
    }

    std::println("Unknown command: {}. Type 'help' for available commands.", cmd);
    return {};
}

void Client::run_interactive_loop()
{
    std::println("TiaoMeng Interactive Client");
    std::println("Type 'help' for available commands, 'quit' to exit.");
    std::println();

    std::string line;
    while (true)
    {
        std::print("> ");
        std::flush(std::cout);

        if (!std::getline(std::cin, line))
        {
            break;
        }

        auto result = process_command(line);
        if (!result && result.error() == "QUIT")
        {
            break;
        }
    }

    std::println("Goodbye.");
}
