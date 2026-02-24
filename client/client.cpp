#include "client.hpp"
#include "fundamentals/types.hpp"
#include "fundamentals/bytes.hpp"
#include "fundamentals/msg_serialize.hpp"
#include "crypto/utils.hpp"
#include "json_utils.hpp"
#include <boost/asio.hpp>
#include <boost/json.hpp>
#include <algorithm>
#include <ranges>
#include <print>

namespace json = boost::json;
using namespace boost::asio;
using namespace bytes;
using namespace msg;

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

std::expected<void, std::string> Client::connect()
{
    if (state != State::Disconnected)
    {
        return std::unexpected("Already connected or connecting");
    }
    
    try
    {
        tcp::resolver resolver(io_ctx);
        auto endpoints = resolver.resolve(host, std::to_string(port));
        
        socket = std::make_unique<tcp::socket>(io_ctx);
        boost::asio::connect(*socket, endpoints);
        
        change_state(State::Connected);
        return {};
    }
    catch (const std::exception& e)
    {
        return std::unexpected(std::format("Connection failed: {}", e.what()));
    }
}

std::expected<void, std::string> Client::disconnect()
{
    try
    {
        shutdown();
        return {};
    }
    catch (const std::exception& e)
    {
        return std::unexpected(std::format("Disconnect failed: {}", e.what()));
    }
}

std::expected<Msg::payload_t, std::string> Client::recv_raw(int timeout_sec)
{
    if (!socket || !socket->is_open())
    {
        return std::unexpected("Socket not connected");
    }
    
    try
    {
        // Read header (4 bytes length + 1 byte type)
        std::array<std::byte, 5> header{};
        
        // Set up timeout using async operations with timer
        std::optional<std::string> timeout_error;
        std::optional<size_t> bytes_read;
        
        net::steady_timer timer(io_ctx);
        timer.expires_after(std::chrono::seconds(timeout_sec));
        
        bool read_complete = false;
        boost::system::error_code read_ec;
        
        net::async_read(*socket, net::buffer(header),
            [&](const boost::system::error_code& ec, size_t n)
            {
                read_ec = ec;
                bytes_read = n;
                read_complete = true;
                timer.cancel();
            });
        
        timer.async_wait([&](const boost::system::error_code& ec)
        {
            if (!ec && !read_complete)
            {
                boost::system::error_code cancel_ec;
                socket->cancel(cancel_ec);
                timeout_error = "Receive timeout";
            }
        });
        
        // Run io_context until read completes or times out
        while (!read_complete && !timeout_error)
        {
            size_t handlers_executed = io_ctx.run_one();
            if (handlers_executed == 0)
            {
                // No more handlers to run
                break;
            }
        }
        
        // Cancel timer if read completed first
        timer.cancel();
        
        if (timeout_error)
        {
            return std::unexpected(*timeout_error);
        }
        
        if (!read_complete)
        {
            return std::unexpected("Read operation did not complete");
        }
        
        if (read_ec)
        {
            return std::unexpected(std::format("Read error: {}", read_ec.message()));
        }
        
        if (!bytes_read || *bytes_read < 5)
        {
            return std::unexpected(std::format("Incomplete header received: {} bytes", bytes_read.value_or(0)));
        }
        
        uint32_t msg_len = to_int(header);
        
        if (msg_len < 5 || msg_len > Msg::max_len)
        {
            return std::unexpected(std::format("Invalid message length: {}", msg_len));
        }
        
        // Read body synchronously (header already received, body should follow immediately)
        size_t body_len = msg_len - 5;
        Msg::payload_t payload(body_len);
        
        if (body_len > 0)
        {
            boost::system::error_code body_ec;
            size_t body_read = net::read(*socket, net::buffer(payload),
                net::transfer_exactly(body_len), body_ec);
            
            if (body_ec)
            {
                return std::unexpected(std::format("Body read error: {}", body_ec.message()));
            }
            
            if (body_read != body_len)
            {
                return std::unexpected(std::format("Incomplete body received: {} of {} bytes", body_read, body_len));
            }
        }
        
        return payload;
    }
    catch (const std::exception& e)
    {
        return std::unexpected(std::format("Receive error: {}", e.what()));
    }
}

std::expected<void, std::string> Client::send_raw(const Msg::payload_t& payload, MsgType type)
{
    if (!socket || !socket->is_open())
    {
        return std::unexpected("Socket not connected");
    }
    
    auto msg_result = msg::make(payload, type);
    if (!msg_result)
    {
        return std::unexpected("Failed to create message");
    }
    
    auto serialized = msg::serialize(*msg_result);
    
    try
    {
        net::write(*socket, net::buffer(serialized));
        return {};
    }
    catch (const std::exception& e)
    {
        return std::unexpected(std::format("Send failed: {}", e.what()));
    }
}

std::expected<void, std::string> Client::perform_handshake()
{
    if (state != State::Connected)
    {
        return std::unexpected("Must be in Connected state to handshake");
    }
    
    kem = std::make_unique<crypto::Kyber768>();
    
    auto kp_result = kem->generate_keypair();
    if (!kp_result)
    {
        return std::unexpected("Failed to generate Kyber768 keypair");
    }
    client_kp = std::move(*kp_result);
    
    change_state(State::Handshaking);
    
    // Step 1: Send client public key
    auto step1_payload = to_bytes<uint8_t>(client_kp.public_key);
    auto step1_result = send_raw(step1_payload, plaintext_handshake);
    if (!step1_result)
    {
        return std::unexpected(std::format("Failed to send public key: {}", step1_result.error()));
    }
    
    // Step 2: Receive server public key + ciphertext (raw binary, NOT JSON)
    auto step2_payload = recv_raw(5);
    if (!step2_payload)
    {
        return std::unexpected(std::format("Failed to receive server response: {}", step2_payload.error()));
    }
    
    if (step2_payload->size() < crypto::Kyber768::public_key_size + crypto::Kyber768::ciphertext_size)
    {
        return std::unexpected(std::format("Invalid server response: payload too small (got {}, expected at least {})", 
            step2_payload->size(), 
            crypto::Kyber768::public_key_size + crypto::Kyber768::ciphertext_size));
    }
    
    std::span<const uint8_t> server_pk(
        reinterpret_cast<const uint8_t*>(step2_payload->data()),
        crypto::Kyber768::public_key_size
    );
    std::span<const uint8_t> server_ct(
        reinterpret_cast<const uint8_t*>(step2_payload->data()) + crypto::Kyber768::public_key_size,
        crypto::Kyber768::ciphertext_size
    );
    
    // Decapsulate to get local shared secret
    auto decap_result = kem->decapsulate(server_ct, client_kp.secret_key);
    if (!decap_result)
    {
        return std::unexpected("Failed to decapsulate server ciphertext");
    }
    ss_local = std::move(*decap_result);
    
    // Step 3: Encapsulate to server public key and send
    auto encap_result = kem->encapsulate(server_pk);
    if (!encap_result)
    {
        return std::unexpected("Failed to encapsulate to server public key");
    }
    ss_remote = std::move(encap_result->shared_secret);
    
    auto step3_payload = to_bytes<uint8_t>(encap_result->ciphertext);
    auto step3_result = send_raw(step3_payload, plaintext_handshake);
    if (!step3_result)
    {
        return std::unexpected(std::format("Failed to send ciphertext: {}", step3_result.error()));
    }
    
    // Combine secrets to create session key (ONE STEP EARLY as required by step 4's recv_Response)
    cipher = std::make_unique<crypto::SessionKey>();
    cipher->complete_handshake(
        std::span<const uint8_t>(ss_remote->data(), ss_remote->size()),
        std::span<const uint8_t>(ss_local->data(), ss_local->size())
    ); //Probably needs to update the calling syntax anyway
    
    // Clear sensitive data
    crypto::secure_clear(client_kp.secret_key);
    if (ss_local) 
    {
        crypto::secure_clear(*ss_local);
    }

    // Step 4: Receive encrypted ConnectionReady response (JSON)
    auto ready_response = recv_response(5);
    if (!ready_response)
    {
        return std::unexpected(std::format("Failed to receive ConnectionReady: {}", ready_response.error()));
    }
    
    auto status_result = json_utils::extract_str(*ready_response, "status");
    if (!status_result)
    {
        return std::unexpected(status_result.error());
    }
    
    if (*status_result != "ConnectionReady")
    {
        return std::unexpected(std::format("Unexpected status: {}", *status_result));
    }
    
    //Change state goes here
    change_state(State::Established);
    return {};
}

std::expected<void, std::string> Client::authenticate(std::string_view username, std::string_view password)
{
    if (state != State::Established)
    {
        return std::unexpected("Connection not established yet");
    }
    
    json::object auth_data
    {
        {"username", std::string(username)},
        {"password", std::string(password)}
    };
    
    auto send_result = send_json_request("auth", auth_data);
    if (!send_result)
    {
        return std::unexpected(send_result.error());
    }
    
    auto recv_result = recv_response();
    if (!recv_result)
    {
        return std::unexpected(recv_result.error());
    }
    
    auto status_result = json_utils::extract_str(*recv_result, "status");
    if (!status_result)
    {
        return std::unexpected(status_result.error());
    }
    
    if (*status_result != "Success")
    {
        return std::unexpected(std::format("Authentication failed: {}", *status_result));
    }
    
    change_state(State::Authenticated);
    return {};
}

std::expected<json::object, std::string> Client::send_command(const json::object& data)
{
    auto send_result = send_json_request("command", data);
    if (!send_result)
    {
        return std::unexpected(send_result.error());
    }
    
    return recv_response();
}

std::expected<json::object, std::string> Client::send_broadcast(const json::object& data)
{
    auto send_result = send_json_request("broadcast", data);
    if (!send_result)
    {
        return std::unexpected(send_result.error());
    }
    
    return recv_response();
}

std::expected<void, std::string> Client::logout()
{
    if (state != State::Authenticated)
    {
        return std::unexpected("Not authenticated");
    }
    
    json::object empty_data;
    auto send_result = send_json_request("logout", empty_data);
    if (!send_result)
    {
        return std::unexpected(send_result.error());
    }
    
    auto recv_result = recv_response();
    if (!recv_result)
    {
        return std::unexpected(recv_result.error());
    }
    
    auto status_result = json_utils::extract_str(*recv_result, "status");
    if (!status_result)
    {
        return std::unexpected(status_result.error());
    }
    
    if (*status_result != "Success")
    {
        return std::unexpected(std::format("Logout failed: {}", *status_result));
    }
    
    change_state(State::Established);
    return {};
}

std::expected<json::object, std::string> Client::recv_response(int timeout_sec)
{
    if (!socket || !socket->is_open())
    {
        return std::unexpected("Socket not connected");
    }
    
    try
    {
        // Read header (4 bytes length + 1 byte type)
        std::array<std::byte, 5> header{};
        
        // Set up timeout using async operations with timer
        std::optional<std::string> timeout_error;
        std::optional<size_t> bytes_read;
        
        net::steady_timer timer(io_ctx);
        timer.expires_after(std::chrono::seconds(timeout_sec));
        
        bool read_complete = false;
        boost::system::error_code read_ec;
        
        net::async_read(*socket, net::buffer(header),
            [&](const boost::system::error_code& ec, size_t n)
            {
                read_ec = ec;
                bytes_read = n;
                read_complete = true;
                timer.cancel();
            });
        
        timer.async_wait([&](const boost::system::error_code& ec)
        {
            if (!ec && !read_complete)
            {
                boost::system::error_code cancel_ec;
                socket->cancel(cancel_ec);
                timeout_error = "Receive timeout";
            }
        });
        
        // Run io_context until read completes or times out
        while (!read_complete && !timeout_error)
        {
            size_t handlers_executed = io_ctx.run_one();
            if (handlers_executed == 0)
            {
                // No more handlers to run
                break;
            }
        }
        
        // Cancel timer if read completed first
        timer.cancel();
        
        if (timeout_error)
        {
            return std::unexpected(*timeout_error);
        }
        
        if (!read_complete)
        {
            return std::unexpected("Read operation did not complete");
        }
        
        if (read_ec)
        {
            return std::unexpected(std::format("Read error: {}", read_ec.message()));
        }
        
        if (!bytes_read || *bytes_read < 5)
        {
            return std::unexpected(std::format("Incomplete header received: {} bytes", bytes_read.value_or(0)));
        }
        
        uint32_t msg_len = to_int(header);
        MsgType msg_type = static_cast<MsgType>(header[4]);
        
        if (msg_len < 5 || msg_len > Msg::max_len)
        {
            return std::unexpected(std::format("Invalid message length: {}", msg_len));
        }

        if (!is_encrypted(msg_type))
        {
            return std::unexpected(std::format("Message type schematic error: unexpected non-encrypted message received"));
        }
        
        // Read body synchronously
        size_t body_len = msg_len - 5;
        std::vector<std::byte> body(body_len);
        
        if (body_len > 0)
        {
            boost::system::error_code body_ec;
            size_t body_read = net::read(*socket, net::buffer(body),
                net::transfer_exactly(body_len), body_ec);
            
            if (body_ec)
            {
                return std::unexpected(std::format("Body read error: {}", body_ec.message()));
            }
            
            if (body_read != body_len)
            {
                return std::unexpected(std::format("Incomplete body received: {} of {} bytes", body_read, body_len));
            }
        }
        
        std::vector<std::byte> full_msg;
        full_msg.reserve(msg_len);

        auto it = std::back_insert_iterator(full_msg);
        std::ranges::copy(header, it);
        std::ranges::copy(body, it); //When will views::concat be online awa
        
        auto msg_result = msg::parse(full_msg);
        if (!msg_result)
        {
            return std::unexpected("Failed to parse message");
        }
        
        // Check if encrypted
        if (!is_encrypted(msg_result->type))
        {
            // Plaintext message (error during handshake)
            auto json_result = parse_json_response(
                std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(msg_result->payload.data()),
                                        msg_result->payload.size())
            );
            if (!json_result)
            {
                return std::unexpected("Failed to parse plaintext JSON");
            }
            return *json_result;
        }
        
        // Decrypt
        if (!cipher || !cipher->is_established())
        {
            return std::unexpected("Cipher not established");
        }
        
        auto decrypted = cipher->decrypt(
            std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(msg_result->payload.data()),
                                    msg_result->payload.size())
        );
        
        if (!decrypted)
        {
            return std::unexpected("Decryption failed");
        }
        
        return parse_json_response(*decrypted);
    }
    catch (const std::exception& e)
    {
        return std::unexpected(std::format("Receive error: {}", e.what()));
    }
}

std::expected<void, std::string> Client::send_json_request(std::string_view action, const json::object& data)
{
    if (!socket || !socket->is_open())
    {
        return std::unexpected("Socket not connected");
    }
    
    if (!cipher || !cipher->is_established())
    {
        return std::unexpected("Secure channel not established");
    }
    
    json::object request;
    request["action"] = std::string(action);
    
    for (const auto& [key, value] : data)
    {
        request[key] = value;
    }
    
    std::string json_str = json::serialize(request);
    std::vector<uint8_t> plaintext(json_str.begin(), json_str.end());
    
    auto encrypted = cipher->encrypt(plaintext);
    if (!encrypted)
    {
        return std::unexpected("Encryption failed");
    }
    
    auto msg_result = msg::make(
        std::span<const std::byte>(reinterpret_cast<const std::byte*>(encrypted->data()),
                                   encrypted->size()),
        encrypted_request
    );
    
    if (!msg_result)
    {
        return std::unexpected("Failed to create message");
    }
    
    auto serialized = msg::serialize(*msg_result);
    
    try
    {
        net::write(*socket, net::buffer(serialized));
        return {};
    }
    catch (const std::exception& e)
    {
        return std::unexpected(std::format("Send failed: {}", e.what()));
    }
}

std::expected<json::object, std::string> Client::parse_json_response(std::span<const uint8_t> data)
{
    try
    {
        std::string json_str(reinterpret_cast<const char*>(data.data()), data.size());
        
        json::error_code ec;
        auto parsed = json::parse(json_str, ec);
        
        if (ec)
        {
            return std::unexpected(std::format("JSON parse error: {}", ec.message()));
        }
        
        if (!parsed.is_object())
        {
            return std::unexpected("Response is not a JSON object");
        }
        
        return parsed.as_object();
    }
    catch (const std::exception& e)
    {
        return std::unexpected(std::format("Parse error: {}", e.what()));
    }
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
        
        if (ss_local) crypto::secure_clear(*ss_local);
        if (ss_remote) crypto::secure_clear(*ss_remote);
        crypto::secure_clear(client_kp.secret_key);
        
        state = State::Disconnected;
    }
    catch (...)
    {
    }
}
