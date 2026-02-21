#include "server.hpp"
#include "helper.hpp"
#include "cipher.hpp"
#include "event_handler.hpp"
#include <bit>

namespace json = boost::json;
using namespace Hibiscus;

Connection::Connection(tcp::socket sock, Server* srv, std::string conn_id)
    : socket(std::move(sock))
    , server(srv)
    , id(std::move(conn_id))
    , state(ConnState::Connected)
    , write_in_progress(false)
{
    std::println("Connection established with id = {}", id);
}

Connection::~Connection() noexcept
{
    if (ss_local)
    {
        secure_clear(*ss_local);
    }
    if (ss_remote)
    {
        secure_clear(*ss_remote);
    }
    if (ss_A)
    {
        secure_clear(*ss_A);
    }
    if (kp)
    {
        secure_clear(kp->secret_key);
    }
    sess.clear();
    std::println("Disconnected with id = {}!", id);
}

void Connection::start()
{
    net::co_spawn(socket.get_executor(), 
        [self = shared_from_this()]() -> net::awaitable<void>
        {
            co_await self->read_header();
        }, 
        net::detached);
}

net::awaitable<void> Connection::read_header()
{
    read_buf.resize(4);

    auto [ec, n] = co_await net::async_read(
        socket,
        net::buffer(read_buf, 4),
        net::as_tuple(net::use_awaitable));
    
    if (ec)
    {
        if (ec == net::error::eof || 
            ec == net::error::connection_reset ||
            ec == net::error::broken_pipe)
        {
            mark_pipe_dead();
        }
        close("Read header error", CloseMode::Abort);
        co_return;
    }
    
    uint32_t len = to_int(read_buf);

    if (n != 4 || len < 5 || len > Msg::max_len)
    {
        close("Length verification error");
        co_return;
    }

    co_await read_body(len);
}

net::awaitable<void> Connection::read_body(uint32_t len)
{
    read_buf.resize(len);   

    auto [ec, n] = co_await net::async_read(
        socket,
        net::buffer(read_buf.data() + 4, len - 4),
        net::as_tuple(net::use_awaitable));
    
    if (ec)
    {
        if (ec == net::error::eof || 
            ec == net::error::connection_reset ||
            ec == net::error::broken_pipe)
        {
            mark_pipe_dead();
        }
        close("Pipe reading error", CloseMode::Abort);
        co_return;
    }
    
    if (n != len - 4)
    {
        close("Incomplete read");
        co_return;
    }
    
    auto m0 = Msg::parse(read_buf);
    if (!m0)
    {
        close("Message parse error");
        if (record_failure())
        {
            close("Too many parse errors");
        }
        co_return;
    }
    
    auto& msg = *m0;
    auto semantic = get_semantic(msg.type);
    bool encrypted = is_encrypted(msg.type);
    
    if (state == ConnState::Connected || state == ConnState::Handshaking)
    {
        if (encrypted)
        {
            close("Encrypted messages not allowed during handshake");
            co_return;
        }
        if (semantic != MsgSemantic::Handshake)
        {
            close("Only Handshake semantic allowed during handshake");
            co_return;
        }
    }
    else
    {
        if (!encrypted)
        {
            close("Plaintext messages not allowed after handshake");
            if (record_failure())
            {
                close("Too many plaintext violations");
            }
            co_return;
        }
    }
    
    switch(semantic)
    {
    case MsgSemantic::Handshake:
        co_await handle_handshake(msg);
        break;
        
    case MsgSemantic::Request:
        co_await handle_encrypted(msg);
        break;
    
    case MsgSemantic::Session:
        close("Session management not implemented");
        co_return;
        
    case MsgSemantic::Control:
    case MsgSemantic::Response:
    case MsgSemantic::Notify:
    case MsgSemantic::Error:
        if (record_failure())
        {
            close("Invalid message direction");
        }
        else
        {
            close("Server-to-client semantic received from client");
        }
        co_return;

    default:
        if (record_failure())
        {
            close("Too many invalid messages");
        }
        else
        {
            close(std::format("Invalid message semantic {}", std::to_underlying(semantic)));
        }
        co_return;
    }

    co_await read_header();
}

net::awaitable<void> Connection::handle_handshake(const Msg& msg)
{
    switch(state)
    {
    case ConnState::Connected:
    {
        if (msg.payload.size() != Kyber768::public_key_size)
        {
            close(std::format("Invalid client public key size: expected {}, got {}",
                Kyber768::public_key_size, msg.payload.size()));
            co_return;
        }
        
        auto kp_result = kem.generate_keypair();
        if (!kp_result)
        {
            close("Failed to generate keypair");
            co_return;
        }
        kp = std::move(*kp_result);
        
        std::span<const uint8_t> cpk(
            reinterpret_cast<const uint8_t*>(msg.payload.data()),
            Kyber768::public_key_size
        );

        auto encap_result = kem.encapsulate(cpk);
        if (!encap_result)
        {
            close("Failed to encapsulate to client public key");
            co_return;
        }
        ss_A = std::move(encap_result->shared_secret);
        
        std::vector<uint8_t> payload;
        payload.reserve(Kyber768::public_key_size + Kyber768::ciphertext_size);
        
        std::ranges::copy(kp->public_key, std::back_inserter(payload));
        std::ranges::copy(encap_result->ciphertext, std::back_inserter(payload));

        auto send_result = Msg::make(to_bytes<uint8_t>(payload), plaintext_handshake);
        if (!send_result)
        {
            close(std::format("Failed to create handshake message, errc = {}", std::to_underlying(send_result.error())));
            co_return;
        }
        send(*send_result);

        client_pk = cpk | std::ranges::to<Kyber768::key_t>();
        state = ConnState::Handshaking;
        break;
    }
    
    case ConnState::Handshaking:
    {
        if (msg.payload.size() < Kyber768::ciphertext_size)
        {
            close(std::format("Invalid handshake payload size: expected at least {}, got {}",
                Kyber768::ciphertext_size, msg.payload.size()));
            co_return;
        }
        
        std::span<const uint8_t> cct(
            reinterpret_cast<const uint8_t*>(msg.payload.data()),
            Kyber768::ciphertext_size
        );
        
        auto decap_result = kem.decapsulate(cct, kp->secret_key);
        if (!decap_result)
        {
            close("Failed to decapsulate client ciphertext");
            co_return;
        }
        ss_local = std::move(*decap_result);
        
        auto encap_result = kem.encapsulate(*client_pk);
        if (!encap_result)
        {
            close("Failed to encapsulate to client public key");
            co_return;
        }
        ss_remote = std::move(encap_result->shared_secret);
        
        sess.complete_handshake(
            std::span<const uint8_t>(ss_local->data(), ss_local->size()),
            std::span<const uint8_t>(ss_A->data(), ss_A->size())
        );
        
        auto response = status_msg("ConnectionReady", "Secure channel established, please authenticate");
        
        auto plaintext = json::serialize(response) 
            | std::views::transform([](char c) { return static_cast<uint8_t>(c); })
            | std::ranges::to<std::vector<uint8_t>>();
        
        auto encrypted = sess.encrypt(plaintext);
        if (!encrypted)
        {
            close("Failed to encrypt handshake response");
            co_return;
        }
        
        auto payload = *encrypted 
            | std::views::transform(int2byte) 
            | std::ranges::to<Msg::payload_t>();
        
        auto send_result = Msg::make(payload, encrypted_response);
        if (!send_result)
        {
            close("Failed to create encrypted response message");
            co_return;
        }
        send(*send_result);
        
        kp->secret_key.clear();
        kp->secret_key.shrink_to_fit();
        ss_A.reset();
        client_pk.reset();
        
        state = ConnState::Established;
        std::println("Secure session established with {}", id);
        break;
    }

    case ConnState::Established:
    case ConnState::Authenticated:
        close("Handshake already completed");
        co_return;
    
    default:
        close("Invalid state for handshake");
        co_return;
    }
}

net::awaitable<void> Connection::handle_encrypted(const Msg& msg)
{
    if (state != ConnState::Established && state != ConnState::Authenticated)
    {
        close("Invalid state: encrypted connection not yet established");
        co_return;
    }

    if (!sess.is_established())
    {
        close("Session key not established");
        co_return;
    }

    auto ct = msg.payload 
        | std::views::transform(std::to_underlying<std::byte>) 
        | std::ranges::to<std::vector<uint8_t>>();
    
    auto decrypted = sess.decrypt(ct);
    if (!decrypted)
    {
        send_encrypted(status_msg("Error", "Decryption failed"));
        if (record_failure())
        {
            close("Decryption failure threshold exceeded");
        }
        co_return;
    }
    
    std::string json_str;
    json_str.reserve(decrypted->size());
    for (auto b : *decrypted)
    {
        json_str.push_back(static_cast<char>(b));
    }
    
    json::error_code ec;
    auto parsed = json::parse(json_str, ec);
    if (ec)
    {
        send_encrypted(status_msg("Error", "Invalid JSON"));
        if (record_failure())
        {
            close("JSON parse failure threshold exceeded");
        }
        co_return;
    }
    
    if (!parsed.is_object())
    {
        send_encrypted(status_msg("Error", "Request must be JSON object"));
        if (record_failure())
        {
            close("Invalid request format threshold exceeded");
        }
        co_return;
    }
    
    co_await handle_request(parsed.as_object());
}

net::awaitable<void> Connection::handle_request(const json::object& request)
{
    auto it = request.find("action");
    if (it == request.end())
    {
        send_encrypted(status_msg("Error", "Missing 'action' field"));
        if (record_failure())
        {
            close("Missing action threshold exceeded");
        }
        co_return;
    }
    
    if (!it->value().is_string())
    {
        send_encrypted(status_msg("Error", "'action' must be string"));
        if (record_failure())
        {
            close("Invalid action format threshold exceeded");
        }
        co_return;
    }
    
    std::string action_str = std::string(it->value().as_string());
    
    auto self = shared_from_this();
    
    if (action_str == "auth")
    {
        EventHandler::handle_auth(self, request);
    }
    else if (action_str == "command")
    {
        EventHandler::handle_command(self, request);
    }
    else if (action_str == "broadcast")
    {
        EventHandler::handle_broadcast(self, request);
    }
    else if (action_str == "logout")
    {
        EventHandler::handle_logout(self);
    }
    else
    {
        send_encrypted(status_msg("Error", std::format("Unknown action: {}", action_str)));
        if (record_failure())
        {
            close("Unknown action threshold exceeded");
        }
    }
}

void Connection::send(const Msg& msg)
{
    auto self = shared_from_this();
    
    net::dispatch(socket.get_executor(),
        [this, self, msg]()
        {
            bool empty = write_queue.empty();
            write_queue.push_back(msg);
            
            if (!write_in_progress && empty)
            {
                write_in_progress = true;
                net::co_spawn(socket.get_executor(),
                    [this, self]() -> net::awaitable<void>
                    {
                        co_await write();
                    },
                    net::detached);
            }
        });
}

void Connection::send_encrypted(const json::object& json_obj, MsgType type)
{
    if (!sess.is_established())
    {
        return;
    }
    
    auto json_str = json::serialize(json_obj);
    auto plaintext = json_str 
        | std::views::transform([](char c) { return static_cast<uint8_t>(c); })
        | std::ranges::to<std::vector<uint8_t>>();
    
    auto encrypted = sess.encrypt(plaintext);
    if (!encrypted)
    {
        return;
    }
    
    auto payload = *encrypted 
        | std::views::transform(int2byte) 
        | std::ranges::to<Msg::payload_t>();
    
    auto enc_msg = Msg::make(payload, type);
    if (!enc_msg)
    {
        return;
    }
    
    send(*enc_msg);
}

void Connection::send_encrypted(const Msg& msg)
{
    if (!sess.is_established())
    {
        return;
    }
    
    auto plaintext = msg.serialize() 
        | std::views::transform(std::to_underlying<std::byte>) 
        | std::ranges::to<std::vector<uint8_t>>();
    
    auto encrypted = sess.encrypt(plaintext);
    if (!encrypted)
    {
        return;
    }
    
    auto payload = *encrypted 
        | std::views::transform(int2byte) 
        | std::ranges::to<Msg::payload_t>();
    
    auto enc_msg = Msg::make(payload, encrypted_request);
    if (!enc_msg)
    {
        return;
    }
    
    send(*enc_msg);
}

net::awaitable<void> Connection::write()
{
    while (!write_queue.empty())
    {
        auto buf = write_queue.front().serialize();
        
        auto [ec, n] = co_await net::async_write(
            socket,
            net::buffer(buf),
            net::as_tuple(net::use_awaitable));
        
        if (ec)
        {
            if (ec == net::error::eof || 
                ec == net::error::connection_reset ||
                ec == net::error::broken_pipe)
            {
                mark_pipe_dead();
            }
            write_in_progress = false;
            close("Pipe writing error", CloseMode::Abort);
            co_return;
        }
        
        write_queue.pop_front();
    }
    
    write_in_progress = false;
}

void Connection::cancel_all_io()
{
    boost::system::error_code ec;
    socket.cancel(ec);
}

void Connection::clear_write_queue()
{
    write_queue.clear();
}

void Connection::shutdown() noexcept
{
    try
    {
        cancel_all_io();
        clear_write_queue();
        
        boost::system::error_code ec;
        socket.close(ec);
    }
    catch (...)
    {
        // noexcept - swallow all exceptions
    }
}

net::awaitable<void> Connection::close_async(std::string_view err, CloseMode mode)
{
    if (is_pipe_dead())
    {
        mode = CloseMode::Abort;
    }
    
    switch (mode)
    {
    case CloseMode::DrainPipe:
        if (!err.empty())
        {
            write_queue.push_back(get_err(err));
            co_await write();
        }
        break;
        
    case CloseMode::BestEffort:
        if (!err.empty())
        {
            send(get_err(err));
        }
        break;
        
    case CloseMode::CancelOthers:
        cancel_all_io();
        clear_write_queue();
        if (!err.empty())
        {
            auto err_msg = get_err(err);
            auto buf = err_msg.serialize();
            co_await net::async_write(socket, net::buffer(buf), net::as_tuple(net::use_awaitable));
        }
        break;
        
    case CloseMode::Abort:
        shutdown();
        break;
    }
    
    server->remove_connection(id);
    co_return;
}

void Connection::close(std::string_view err, Connection::CloseMode mode)
{
    if (is_pipe_dead())
    {
        mode = CloseMode::Abort;
    }
    
    if (mode == CloseMode::DrainPipe)
    {
        net::co_spawn(socket.get_executor(),
            [self = shared_from_this(), err, mode]() -> net::awaitable<void>
            {
                co_await self->close_async(err, mode);
            }, net::detached);
    }
    else
    {
        switch (mode)
        {
        case CloseMode::BestEffort:
            if (!err.empty())
            {
                send(get_err(err));
            }
            server->remove_connection(id);
            break;
            
        case CloseMode::CancelOthers:
            cancel_all_io();
            clear_write_queue();
            if (!err.empty())
            {
                auto err_msg = get_err(err);
                auto buf = err_msg.serialize();
                net::async_write(socket, net::buffer(buf),
                    [self = shared_from_this()](auto, auto)
                    {
                        self->shutdown();
                        self->server->remove_connection(self->id);
                    });
                return;
            }
            server->remove_connection(id);
            break;
            
        case CloseMode::Abort:
            shutdown();
            server->remove_connection(id);
            break;
            
        default:
            break;
        }
    }
}
