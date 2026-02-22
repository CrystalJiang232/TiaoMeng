#include "server.hpp"
#include "config.hpp"
#include "logger.hpp"
#include "event_handler.hpp"
#include "fundamentals/bytes.hpp"
#include "fundamentals/msg_serialize.hpp"
#include <bit>

namespace json = boost::json;
using namespace bytes;
using namespace msg;
using crypto::secure_clear;
using crypto::Kyber768;
using json_utils::status_msg;

Connection::Connection(tcp::socket sock, Server* srv, std::string conn_id, const Config& config)
    : socket(std::move(sock))
    , server(srv)
    , id(std::move(conn_id))
    , state(ConnState::Connected)
    , write_in_progress(false)
    , fail_tracker(config.security().max_failures_before_disconnect)
    , config_(config)
{
    LOG_INFO("Connection established with id = {}", id);
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
    LOG_INFO("Disconnected with id = {}", id);
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
        send_raw_error("Read header error", CloseMode::CancelOthers);
        co_return;
    }
    
    uint32_t len = to_int(read_buf);

    if (n != 4 || len < 5 || len > Msg::max_len)
    {
        send_raw_error("Length verification error", CloseMode::CancelOthers);
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
        send_raw_error("Pipe reading error", CloseMode::CancelOthers);
        co_return;
    }
    
    if (n != len - 4)
    {
        send_raw_error("Incomplete read", CloseMode::CancelOthers);
        co_return;
    }
    
    auto m0 = msg::parse(read_buf);
    if (!m0)
    {
        if (send_error("Message parse error", CloseMode::CancelOthers))
        {
            co_return;
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
            send_raw_error("Encrypted messages not allowed during handshake", CloseMode::CancelOthers);
            co_return;
        }
        if (semantic != MsgSemantic::Handshake)
        {
            send_raw_error("Only Handshake semantic allowed during handshake", CloseMode::CancelOthers);
            co_return;
        }
    }
    else
    {
        if (!encrypted)
        {
            std::ignore = send_error("Plaintext messages not allowed after handshake", CloseMode::CancelOthers);
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
        std::ignore = send_error("Session management not implemented", CloseMode::CancelOthers);
        co_return;
        
    case MsgSemantic::Control:
    [[fallthrough]];
    case MsgSemantic::Response:
    [[fallthrough]];
    case MsgSemantic::Notify:
    [[fallthrough]];
    case MsgSemantic::Error:
        std::ignore = send_error("Invalid message direction: Server-to-client semantic received from client", CloseMode::CancelOthers);
        co_return;
    default:
        std::ignore = send_error(std::format("Invalid message semantic {}", std::to_underlying(semantic)), CloseMode::CancelOthers);
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
            send_raw_error(std::format("Invalid client public key size: expected {}, got {}",
                Kyber768::public_key_size, msg.payload.size()), CloseMode::CancelOthers);
            co_return;
        }
        
        auto kp_result = kem.generate_keypair();
        if (!kp_result)
        {
            send_raw_error("Failed to generate keypair", CloseMode::CancelOthers);
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
            send_raw_error("Failed to encapsulate to client public key", CloseMode::CancelOthers);
            co_return;
        }
        ss_A = std::move(encap_result->shared_secret);
        
        std::vector<uint8_t> payload;
        payload.reserve(Kyber768::public_key_size + Kyber768::ciphertext_size);
        
        std::ranges::copy(kp->public_key, std::back_inserter(payload));
        std::ranges::copy(encap_result->ciphertext, std::back_inserter(payload));

        auto send_result = msg::make(to_bytes<uint8_t>(payload), plaintext_handshake);
        if (!send_result)
        {
            send_raw_error(std::format("Failed to create handshake message, errc = {}", std::to_underlying(send_result.error())), CloseMode::CancelOthers);
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
            send_raw_error(std::format("Invalid handshake payload size: expected at least {}, got {}",
                Kyber768::ciphertext_size, msg.payload.size()), CloseMode::CancelOthers);
            co_return;
        }
        
        std::span<const uint8_t> cct(
            reinterpret_cast<const uint8_t*>(msg.payload.data()),
            Kyber768::ciphertext_size
        );
        
        auto decap_result = kem.decapsulate(cct, kp->secret_key);
        if (!decap_result)
        {
            send_raw_error("Failed to decapsulate client ciphertext", CloseMode::CancelOthers);
            co_return;
        }
        ss_local = std::move(*decap_result);
        
        auto encap_result = kem.encapsulate(*client_pk);
        if (!encap_result)
        {
            send_raw_error("Failed to encapsulate to client public key", CloseMode::CancelOthers);
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
            std::ignore = send_error("Failed to encrypt handshake response", CloseMode::CancelOthers);
            co_return;
        }
        
        auto payload = *encrypted 
            | std::views::transform(int2byte) 
            | std::ranges::to<Msg::payload_t>();
        
        auto send_result = msg::make(payload, encrypted_response);
        if (!send_result)
        {
            std::ignore = send_error("Failed to create encrypted response message", CloseMode::CancelOthers);
            co_return;
        }
        send(*send_result);
        
        kp->secret_key.clear();
        kp->secret_key.shrink_to_fit();
        ss_A.reset();
        client_pk.reset();
        
        state = ConnState::Established;
    LOG_INFO("Secure session established with {}", id);
        break;
    }

    case ConnState::Established:
    [[fallthrough]];
    case ConnState::Authenticated:
        std::ignore = send_error("Handshake already completed", CloseMode::CancelOthers);
        co_return;
    
    default:
        std::ignore = send_error("Invalid state for handshake", CloseMode::CancelOthers);
        co_return;
    }
}

net::awaitable<void> Connection::handle_encrypted(const Msg& msg)
{
    if (state != ConnState::Established && state != ConnState::Authenticated)
    {
        std::ignore = send_error("Invalid state: encrypted connection not yet established", CloseMode::CancelOthers);
        co_return;
    }

    if (!sess.is_established())
    {
        std::ignore = send_error("Session key not established", CloseMode::CancelOthers);
        co_return;
    }

    auto ct = msg.payload 
        | std::views::transform(std::to_underlying<std::byte>) 
        | std::ranges::to<std::vector<uint8_t>>();
    
    auto decrypted = sess.decrypt(ct);
    if (!decrypted)
    {
        std::ignore = send_error("Decryption failed", CloseMode::CancelOthers);
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
        std::ignore = send_error("Invalid JSON", CloseMode::CancelOthers);
        co_return;
    }
    
    if (!parsed.is_object())
    {
        std::ignore = send_error("Request must be JSON object", CloseMode::CancelOthers);
        co_return;
    }
    
    co_await handle_request(parsed.as_object());
}

net::awaitable<void> Connection::handle_request(const json::object& request)
{
    evt_hdl.route(shared_from_this(), request);
    co_return;
}

void Connection::send(const Msg& msg)
{
    net::dispatch(socket.get_executor(),
        [this, self = shared_from_this(), msg]()
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
    
    auto enc_msg = msg::make(payload, type);
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
    
    auto plaintext = msg::serialize(msg) 
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
    
    auto enc_msg = msg::make(payload, encrypted_request);
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
        auto buf = msg::serialize(write_queue.front());
        write_queue.pop_front(); //Stack debugging - avoid popping on an 'inadvertently-cleared' deque(cleared by other coroutines' exit) 
        //Probably atomic operation would be safer?  
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
            send_raw_error("Pipe writing error", CloseMode::CancelOthers);
            co_return;
        }
        
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
    (void)err; // Error message is now sent by caller (send_error/send_raw_error) before calling close
    
    if (is_pipe_dead())
    {
        mode = CloseMode::Abort;
    }
    
    switch (mode)
    {
    case CloseMode::DrainPipe:
        co_await write();
        break;
        
    case CloseMode::BestEffort:
        // Just let pending writes complete naturally
        break;
        
    case CloseMode::CancelOthers:
        cancel_all_io();
        clear_write_queue();
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
    net::co_spawn(socket.get_executor(),
        [self = shared_from_this(), err, mode]() -> net::awaitable<void>
        {
            co_await self->close_async(err, mode);
        }, net::detached);
}

void Connection::send_raw_error(std::string_view err, CloseMode mode)
{
    static const Msg decay_msg = *msg::make(bytes::to_bytes("Unknown error"), plaintext_error);
    auto err_msg = msg::make(bytes::to_bytes(err), plaintext_error).value_or(decay_msg);
    send(err_msg);
    close("", mode); // close_async will ignore the empty string
}

[[nodiscard("Do not discard send_error's value: caller is responsible for co_return upon this function returning true to prevent connection leakage.")]] bool Connection::send_error(std::string_view err, CloseMode mode)
{
    send_encrypted(status_msg("Error", err), encrypted_error);
    if (record_failure())
    {
        close("", mode);
        return true;
    }
    return false;
}