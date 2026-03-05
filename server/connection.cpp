#include "server.hpp"
#include "config.hpp"
#include "logger/logger.hpp"
#include "event_handler.hpp"
#include "fundamentals/bytes.hpp"
#include "fundamentals/msg_serialize.hpp"
#include <bit>
#include <mutex>
#include <boost/asio/experimental/awaitable_operators.hpp>

namespace json = boost::json;
using namespace bytes;
using namespace msg;
using crypto::secure_clear;
using crypto::Kyber768;
using json_utils::status_msg;

// C++ 'fundamentals' - initialization sequence is as per variable DECLARED sequence, not as per initializer sequence in ctor definition  
// It's vital to align latter to former to prevent unexpected schematic-based error(or '-Wreorder')
Connection::Connection(tcp::socket sock, Server* srv, std::string conn_id, const Config& config, net::io_context& io)
    : strand(net::make_strand(io))
    , socket(std::move(sock))
    , server(srv)
    , id(std::move(conn_id))
    , state(ConnState::Connected)
    , write_in_progress(false)
    , fail_tracker(config.security().max_failures_before_disconnect)
    , cfg(config)
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
    LOG_DEBUG("Connection {} start() called", id);
    net::co_spawn(strand,
        [self = shared_from_this()]() -> net::awaitable<void>
        {
            LOG_DEBUG("Connection {} read_header coroutine started", self->id);
            co_await self->read_header();
        },
        net::detached);
    LOG_DEBUG("Connection {} start() co_spawn returned", id);
}

net::awaitable<std::optional<Connection::IoResult>> Connection::read_with_timeout(
    net::mutable_buffer buf,
    std::chrono::seconds timeout)
{
    if(is_closing())
    {
        co_return std::nullopt;
    }
    
    using net::experimental::awaitable_operators::operator||;
    
    net::steady_timer timer(strand);
    timer.expires_after(timeout);
    
    auto read_op = [&]() -> net::awaitable<IoResult>
    {
        auto [ec, n] = co_await net::async_read(socket, buf, net::as_tuple(net::use_awaitable));
        timer.cancel();
        co_return IoResult{ec, n};
    };
    
    auto timer_op = [&]() -> net::awaitable<void>
    {
        std::ignore = co_await timer.async_wait(net::as_tuple(net::use_awaitable));
        co_return;
    };
    
    auto result = co_await (read_op() || timer_op());
    if(result.index() == 0)
    {
        co_return std::get<0>(result);
    }

    co_return std::nullopt;
}

net::awaitable<std::optional<Connection::IoResult>> Connection::write_with_timeout(
    const Msg& msg,
    std::chrono::seconds timeout)
{
    if(is_closing())
    {
        co_return std::nullopt;
    }

    using net::experimental::awaitable_operators::operator||;
    
    net::steady_timer timer(strand);
    timer.expires_after(timeout);
    
    auto buf = msg::serialize(msg);
    
    auto write_op = [&]() -> net::awaitable<IoResult>
    {
        auto [ec, n] = co_await net::async_write(socket, net::buffer(buf), net::as_tuple(net::use_awaitable));
        timer.cancel();
        co_return IoResult{ec, n};
    };
    
    auto timer_op = [&]() -> net::awaitable<void>
    {
        std::ignore = co_await timer.async_wait(net::as_tuple(net::use_awaitable));
        co_return;
    };
    
    if(auto result = co_await (write_op() || timer_op()); result.index() == 0)
    {
        co_return std::get<IoResult>(result);
    }
    
    co_return std::nullopt;
}

net::awaitable<void> Connection::read_header()
{
    if(is_closing())
    {
        co_return;
    }

    LOG_DEBUG("Connection {} read_header waiting for 4 bytes", id);
    read_buf.resize(4);

    auto result = co_await read_with_timeout(
        net::buffer(read_buf, 4),
        cfg.timeouts().read_timeout);
    
    
    if (!result)
    {
        error_and_close("Read header timeout");
        co_return;
    }
    
    if (auto e = result->ec)
    {
        if (e == net::error::eof ||
            e == net::error::connection_reset ||
            e == net::error::broken_pipe)
        {
        }
        error_and_close("Read header error");
        co_return;
    }
    
    uint32_t len = to_int(read_buf);

    if (result->bytes != 4 || len < 5 || len > Msg::max_len)
    {
        error_and_close("Length verification error");
        co_return;
    }

    co_await read_body(len);
}

net::awaitable<void> Connection::read_body(uint32_t len)
{
    LOG_DEBUG("Connection {} read_body waiting for {} bytes (total len={})", id, len - 4, len);
    if(is_closing())
    {
        co_return;
    }

    read_buf.resize(len);

    auto result = co_await read_with_timeout(
        net::buffer(read_buf.data() + 4, len - 4),
        cfg.timeouts().read_timeout);
    
    if (!result)
    {
        error_and_close("Read body timeout");
        co_return;
    }
    
    if (auto e = result->ec)
    {
        error_and_close("Pipe reading error");
        co_return;
    }
    
    if (result->bytes != len - 4)
    {
        error_and_close("Incomplete read");
        co_return;
    }
    
    // Track bytes received
    if (server) server->metrics().bytes_received += len;
    
    // Message parsing
    auto m0 = msg::parse(read_buf);
    if (!m0)
    {
        LOG_DEBUG("Connection {} message parse error, errc={}", id, std::to_underlying(m0.error()));
        if (send_error("Message parse error"))
        {
            co_return;
        }
    }
    
    auto& msg = *m0;
    auto semantic = get_semantic(msg.type);
    bool encrypted = is_encrypted(msg.type);
    LOG_DEBUG("Connection {} received message: type={}, semantic={}, encrypted={}, payload_size={}", 
              id, static_cast<int>(msg.type), std::to_underlying(semantic), encrypted, msg.payload.size());
    
    
    // Connection state verification
    switch(auto st = state.load(std::memory_order_acquire))
    {
        case ConnState::Connected:
        [[fallthrough]];
        case ConnState::Handshaking:
        if (encrypted)
        {
            error_and_close("Encrypted messages not allowed during handshake");
            co_return;
        }
        if (semantic != MsgSemantic::Handshake)
        {
            error_and_close("Only Handshake semantic allowed during handshake");
            co_return;
        }
        break;
        
        case ConnState::Established:
        [[fallthrough]];
        case ConnState::Authenticated:
        if (!encrypted)
        {
            if(send_error("Plaintext messages not allowed after handshake"))
            {
                co_return;
            }
        }
        break;

        case ConnState::Closing:
        co_return;

        default:
        error_and_close("Invalid state occur!"); //TCP Analogy: RST
        LOG_ERROR("Invalid state occur @ {}: state = {}", get_id(), std::to_underlying(st));
        co_return;
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
        std::ignore = send_error("Session management not implemented");
        co_return;
        
    case MsgSemantic::Control:
    [[fallthrough]];
    case MsgSemantic::Response:
    [[fallthrough]];
    case MsgSemantic::Notify:
    [[fallthrough]];
    case MsgSemantic::Error:
        error_and_close("Invalid message direction: Server-to-client semantic received from client");
        co_return;
    default:
        error_and_close(std::format("Invalid message semantic {}", std::to_underlying(semantic)));
        co_return;
    }

    LOG_DEBUG("Connection {} read_body completed, restarting read_header", id);
    co_await read_header();
}

net::awaitable<void> Connection::handle_handshake(const Msg& msg)
{
    switch(state.load())
    {
    case ConnState::Connected:
    {
        if (msg.payload.size() != Kyber768::public_key_size)
        {
            send_raw_error(std::format("Invalid client public key size: expected {}, got {}",
                Kyber768::public_key_size, msg.payload.size()));
            co_return;
        }
        
        auto kp_result = kem.generate_keypair();
        if (!kp_result)
        {
            if (server) server->metrics().handshakes_failed++;
            send_raw_error("Failed to generate keypair");
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
            if (server) server->metrics().handshakes_failed++;
            send_raw_error("Failed to encapsulate to client public key");
            co_return;
        }
        ss_A = std::move(encap_result->shared_secret);
        
        std::vector<uint8_t> payload;
        payload.reserve(Kyber768::public_key_size + Kyber768::ciphertext_size);
        
        std::ranges::copy(kp->public_key, std::back_inserter(payload));
        std::ranges::copy(encap_result->ciphertext, std::back_inserter(payload));

        auto send_result = msg::make(to_bytes<uint8_t>(payload), plaintext_handshake);
        LOG_DEBUG("Connection {} msg::make success={}", id, send_result.has_value());
        if (!send_result)
        {
            send_raw_error(std::format("Failed to create handshake message, errc = {}", std::to_underlying(send_result.error())));
            co_return;
        }
        LOG_DEBUG("Connection {} calling send() with handshake response", id);
        send(*send_result);
        LOG_DEBUG("Connection {} send() returned", id);

        client_pk = cpk | std::ranges::to<Kyber768::key_t>();
        state.store(ConnState::Handshaking, std::memory_order_release);
        LOG_DEBUG("Connection {} handshake state changed to Handshaking", id);
        break;
    }
    
    case ConnState::Handshaking:
    {
        if (msg.payload.size() < Kyber768::ciphertext_size)
        {
            send_raw_error(std::format("Invalid handshake payload size: expected at least {}, got {}",
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
            if (server) server->metrics().handshakes_failed++;
            send_raw_error("Failed to decapsulate client ciphertext");
            co_return;
        }
        ss_local = std::move(*decap_result);
        
        auto encap_result = kem.encapsulate(*client_pk);
        if (!encap_result)
        {
            if (server) server->metrics().handshakes_failed++;
            send_raw_error("Failed to encapsulate to client public key");
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
            LOG_ERROR("Failed to encrypt handshake response");
            error_and_close("Failed to encrypt handshake response");
            co_return;
        }
        
        auto payload = *encrypted 
            | std::views::transform(int2byte) 
            | std::ranges::to<Msg::payload_t>();
        
        auto send_result = msg::make(payload, encrypted_response);
        if (!send_result)
        {
            LOG_ERROR("Failed to create encrypted response message");
            error_and_close("Failed to create encrypted response message");
            co_return;
        }
        send(*send_result);
        
        kp->secret_key.clear();
        kp->secret_key.shrink_to_fit();
        ss_A.reset();
        client_pk.reset();
        
        state.store(ConnState::Established, std::memory_order_release);
        LOG_INFO("Secure session established with {}", id);
        if (server) 
        {
            server->metrics().handshakes_completed++;
        }
        break;
    }

    case ConnState::Established:
    [[fallthrough]];
    case ConnState::Authenticated:
        std::ignore = send_error("Handshake already completed");
        co_return;
    
    case ConnState::Closing:
        co_return;

    default:
        LOG_ERROR("Invalid state for handshake for id = {}",get_id());
        error_and_close("Invalid state for handshake");
        co_return;
    }
}

net::awaitable<void> Connection::handle_encrypted(const Msg& msg)
{
    if (!sess.is_established())
    {
        send_raw_error("Session key not established");
        co_return;
    }

    auto ct = msg.payload 
        | std::views::transform(std::to_underlying<std::byte>) 
        | std::ranges::to<std::vector<uint8_t>>();
    
    auto decrypted = sess.decrypt(ct);
    if (!decrypted)
    {
        if (server) server->metrics().errors++;
        LOG_ERROR("Decryption failed in connection with {}", get_id());
        std::ignore = send_error("Decryption failed");
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
        std::ignore = send_error("Invalid JSON");
        co_return;
    }
    
    if (!parsed.is_object())
    {
        std::ignore = send_error("Request must be JSON object");
        co_return;
    }
    
    co_await handle_request(parsed.as_object());
}

net::awaitable<void> Connection::handle_request(const json::object& request)
{
    if(is_closing())
    {
        co_return;
    }
    if (server) server->metrics().messages_received++;
    evt_hdl.route(shared_from_this(), request);
    co_return;
}

void Connection::send(const Msg& msg)
{
    if(is_closing())
    {
        return;
    }
    //Avoid falling into recursive loop
    //Upon closing, give up appending anything else into the write queue or dispatching any coroutines
    //Queue-draining is `close()` responsibility

    LOG_DEBUG("Connection {} send() called, type={}, len={}", id, static_cast<int>(msg.type), msg.len);
    net::dispatch(strand,
        [this, self = shared_from_this(), msg]()
        {
            LOG_DEBUG("Connection {} dispatch lambda attempting to lock write_mtx", id);
            bool should_spawn = false;
            {
                std::lock_guard lock(write_mtx);
                LOG_DEBUG("Connection {} dispatch lambda acquired write_mtx, queue_size={}", id, write_queue.size());
                bool was_empty = write_queue.empty();
                write_queue.push_back(msg);
                
                if (!write_in_progress.load() && was_empty)
                {
                    write_in_progress.store(true);
                    should_spawn = true;
                }
                LOG_DEBUG("Connection {} dispatch lambda releasing write_mtx", id);
            }
            if (should_spawn)
            {
                LOG_DEBUG("Connection {} spawning write coroutine", id);
                net::co_spawn(strand,
                    [this, self]() -> net::awaitable<void>
                    {
                        LOG_DEBUG("Connection {} write coroutine started", self->id);
                        co_await write();
                        LOG_DEBUG("Connection {} write coroutine exited", self->id);
                    },
                    net::detached);
            }
            else
            {
                LOG_DEBUG("Connection {} write coroutine already running or queue not empty", id);
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
    if(is_closing())
    {
        //Do not clear writing queue: 
        // queue should either be drained by spawned coroutine, or be cleared by shutdown(immediate schematic)
        co_return;
    }

    while (true)
    {
        Msg msg;
        {
            std::lock_guard lock(write_mtx);
            if (write_queue.empty())
            {
                write_in_progress.store(false);
                co_return;
            }
            msg = std::move(write_queue.front());
            write_queue.pop_front();
        }
        
        auto result = co_await write_with_timeout(msg, cfg.timeouts().write_timeout);

        if (!result)
        //Write timeout, give up writing lingering data
        {
            {
                std::lock_guard lock(write_mtx);
                write_in_progress.store(false);
                write_queue.clear();
            }
            error_and_close("Write timeout");
            co_return;
        }
        
        if (auto e = result->ec)
        {
            LOG_WARN("Error occur in write to {}: {}", get_id(), e.message());
            {
                std::lock_guard lock(write_mtx);
                write_in_progress.store(false);
            }
            error_and_close("Pipe writing error");
            co_return;
        }
        
        // Track bytes and messages sent
        if (server) 
        {
            server->metrics().bytes_sent += result->bytes;
            server->metrics().messages_sent++;
        }
    }
}


void Connection::shutdown() noexcept
{
    try
    {
        state.store(ConnState::Closing);

        boost::system::error_code ec;
        socket.cancel(ec);
        write_queue.clear();
        socket.close(ec);
    }
    catch (...)
    {
        // noexcept - swallow all exceptions
    }
}

net::awaitable<void> Connection::close_async(CloseMode mode)
{
    switch (mode)
    {
    case CloseMode::Graceful:
        co_await write();
        break;

    case CloseMode::Immediate:
        shutdown();
        break;
    }
    
    server->remove_connection(id);
    co_return;
}

void Connection::close(CloseMode mode)
{
    // Rush E: don't wait for close_async to exchange
    // Optionally specify another memory order for performance optimization?  
    if(this->state.exchange(ConnState::Closing) == ConnState::Closing)
    {
        LOG_DEBUG("Connection already closing, deferring");
        return;
    }

    //Only one closing coroutine should be spawned
    net::co_spawn(strand,
        [self = shared_from_this(), mode]() -> net::awaitable<void>
        {
            LOG_DEBUG("Connection {} close coroutine starting", self->id);
            co_await self->close_async(mode);
            LOG_DEBUG("Connection {} close coroutine completed", self->id);
        }, net::detached);
}

//Defaults to force close
void Connection::send_raw_error(std::string_view err, CloseMode mode)
{
    if(is_closing())
    {
        return;
    }

    LOG_DEBUG("Connection {} send_raw_error: {}", id, err);
    static const Msg decay_msg = *msg::make(bytes::to_bytes("Unknown error"), plaintext_error);

    auto err_msg = msg::make(bytes::to_bytes(err), plaintext_error).value_or(decay_msg);
    send(err_msg); //sends anyway
    close(mode);
}

bool Connection::send_error(std::string_view err, CloseMode mode, bool force_close)
{
    if(is_closing())
    {
        return true; //"Exception" spreading
    }

    LOG_DEBUG("Connection {} send_error: {}", id, err);
    send_encrypted(status_msg("Error", err), encrypted_error);
    if (force_close || record_failure())
    {
        close(mode);
        return true;
    }
    return false;
}

void Connection::error_and_close(std::string_view err_text)
{
    if(is_closing()) //Already closing, do not append any error texts into it(mostly caused by write/read functions)
    {
        return;
    }

    if(has_session_key())
    {
        std::ignore = send_error(err_text, CloseMode::Graceful, true);
    }
    else
    {
        send_raw_error(err_text, CloseMode::Graceful);
    }
}