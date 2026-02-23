#include "server.hpp"
#include "config.hpp"
#include "logger.hpp"
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

Connection::Connection(tcp::socket sock, Server* srv, std::string conn_id, const Config& config, net::io_context& io)
    : strand(net::make_strand(io))
    , socket(std::move(sock))
    , server(srv)
    , id(std::move(conn_id))
    , state(ConnState::Connected)
    , write_in_progress(false)
    , fail_tracker(config.security().max_failures_before_disconnect)
    , config_(config)
    , write_mtx()
    , global_timer(strand)
{
    LOG_INFO("Connection established with id = {}", id);
    LOG_DEBUG("Connection {}: about to set global timer", id);
    reset_global_timer(config_.timeouts().handshake_timeout);
    LOG_DEBUG("Connection {}: global timer set complete", id);
}

Connection::~Connection() noexcept
{
    cancel_global_timer();
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

void Connection::reset_global_timer(std::chrono::seconds duration)
{
    LOG_DEBUG("Connection {}: reset_global_timer {}s", id, duration.count());
    global_timer.expires_after(duration);
    LOG_DEBUG("Connection {}: timer expiry set", id);
    /*
    global_timer.async_wait(
        net::bind_executor(strand, [self = shared_from_this()](boost::system::error_code ec)
        {
            if (!ec)
            {
                self->on_global_timeout();
            }
        }));
        */
    
    LOG_DEBUG("Connection {}: async_wait initiated", id);
}

void Connection::cancel_global_timer()
{
    boost::system::error_code ec;
    global_timer.cancel(ec);
}

void Connection::on_global_timeout()
{
    auto st = state.load(std::memory_order_acquire);
    if (st == ConnState::Connected || st == ConnState::Handshaking)
    {
        send_raw_error("Handshake timeout", CloseMode::CancelOthers);
    }
    else if (st == ConnState::Established || st == ConnState::Authenticated)
    {
        std::ignore = send_error("Session timeout", CloseMode::CancelOthers, true);
    }
}

void Connection::reset_session_timer()
{
    auto st = state.load(std::memory_order_acquire);
    if (st == ConnState::Established || st == ConnState::Authenticated)
    {
        reset_global_timer(config_.security().session_timeout);
    }
}

net::awaitable<Connection::IoResult> Connection::read_with_timeout(
    net::mutable_buffer buf,
    std::chrono::seconds timeout)
{
    using net::experimental::awaitable_operators::operator||;
    
    net::steady_timer timer(strand);
    timer.expires_after(timeout);
    
    auto read_op = [&]() -> net::awaitable<IoResult>
    {
        auto [ec, n] = co_await net::async_read(socket, buf, net::as_tuple(net::use_awaitable));
        timer.cancel();
        co_return IoResult{ec, n, false};
    };
    
    auto timer_op = [&]() -> net::awaitable<IoResult>
    {
        auto [ec] = co_await timer.async_wait(net::as_tuple(net::use_awaitable));
        co_return IoResult{ec, 0, true};
    };
    
    auto result = co_await (read_op() || timer_op());
    co_return result.index() == 0 ? std::get<0>(result) : std::get<1>(result);
}

net::awaitable<Connection::IoResult> Connection::write_with_timeout(
    const Msg& msg,
    std::chrono::seconds timeout)
{
    using net::experimental::awaitable_operators::operator||;
    
    net::steady_timer timer(strand);
    timer.expires_after(timeout);
    
    auto buf = msg::serialize(msg);
    
    auto write_op = [&]() -> net::awaitable<IoResult>
    {
        auto [ec, n] = co_await net::async_write(socket, net::buffer(buf), net::as_tuple(net::use_awaitable));
        timer.cancel();
        co_return IoResult{ec, n, false};
    };
    
    auto timer_op = [&]() -> net::awaitable<IoResult>
    {
        auto [ec] = co_await timer.async_wait(net::as_tuple(net::use_awaitable));
        co_return IoResult{ec, 0, true};
    };
    
    auto result = co_await (write_op() || timer_op());
    co_return std::get<0>(result);
}

net::awaitable<void> Connection::read_header()
{
    LOG_DEBUG("Connection {} read_header waiting for 4 bytes", id);
    read_buf.resize(4);

    auto result = co_await read_with_timeout(
        net::buffer(read_buf, 4),
        config_.timeouts().read_timeout);
    
    LOG_DEBUG("Connection {} read_header result: timed_out={}, ec={}, bytes={}",
              id, result.timed_out, result.ec.message(), result.bytes);
    
    if (result.timed_out)
    {
        if (is_pipe_dead())
        {
            co_return;
        }

        if(has_session_key())
        {
            //Encrypted error
            std::ignore = send_error("Read header timeout", CloseMode::CancelOthers, true);
        }
        else
        {
            send_raw_error("Read header timeout", CloseMode::CancelOthers);
        }
        co_return;
    }
    
    if (result.ec)
    {
        if (result.ec == net::error::eof ||
            result.ec == net::error::connection_reset ||
            result.ec == net::error::broken_pipe)
        {
            mark_pipe_dead();
        }
        send_raw_error("Read header error", CloseMode::CancelOthers);
        co_return;
    }
    
    uint32_t len = to_int(read_buf);

    if (result.bytes != 4 || len < 5 || len > Msg::max_len)
    {
        send_raw_error("Length verification error", CloseMode::CancelOthers);
        co_return;
    }

    co_await read_body(len);
}

net::awaitable<void> Connection::read_body(uint32_t len)
{
    LOG_DEBUG("Connection {} read_body waiting for {} bytes (total len={})", id, len - 4, len);
    read_buf.resize(len);

    auto result = co_await read_with_timeout(
        net::buffer(read_buf.data() + 4, len - 4),
        config_.timeouts().read_timeout);
    
    LOG_DEBUG("Connection {} read_body result: timed_out={}, ec={}, bytes={}",
              id, result.timed_out, result.ec.message(), result.bytes);
    
    if (result.timed_out)
    {
        record_failure();
        if (is_pipe_dead())
        {
            co_return;
        }
        send_raw_error("Read body timeout", CloseMode::CancelOthers);
        co_return;
    }
    
    if (result.ec)
    {
        if (result.ec == net::error::eof ||
            result.ec == net::error::connection_reset ||
            result.ec == net::error::broken_pipe)
        {
            mark_pipe_dead();
        }
        send_raw_error("Pipe reading error", CloseMode::CancelOthers);
        co_return;
    }
    
    if (result.bytes != len - 4)
    {
        send_raw_error("Incomplete read", CloseMode::CancelOthers);
        co_return;
    }
    
    auto m0 = msg::parse(read_buf);
    if (!m0)
    {
        LOG_DEBUG("Connection {} message parse error, errc={}", id, std::to_underlying(m0.error()));
        if (send_error("Message parse error", CloseMode::CancelOthers))
        {
            co_return;
        }
        co_return;
    }
    
    auto& msg = *m0;
    auto semantic = get_semantic(msg.type);
    bool encrypted = is_encrypted(msg.type);
    LOG_DEBUG("Connection {} received message: type={}, semantic={}, encrypted={}, payload_size={}", 
              id, static_cast<int>(msg.type), std::to_underlying(semantic), encrypted, msg.payload.size());
    
    if (state.load(std::memory_order_acquire) == ConnState::Connected || state.load(std::memory_order_acquire) == ConnState::Handshaking)
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
        LOG_DEBUG("Connection {} routing to handle_handshake", id);
        co_await handle_handshake(msg);
        LOG_DEBUG("Connection {} returned from handle_handshake", id);
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

    LOG_DEBUG("Connection {} read_body completed, restarting read_header", id);
    co_await read_header();
}

net::awaitable<void> Connection::handle_handshake(const Msg& msg)
{
    LOG_DEBUG("Connection {} handle_handshake entered, current state={}", id, std::to_underlying(state.load()));
    switch(state)
    {
    case ConnState::Connected:
    {
        LOG_DEBUG("Connection {} handshake state=Connected, payload_size={}", id, msg.payload.size());
        if (msg.payload.size() != Kyber768::public_key_size)
        {
            send_raw_error(std::format("Invalid client public key size: expected {}, got {}",
                Kyber768::public_key_size, msg.payload.size()), CloseMode::CancelOthers);
            co_return;
        }
        
        auto kp_result = kem.generate_keypair();
        LOG_DEBUG("Connection {} keypair generated, success={}", id, kp_result.has_value());
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
        LOG_DEBUG("Connection {} encapsulate success={}", id, encap_result.has_value());
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
        LOG_DEBUG("Connection {} msg::make success={}", id, send_result.has_value());
        if (!send_result)
        {
            send_raw_error(std::format("Failed to create handshake message, errc = {}", std::to_underlying(send_result.error())), CloseMode::CancelOthers);
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
        
        state.store(ConnState::Established, std::memory_order_release);
        reset_global_timer(config_.security().session_timeout);
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
    if (state.load(std::memory_order_acquire) != ConnState::Established && state.load(std::memory_order_acquire) != ConnState::Authenticated)
    {
        send_raw_error("Invalid state: encrypted connection not yet established", CloseMode::CancelOthers);
        co_return;
    }

    if (!sess.is_established())
    {
        send_raw_error("Session key not established", CloseMode::CancelOthers);
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
    LOG_DEBUG("Connection {} write() entered", id);
    while (true)
    {
        Msg msg;
        {
            LOG_DEBUG("Connection {} write() attempting to lock write_mtx", id);
            std::lock_guard lock(write_mtx);
            LOG_DEBUG("Connection {} write() acquired write_mtx", id);
            if (write_queue.empty())
            {
                LOG_DEBUG("Connection {} write queue empty, exiting", id);
                write_in_progress.store(false);
                co_return;
            }
            msg = std::move(write_queue.front());
            write_queue.pop_front();
            LOG_DEBUG("Connection {} write popped message from queue, {} remaining", id, write_queue.size());
            LOG_DEBUG("Connection {} write() releasing write_mtx", id);
        }
        
        auto result = co_await write_with_timeout(msg, config_.timeouts().write_timeout);
        LOG_DEBUG("Connection {} write result: timed_out={}, ec={}, bytes={}",
                  id, result.timed_out, result.ec.message(), result.bytes);
        
        if (result.timed_out)
        {
            record_failure();
            {
                std::lock_guard lock(write_mtx);
                write_in_progress.store(false);
                clear_write_queue();
            }
            send_raw_error("Write timeout", CloseMode::CancelOthers);
            co_return;
        }
        
        if (result.ec)
        {
            LOG_DEBUG("Connection {} write error: {}", id, result.ec.message());
            if (result.ec == net::error::eof ||
                result.ec == net::error::connection_reset ||
                result.ec == net::error::broken_pipe)
            {
                mark_pipe_dead();
            }
            {
                std::lock_guard lock(write_mtx);
                write_in_progress.store(false);
            }
            send_raw_error("Pipe writing error", CloseMode::CancelOthers);
            co_return;
        }
        LOG_DEBUG("Connection {} write successful, {} bytes sent", id, result.bytes);
    }
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
    LOG_DEBUG("Connection {} close() called, err='{}', mode={}", id, err, std::to_underlying(mode));
    net::co_spawn(strand,
        [self = shared_from_this(), err, mode]() -> net::awaitable<void>
        {
            LOG_DEBUG("Connection {} close coroutine starting", self->id);
            co_await self->close_async(err, mode);
            LOG_DEBUG("Connection {} close coroutine completed", self->id);
        }, net::detached);
}

//Defaults to force close
void Connection::send_raw_error(std::string_view err, CloseMode mode)
{
    LOG_DEBUG("Connection {} send_raw_error: {}", id, err);
    static const Msg decay_msg = *msg::make(bytes::to_bytes("Unknown error"), plaintext_error);
    auto err_msg = msg::make(bytes::to_bytes(err), plaintext_error).value_or(decay_msg);
    send(err_msg);
    close("", mode); // close_async will ignore the empty string
}

[[nodiscard("Do not discard send_error's value: caller is responsible for co_return upon this function returning true to prevent connection leakage.")]] bool Connection::send_error(std::string_view err, CloseMode mode, bool force_close)
{
    LOG_DEBUG("Connection {} send_error: {}", id, err);
    send_encrypted(status_msg("Error", err), encrypted_error);
    if (force_close || record_failure())
    {
        close("", mode);
        return true;
    }
    return false;
}