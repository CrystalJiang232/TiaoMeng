#include "client/client.hpp"

#include "fundamentals/bytes.hpp"
#include "fundamentals/msg_serialize.hpp"
#include "fundamentals/json_utils.hpp"
#include "crypto/utils.hpp"

#include <ranges>
#include <iostream>
#include <sstream>
#include <print>
#include <unordered_map>

namespace json = boost::json;
using namespace bytes;
using namespace msg;
using net::experimental::awaitable_operators::operator||;

Client::Client(const ClientConfig& cfg)
    : cfg(cfg)
    , owns_io_ctx(true)
    , io_ctx_storage(std::in_place)
    , io_ctx(*io_ctx_storage)
    , strand(net::make_strand(io_ctx))
    , sock(strand)
{
}

Client::Client(const ClientConfig& cfg, net::io_context& external_io)
    : cfg(cfg)
    , owns_io_ctx(false)
    , io_ctx(external_io)
    , strand(net::make_strand(io_ctx))
    , sock(strand)
{
}

Client::~Client() noexcept
{
    shutdown();
}

net::awaitable<std::expected<void, std::string>> Client::async_connect()
{
    if (getState() != ClientState::Disconnected)
    {
        co_return std::unexpected("Already connected or connecting");
    }
    
    tcp::resolver resolver(strand);
    auto [ec, results] = co_await resolver.async_resolve(
        cfg.host, 
        std::to_string(cfg.port), 
        net::as_tuple(net::use_awaitable));
    
    if (ec)
    {
        shutdown();
        co_return std::unexpected(std::format("Resolve failed: {}", ec.message()));
    }
    
    auto [ec2, ep] = co_await net::async_connect(
        sock, 
        results, 
        net::as_tuple(net::use_awaitable));
    
    if (ec2)
    {
        shutdown();
        co_return std::unexpected(std::format("Connect failed: {}", ec2.message()));
    }
    
    setState(ClientState::Connected);
    co_return std::expected<void, std::string>{};
}

net::awaitable<std::expected<void, std::string>> Client::async_disconnect()
{
    shutdown();
    co_return std::expected<void, std::string>{};
}

net::awaitable<std::expected<void, std::string>> Client::async_handshake()
{
    if (getState() != ClientState::Connected)
    {
        co_return std::unexpected("Must be connected before handshake");
    }
    
    // Simple workaround: ignore underlying error message anyway
    if(co_await handshakeStep1() && co_await handshakeStep2() && co_await handshakeStep3())
    {
        co_return std::expected<void, std::string>{};
    }
    else
    {
        shutdown(); // ...
        co_return std::unexpected("Handshake failed");
    }
}

net::awaitable<std::expected<void, std::string>> Client::handshakeStep1()
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
    
    auto [ec, n] = co_await net::async_write(
        sock, 
        net::buffer(msg::serialize(*step1)), 
        net::as_tuple(net::use_awaitable));
    
    if (ec)
    {
        co_return std::unexpected(std::format("Handshake step1 write failed: {}", ec.message()));
    }

    setState(ClientState::Handshaking); // ?
    
    co_return std::expected<void, std::string>{};
}

net::awaitable<std::expected<void, std::string>> Client::handshakeStep2()
{
    auto step2_result = co_await read_msg(cfg.handshake_timeout);
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
    
    auto [ec3, n3] = co_await net::async_write(
        sock, 
        net::buffer(msg::serialize(*step3)), 
        net::as_tuple(net::use_awaitable));
    
    if (ec3)
    {
        co_return std::unexpected(std::format("Handshake step3 write failed: {}", ec3.message()));
    }
    
    cipher.complete_handshake(
        std::span<const uint8_t>(ss_remote->data(), ss_remote->size()),
        std::span<const uint8_t>(ss_local->data(), ss_local->size())
    );
    
    crypto::secure_clear(kp->secret_key);
    
    co_return std::expected<void, std::string>{};
}

net::awaitable<std::expected<void, std::string>> Client::handshakeStep3()
{
    auto step4_result = co_await read_msg(cfg.handshake_timeout);
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
    
    setState(ClientState::Established);
    co_return std::expected<void, std::string>{};
}

net::awaitable<std::expected<void, std::string>> Client::async_auth(
    std::string_view username, std::string_view password)
{
    if (getState() != ClientState::Established)
    {
        co_return std::unexpected("Must complete handshake before auth");
    }
    
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
    
    auto send_r = co_await send_msg(*msg_result);
    if (!send_r)
    {
        co_return send_r;
    }
    
    auto resp_result = co_await read_msg(cfg.request_timeout);
    if (!resp_result)
    {
        co_return std::unexpected(resp_result.error());
    }
    
    auto resp = std::move(*resp_result);
    auto decrypted = cipher.decrypt(
        std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(resp.payload.data()), resp.payload.size())
    );
    
    if (!decrypted)
    {
        co_return std::unexpected("Decryption failed");
    }
    
    std::string resp_str(decrypted->begin(), decrypted->end());
    json::error_code jec;
    auto parsed = json::parse(resp_str, jec);
    
    if (jec || !parsed.is_object())
    {
        co_return std::unexpected("Invalid JSON in response");
    }
    
    auto status = json_utils::extract_str(parsed.as_object(), "status");
    if (!status || *status != "Success")
    {
        co_return std::unexpected(std::format("Auth failed: {}", status.value_or("<missing>")));
    }
    
    setState(ClientState::Authenticated);
    co_return std::expected<void, std::string>{};
}

net::awaitable<std::expected<json::object, std::string>> Client::async_send_command(
    const json::object& data)
{
    if (getState() != ClientState::Authenticated)
    {
        co_return std::unexpected("Must be authenticated");
    }
    
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
    
    auto send_r = co_await send_msg(*msg_result);
    if (!send_r)
    {
        co_return std::unexpected(send_r.error());
    }
    
    auto resp_result = co_await read_msg(cfg.request_timeout);
    if (!resp_result)
    {
        co_return std::unexpected(resp_result.error());
    }
    
    auto resp = std::move(*resp_result);
    auto decrypted = cipher.decrypt(
        std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(resp.payload.data()), resp.payload.size())
    );
    
    if (!decrypted)
    {
        co_return std::unexpected("Decryption failed");
    }
    
    std::string resp_str(decrypted->begin(), decrypted->end());
    json::error_code jec;
    auto parsed = json::parse(resp_str, jec);
    
    if (jec || !parsed.is_object())
    {
        co_return std::unexpected("Invalid JSON in response");
    }
    
    co_return parsed.as_object();
}

net::awaitable<std::expected<json::object, std::string>> Client::async_send_broadcast(
    std::string_view message)
{
    if (getState() != ClientState::Authenticated)
    {
        co_return std::unexpected("Must be authenticated");
    }
    
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
    
    auto send_r = co_await send_msg(*msg_result);
    if (!send_r)
    {
        co_return std::unexpected(send_r.error());
    }
    
    auto resp_result = co_await read_msg(cfg.request_timeout);
    if (!resp_result)
    {
        co_return std::unexpected(resp_result.error());
    }
    
    auto resp = std::move(*resp_result);
    auto decrypted = cipher.decrypt(
        std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(resp.payload.data()), resp.payload.size())
    );
    
    if (!decrypted)
    {
        co_return std::unexpected("Decryption failed");
    }
    
    std::string resp_str(decrypted->begin(), decrypted->end());
    json::error_code jec;
    auto parsed = json::parse(resp_str, jec);
    
    if (jec || !parsed.is_object())
    {
        co_return std::unexpected("Invalid JSON in response");
    }
    
    co_return parsed.as_object();
}

net::awaitable<std::expected<void, std::string>> Client::async_logout()
{
    if (getState() != ClientState::Authenticated)
    {
        co_return std::unexpected("Must be authenticated");
    }
    
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
    
    auto send_r = co_await send_msg(*msg_result);
    if (!send_r)
    {
        co_return send_r;
    }
    
    auto resp_result = co_await read_msg(cfg.request_timeout);
    if (!resp_result)
    {
        co_return std::unexpected(resp_result.error());
    }
    
    auto resp = std::move(*resp_result);
    auto decrypted = cipher.decrypt(
        std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(resp.payload.data()), resp.payload.size())
    );
    
    if (!decrypted)
    {
        co_return std::unexpected("Decryption failed");
    }
    
    std::string resp_str(decrypted->begin(), decrypted->end());
    json::error_code jec;
    auto parsed = json::parse(resp_str, jec);
    
    if (jec || !parsed.is_object())
    {
        co_return std::unexpected("Invalid JSON in response");
    }
    
    auto status = json_utils::extract_str(parsed.as_object(), "status");
    if (!status || *status != "Success")
    {
        co_return std::unexpected(std::format("Logout failed: {}", status.value_or("<missing>")));
    }
    
    setState(ClientState::Established);
    co_return std::expected<void, std::string>{};
}

net::awaitable<void> Client::run(
    std::optional<std::reference_wrapper<MetricsCollector>> mts)
{
    metrics = mts;
    
    auto conn_r = co_await async_connect();
    if (!conn_r)
    {
        if (metrics) metrics->get().record_fail();
        co_return;
    }
    
    auto hs_r = co_await async_handshake();
    if (!hs_r)
    {
        if (metrics) metrics->get().record_fail();
        shutdown();
        co_return;
    }
    
    auto u = std::format("{}{}", cfg.username_prefix, cfg.user_index);
    auto p = std::format("{}{}", cfg.password_prefix, cfg.user_index);
    
    auto auth_r = co_await async_auth(u, p);
    if (!auth_r)
    {
        if (metrics) metrics->get().record_fail();
        shutdown();
        co_return;
    }
    
    // Spawn read loop
    net::co_spawn(strand,
        [self = shared_from_this()]() -> net::awaitable<void>
        {
            co_await self->readLoop();
        },
        net::detached);
    
    // Run send loop
    if (metrics)
    {
        auto ok = co_await sendLoop(cfg, metrics->get());
        if (!ok)
        {
            metrics->get().record_fail();
        }
    }
    
    shutdown();
}

net::awaitable<bool> Client::sendLoop(const ClientConfig& cfg, MetricsCollector& mts)
{
    if (cfg.rate_per_sec == 0)
    {
        co_return true;
    }
    
    auto interval = std::chrono::microseconds(1'000'000 / cfg.rate_per_sec);
    auto start = std::chrono::steady_clock::now();
    auto warmup_end = start + cfg.warmup;
    auto deadline = start + cfg.test_duration + cfg.warmup;
    std::string data(cfg.payload_size, 'x');
    
    while (std::chrono::steady_clock::now() < deadline)
    {
        net::steady_timer t(strand);
        t.expires_after(interval);
        co_await t.async_wait(net::use_awaitable);
        
        if (std::chrono::steady_clock::now() < warmup_end)
        {
            continue;
        }
        
        auto r = co_await async_send_broadcast(data);
        if (!r)
        {
            co_return false;
        }
        
        mts.record_ok();
    }
    
    co_return true;
}

net::awaitable<void> Client::readLoop()
{
    while (getState() == ClientState::Authenticated || getState() == ClientState::Established)
    {
        auto m = co_await read_msg(cfg.request_timeout);
        if (!m)
        {
            // read_msg already called shutdown(), just exit
            co_return;
        }
        
        // For now, just consume. Future: demux notifications vs responses
    }
}

net::awaitable<std::optional<Client::IoResult>> Client::readWithTimeout(
    net::mutable_buffer buf, std::chrono::seconds timeout)
{
    if (getState() == ClientState::Disconnected || getState() == ClientState::Closing)
    {
        co_return std::nullopt;
    }
    
    net::steady_timer timer(strand);
    timer.expires_after(timeout);
    
    auto readOp = [&]() -> net::awaitable<IoResult>
    {
        auto [ec, n] = co_await net::async_read(sock, buf, net::as_tuple(net::use_awaitable));
        timer.cancel();
        co_return IoResult{ec, n};
    };
    
    auto timerOp = [&]() -> net::awaitable<void>
    {
        std::ignore = co_await timer.async_wait(net::as_tuple(net::use_awaitable));
        co_return;
    };
    
    auto result = co_await (readOp() || timerOp());
    if (result.index() == 0)
    {
        co_return std::get<0>(result);
    }
    
    co_return std::nullopt;
}

net::awaitable<std::optional<Client::IoResult>> Client::writeWithTimeout(
    net::const_buffer buf, std::chrono::seconds timeout)
{
    if (getState() == ClientState::Disconnected || getState() == ClientState::Closing)
    {
        co_return std::nullopt;
    }
    
    net::steady_timer timer(strand);
    timer.expires_after(timeout);
    
    auto writeOp = [&]() -> net::awaitable<IoResult>
    {
        auto [ec, n] = co_await net::async_write(sock, buf, net::as_tuple(net::use_awaitable));
        timer.cancel();
        co_return IoResult{ec, n};
    };
    
    auto timerOp = [&]() -> net::awaitable<void>
    {
        std::ignore = co_await timer.async_wait(net::as_tuple(net::use_awaitable));
        co_return;
    };
    
    auto result = co_await (writeOp() || timerOp());
    if (result.index() == 0)
    {
        co_return std::get<0>(result);
    }
    
    co_return std::nullopt;
}

net::awaitable<std::expected<Msg, std::string>> Client::read_msg(std::chrono::seconds timeout)
{
    std::array<std::byte, 5> hdr{};
    
    auto hdr_result = co_await readWithTimeout(net::buffer(hdr), timeout);
    if (!hdr_result || hdr_result->ec)
    {
        shutdown();
        co_return std::unexpected("Read header error, connection closed");
    }
    
    if (hdr_result->bytes != 5)
    {
        shutdown();
        co_return std::unexpected("Header read failed: incomplete read");
    }
    
    uint32_t len = to_int(hdr);
    if (len < 5 || len > Msg::max_len)
    {
        shutdown();
        co_return std::unexpected("Invalid message length");
    }
    
    read_buf.resize(len);
    std::ranges::copy(hdr, read_buf.begin());
    size_t body_len = len - 5;
    
    if (body_len > 0)
    {
        auto body_result = co_await readWithTimeout(
            net::buffer(read_buf.data() + 5, body_len), 
            timeout);
        
        if (!body_result || body_result->ec)
        {
            shutdown();
            co_return std::unexpected("Read body error, connection closed");
        }
        
        if (body_result->bytes != body_len)
        {
            shutdown();
            co_return std::unexpected("Body read failed: incomplete read");
        }
    }
    
    auto parsed = msg::parse(read_buf);
    if (!parsed)
    {
        co_return std::unexpected("Message parse failed");
    }
    
    co_return *parsed;
}

net::awaitable<std::expected<void, std::string>> Client::send_msg(const Msg& m)
{
    auto buf = msg::serialize(m);
    
    auto result = co_await writeWithTimeout(net::buffer(buf), cfg.request_timeout);
    if (!result || result->ec)
    {
        shutdown();
        co_return std::unexpected(std::format("Write failed, connection closed"));
    }
    co_return std::expected<void, std::string>{};
}

void Client::enqueue_msg(const Msg& m)
{
    net::dispatch(strand,
        [this, self = shared_from_this(), m]()
        {
            bool was_empty = write_queue.empty();
            write_queue.push_back(m);
            
            if (!write_in_progress.load(std::memory_order_acquire) && was_empty)
            {
                write_in_progress.store(true, std::memory_order_release);
                net::co_spawn(strand,
                    [this, self]() -> net::awaitable<void>
                    {
                        co_await writeLoop();
                    },
                    net::detached);
            }
        });
}

net::awaitable<void> Client::writeLoop()
{
    while (true)
    {
        Msg m;
        {
            std::lock_guard lock(write_mtx);
            if (write_queue.empty())
            {
                write_in_progress.store(false, std::memory_order_release);
                co_return;
            }
            m = std::move(write_queue.front());
            write_queue.pop_front();
        }
        
        auto buf = msg::serialize(m);
        auto result = co_await writeWithTimeout(net::buffer(buf), cfg.request_timeout);
        
        if (!result || result->ec)
        {
            std::lock_guard lock(write_mtx);
            write_in_progress.store(false, std::memory_order_release);
            write_queue.clear();
            shutdown();
            co_return;
        }
    }
}

void Client::setState(ClientState new_state)
{
    state.store(new_state, std::memory_order_release);
    if (cfg.on_state_change)
    {
        cfg.on_state_change(static_cast<int>(new_state));
    }
}

bool Client::is_connected() const
{
    auto s = getState();
    return s != ClientState::Disconnected && s != ClientState::Closing;
}

bool Client::is_established() const
{
    auto s = getState();
    return s == ClientState::Established || s == ClientState::Authenticated;
}

bool Client::is_authenticated() const
{
    return getState() == ClientState::Authenticated;
}

void Client::shutdown() noexcept
{
    if(state.exchange(ClientState::Closing, std::memory_order_acq_rel) == ClientState::Closing)
    {
        return;  
    }

    clearCrypto();
    boost::system::error_code ec;
    sock.cancel(ec);
    
    {
        std::lock_guard lock(write_mtx);
        write_queue.clear();
    }
    
    sock.close(ec);
    
    setState(ClientState::Disconnected); 
}

void Client::clearCrypto() noexcept
{
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
}

// Sync API wrappers
std::expected<void, std::string> Client::connect()
{
    auto fut = net::co_spawn(strand,
        [this]() -> net::awaitable<std::expected<void, std::string>>
        {
            co_return co_await async_connect();
        },
        net::use_future);
    
    if (owns_io_ctx)
    {
        io_ctx.run();
        io_ctx.restart();
    }
    
    return fut.get();
}

std::expected<void, std::string> Client::disconnect()
{
    shutdown();

    

    return {};
}

std::expected<void, std::string> Client::handshake()
{
    auto fut = net::co_spawn(strand,
        [this]() -> net::awaitable<std::expected<void, std::string>>
        {
            co_return co_await async_handshake();
        },
        net::use_future);
    
    if (owns_io_ctx)
    {
        io_ctx.run();
        io_ctx.restart();
    }
    
    return fut.get();
}

std::expected<void, std::string> Client::authenticate(
    std::string_view username, std::string_view password)
{
    auto fut = net::co_spawn(strand,
        [this, username, password]() -> net::awaitable<std::expected<void, std::string>>
        {
            co_return co_await async_auth(username, password);
        },
        net::use_future);
    
    if (owns_io_ctx)
    {
        io_ctx.run();
        io_ctx.restart();
    }
    
    return fut.get();
}

std::expected<json::object, std::string> Client::send_command(
    const json::object& data)
{
    auto fut = net::co_spawn(strand,
        [this, &data]() -> net::awaitable<std::expected<json::object, std::string>>
        {
            co_return co_await async_send_command(data);
        },
        net::use_future);
    
    if (owns_io_ctx)
    {
        io_ctx.run();
        io_ctx.restart();
    }
    
    return fut.get();
}

std::expected<json::object, std::string> Client::send_broadcast(
    std::string_view message)
{
    auto fut = net::co_spawn(strand,
        [this, message]() -> net::awaitable<std::expected<json::object, std::string>>
        {
            co_return co_await async_send_broadcast(message);
        },
        net::use_future);
    
    if (owns_io_ctx)
    {
        io_ctx.run();
        io_ctx.restart();
    }
    
    return fut.get();
}

std::expected<void, std::string> Client::logout()
{
    auto fut = net::co_spawn(strand,
        [this]() -> net::awaitable<std::expected<void, std::string>>
        {
            co_return co_await async_logout();
        },
        net::use_future);
    
    if (owns_io_ctx)
    {
        io_ctx.run();
        io_ctx.restart();
    }
    
    return fut.get();
}

void Client::run_interactive()
{
    // Helper for abbreviation matching
    auto resolve_cmd = [](std::string_view input) -> std::optional<std::string>
    {
        static const std::unordered_map<std::string, std::vector<std::string>> abbrevs = {
            {"connect", {"c", "conn"}},
            {"auth", {"a", "login"}},
            {"command", {"cmd"}},
            {"broadcast", {"b"}},
            {"disconnect", {"d"}},
            {"status", {"s", "stat"}},
            {"logout", {"l"}},
            {"help", {"h", "?"}},
            {"quit", {"q", "exit"}}
        };
        
        for (const auto& [full, aliases] : abbrevs)
        {
            if (input == full || std::ranges::contains(aliases, input))
            {
                return full;
            }
        }
        return std::nullopt;
    };
    
    std::println("TiaoMeng Interactive Client");
    std::println("Type 'help' for commands, 'quit' to exit.");
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
        
        line.erase(0, line.find_first_not_of(" \t\r\n"));
        line.erase(line.find_last_not_of(" \t\r\n") + 1);
        
        if (line.empty())
        {
            continue;
        }
        
        std::istringstream iss(line);
        std::string cmd;
        iss >> cmd;
        
        // Resolve abbreviations
        auto resolved = resolve_cmd(cmd);
        if (resolved)
        {
            cmd = *resolved;
        }
        
        if (cmd == "quit" || cmd == "exit")
        {
            break;
        }
        
        if (cmd == "help")
        {
            std::println("Commands:");
            std::println("  connect [host] [port]  - Connect to server (conn)");
            std::println("  auth <user> <pass>     - Authenticate (a, login)");
            std::println("  command <json>         - Send command (cmd)");
            std::println("  broadcast <message>    - Broadcast message (b)");
            std::println("  status                 - Show connection status (s, stat)");
            std::println("  logout                 - Log out (keep connection) (l)");
            std::println("  disconnect             - Close connection (d)");
            std::println("  quit/exit              - Exit (q)");
            std::println("  help                   - Show this help (h, ?)");
            continue;
        }
        
        if (cmd == "connect")
        {
            auto r = connect();
            if (!r)
            {
                std::println("Connect failed: {}", r.error());
                continue;
            }
            
            auto r2 = handshake();
            if (!r2)
            {
                std::println("Handshake failed: {}", r2.error());
                std::ignore = disconnect();
                continue;
            }
            
            std::println("Connected. Use 'auth <user> <pass>' to authenticate.");
            continue;
        }
        
        if (cmd == "auth")
        {
            std::string user, pass;
            iss >> user >> pass;
            
            if (user.empty() || pass.empty())
            {
                std::print("Username: ");
                std::flush(std::cout);
                std::getline(std::cin, user);
                user.erase(0, user.find_first_not_of(" \t\r\n"));
                
                std::print("Password: ");
                std::flush(std::cout);
                std::getline(std::cin, pass);
            }
            
            if (user.empty() || pass.empty())
            {
                std::println("Error: Username and password required");
                continue;
            }
            
            auto r = authenticate(user, pass);
            if (!r)
            {
                std::println("Auth failed: {}", r.error());
                continue;
            }
            
            std::println("Authenticated successfully.");
            continue;
        }
        
        if (cmd == "command")
        {
            if (!is_authenticated())
            {
                std::println("Error: Must be authenticated");
                continue;
            }
            
            std::string json_str;
            std::getline(iss, json_str);
            json_str.erase(0, json_str.find_first_not_of(" \t"));
            
            if (json_str.empty())
            {
                std::println("Error: JSON payload required");
                continue;
            }
            
            json::error_code jec;
            auto parsed = json::parse(json_str, jec);
            if (jec || !parsed.is_object())
            {
                std::println("Error: Invalid JSON");
                continue;
            }
            
            auto r = send_command(parsed.as_object());
            if (!r)
            {
                std::println("Command failed: {}", r.error());
                continue;
            }
            
            std::println("Response: {}", json::serialize(*r));
            continue;
        }
        
        if (cmd == "broadcast")
        {
            if (!is_authenticated())
            {
                std::println("Error: Must be authenticated");
                continue;
            }
            
            std::string message;
            std::getline(iss, message);
            message.erase(0, message.find_first_not_of(" \t"));
            
            if (message.empty())
            {
                std::println("Error: Message required");
                continue;
            }
            
            auto r = send_broadcast(message);
            if (!r)
            {
                std::println("Broadcast failed: {}", r.error());
                continue;
            }
            
            std::println("Response: {}", json::serialize(*r));
            continue;
        }
        
        if (cmd == "status")
        {
            auto s = getState();
            std::string state_str;
            switch (s)
            {
                case ClientState::Disconnected: state_str = "Disconnected"; break;
                case ClientState::Connected: state_str = "Connected"; break;
                case ClientState::Handshaking: state_str = "Handshaking"; break;
                case ClientState::Established: state_str = "Established"; break;
                case ClientState::Authenticated: state_str = "Authenticated"; break;
                case ClientState::Closing: state_str = "Closing"; break;
            }
            
            std::println("State: {}", state_str);
            std::println("Connected: {}", is_connected() ? "yes" : "no");
            std::println("Established: {}", is_established() ? "yes" : "no");
            std::println("Authenticated: {}", is_authenticated() ? "yes" : "no");
            continue;
        }
        
        if (cmd == "logout")
        {
            if (!is_authenticated())
            {
                std::println("Error: Not authenticated");
                continue;
            }
            
            auto r = logout();
            if (!r)
            {
                std::println("Logout failed: {}", r.error());
                continue;
            }
            
            std::println("Logged out successfully.");
            continue;
        }
        
        if (cmd == "disconnect")
        {
            auto r = disconnect();
            if (!r)
            {
                std::println("Disconnect failed: {}", r.error());
                continue;
            }
            std::println("Disconnected.");
            continue;
        }
        
        std::println("Unknown command: {}. Type 'help' for available commands.", cmd);
    }
    
    std::println("Goodbye.");
}
