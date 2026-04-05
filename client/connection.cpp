#include "client/connection.hpp"

#include "fundamentals/bytes.hpp"
#include "fundamentals/msg_serialize.hpp"
#include "fundamentals/json_utils.hpp"
#include "crypto/utils.hpp"
#include "logger/logger.hpp"
#include <boost/asio.hpp>
#include <boost/asio/experimental/awaitable_operators.hpp>
#include <boost/json.hpp>
#include <ranges>
#include <format>

namespace json = boost::json;
using namespace bytes;
using namespace msg;

LoadConnection::LoadConnection(net::io_context& io, std::string h, uint16_t p, size_t idx)
    : sock(io)
    , host(std::move(h))
    , port(p)
    , conn_idx(idx)
{
}

net::awaitable<void> LoadConnection::run(const LoadTestConfig& cfg, MetricsCollector& mts)
{
    LOG_DEBUG("Connection {} run() started", conn_idx);
    tcp::resolver resolver(sock.get_executor());
    auto [ec, results] = co_await resolver.async_resolve(host, std::to_string(port), net::as_tuple(net::use_awaitable));
    
    if (ec)
    {
        LOG_DEBUG("Connection {} resolve failed: {}", conn_idx, ec.message());
        mts.record_fail();
        co_return;
    }
    
    LOG_DEBUG("Connection {} resolving completed", conn_idx);
    auto [ec2, ep] = co_await net::async_connect(sock, results, net::as_tuple(net::use_awaitable));
    
    if (ec2)
    {
        LOG_DEBUG("Connection {} connect failed: {}", conn_idx, ec2.message());
        mts.record_fail();
        co_return;
    }
    
    LOG_DEBUG("Connection {} connected", conn_idx);
    if (!co_await do_handshake(cfg))
    {
        LOG_DEBUG("Connection {} handshake failed", conn_idx);
        mts.record_fail();
        shutdown();
        co_return;
    }
    
    LOG_DEBUG("Connection {} handshake completed", conn_idx);
    size_t user_idx = conn_idx % cfg.users_count;
    
    if (!co_await do_auth(cfg, user_idx))
    {
        LOG_DEBUG("Connection {} auth failed for user {}", conn_idx, user_idx);
        mts.record_fail();
        shutdown();
        co_return;
    }
    
    LOG_DEBUG("Connection {} authenticated as user {}", conn_idx, user_idx);
    net::co_spawn(sock.get_executor(),
        [self = shared_from_this(), &cfg]() -> net::awaitable<void>
        {
            LOG_DEBUG("Connection {} read_loop spawned", self->conn_idx);
            co_await self->read_loop(cfg);
            LOG_DEBUG("Connection {} read_loop exited", self->conn_idx);
        },
        net::detached);
    
    if (!co_await send_loop(cfg, mts))
    {
        LOG_DEBUG("Connection {} send_loop failed", conn_idx);
        shutdown();
        co_return;
    }
    
    LOG_DEBUG("Connection {} send_loop completed, shutting down", conn_idx);
    shutdown();
}

net::awaitable<bool> LoadConnection::do_handshake(const LoadTestConfig& cfg)
{
    LOG_DEBUG("Connection {} do_handshake started", conn_idx);
    auto kp_opt = kem.generate_keypair();
    if (!kp_opt)
    {
        LOG_DEBUG("Connection {} keypair generation failed", conn_idx);
        co_return false;
    }
    
    kp = std::move(*kp_opt);
    LOG_DEBUG("Connection {} keypair generated", conn_idx);
    
    auto step1 = msg::make(to_bytes<uint8_t>(kp->public_key), plaintext_handshake);
    if (!step1)
    {
        LOG_DEBUG("Connection {} step1 msg creation failed", conn_idx);
        co_return false;
    }
    
    auto [ec1, n1] = co_await net::async_write(sock, net::buffer(msg::serialize(*step1)), net::as_tuple(net::use_awaitable));
    if (ec1)
    {
        LOG_DEBUG("Connection {} step1 write failed: {}", conn_idx, ec1.message());
        co_return false;
    }
    
    LOG_DEBUG("Connection {} step1 sent", conn_idx);
    auto step2 = co_await read_msg(std::chrono::seconds(cfg.timeout_sec));
    if (!step2 || step2->payload.size() < crypto::Kyber768::public_key_size + crypto::Kyber768::ciphertext_size)
    {
        co_return false;
    }
    
    std::span<const uint8_t> server_pk(
        reinterpret_cast<const uint8_t*>(step2->payload.data()),
        crypto::Kyber768::public_key_size
    );
    std::span<const uint8_t> server_ct(
        reinterpret_cast<const uint8_t*>(step2->payload.data()) + crypto::Kyber768::public_key_size,
        crypto::Kyber768::ciphertext_size
    );
    
    auto decap = kem.decapsulate(server_ct, kp->secret_key);
    if (!decap)
    {
        co_return false;
    }
    
    ss_local = std::move(*decap);
    
    auto encap = kem.encapsulate(server_pk);
    if (!encap)
    {
        co_return false;
    }
    
    ss_remote = std::move(encap->shared_secret);
    
    auto step3 = msg::make(to_bytes<uint8_t>(encap->ciphertext), plaintext_handshake);
    if (!step3)
    {
        co_return false;
    }
    
    auto [ec3, n3] = co_await net::async_write(sock, net::buffer(msg::serialize(*step3)), net::as_tuple(net::use_awaitable));
    if (ec3)
    {
        co_return false;
    }
    
    cipher.complete_handshake(
        std::span<const uint8_t>(ss_remote->data(), ss_remote->size()),
        std::span<const uint8_t>(ss_local->data(), ss_local->size())
    );
    
    LOG_DEBUG("Connection {} session key established", conn_idx);
    crypto::secure_clear(kp->secret_key);
    
    auto step4 = co_await read_msg(std::chrono::seconds(cfg.timeout_sec));
    if (!step4)
    {
        co_return false;
    }
    
    auto decrypted = cipher.decrypt(
        std::span<const uint8_t>(
            reinterpret_cast<const uint8_t*>(step4->payload.data()),
            step4->payload.size()
        )
    );
    if (!decrypted)
    {
        co_return false;
    }
    
    std::string json_str(reinterpret_cast<const char*>(decrypted->data()), decrypted->size());
    json::error_code jec;
    auto parsed = json::parse(json_str, jec);
    
    if (jec || !parsed.is_object())
    {
        co_return false;
    }
    
    auto status = json_utils::extract_str(parsed.as_object(), "status");
    LOG_DEBUG("Connection {} handshake status: {}", conn_idx, status.value_or("<missing>"));
    co_return status && *status == "ConnectionReady";
}

net::awaitable<bool> LoadConnection::do_auth(const LoadTestConfig& cfg, size_t user_idx)
{
    LOG_DEBUG("Connection {} do_auth started for user {}", conn_idx, user_idx);
    auto u = std::format("{}{}", cfg.username_prefix, user_idx);
    auto p = std::format("{}{}", cfg.password_prefix, user_idx);
    json::object req{{"action", "auth"}, {"username", u}, {"password", p}};
    
    auto json_str = json::serialize(req);
    std::vector<uint8_t> plaintext(json_str.begin(), json_str.end());
    auto encrypted = cipher.encrypt(plaintext);
    
    if (!encrypted)
    {
        co_return false;
    }
    
    auto payload = *encrypted
        | std::views::transform([](uint8_t x) { return bytes::int2byte(x); })
        | std::ranges::to<Msg::payload_t>();
    auto msg_result = msg::make(payload, encrypted_request);
    
    if (!msg_result)
    {
        co_return false;
    }
    
    auto [ec, n] = co_await net::async_write(sock, net::buffer(msg::serialize(*msg_result)), net::as_tuple(net::use_awaitable));
    if (ec)
    {
        co_return false;
    }
    
    auto resp = co_await read_msg(std::chrono::seconds(cfg.timeout_sec));
    if (!resp)
    {
        co_return false;
    }
    
    auto decrypted = cipher.decrypt(
        std::span<const uint8_t>(
            reinterpret_cast<const uint8_t*>(resp->payload.data()),
            resp->payload.size()
        )
    );
    if (!decrypted)
    {
        co_return false;
    }
    
    std::string resp_str(decrypted->begin(), decrypted->end());
    json::error_code jec;
    auto parsed = json::parse(resp_str, jec);
    
    if (jec || !parsed.is_object())
    {
        co_return false;
    }
    
    auto status = json_utils::extract_str(parsed.as_object(), "status");
    LOG_DEBUG("Connection {} auth status: {}", conn_idx, status.value_or("<missing>"));
    co_return status && *status == "Success";
}

net::awaitable<bool> LoadConnection::send_loop(const LoadTestConfig& cfg, MetricsCollector& mts)
{
    LOG_DEBUG("Connection {} send_loop started", conn_idx);
    auto interval = std::chrono::microseconds(1'000'000 / cfg.rate_per_sec);
    auto start = std::chrono::steady_clock::now();
    auto warmup_end = start + std::chrono::seconds(cfg.warmup_sec);
    auto deadline = start + std::chrono::seconds(cfg.duration_sec + cfg.warmup_sec);
    std::string data(cfg.payload_size, 'x');
    
    while (std::chrono::steady_clock::now() < deadline)
    {
        net::steady_timer t(sock.get_executor());
        t.expires_after(interval);
        co_await t.async_wait(net::use_awaitable);
        
        if (std::chrono::steady_clock::now() < warmup_end)
        {
            continue;
        }
        
        if (!co_await send_broadcast(data))
        {
            LOG_DEBUG("Connection {} send_broadcast failed", conn_idx);
            mts.record_fail();
            co_return false;
        }
        
        mts.record_ok();
    }
    
    LOG_DEBUG("Connection {} send_loop completed", conn_idx);
    co_return true;
}

net::awaitable<bool> LoadConnection::send_broadcast(std::string_view payload_data)
{
    LOG_DEBUG("Connection {} send_broadcast", conn_idx);
    json::object req{{"action", "broadcast"}, {"message", std::string(payload_data)}};
    auto json_str = json::serialize(req);
    std::vector<uint8_t> plaintext(json_str.begin(), json_str.end());
    auto encrypted = cipher.encrypt(plaintext);
    
    if (!encrypted)
    {
        co_return false;
    }
    
    auto payload = *encrypted
        | std::views::transform([](uint8_t x) { return bytes::int2byte(x); })
        | std::ranges::to<Msg::payload_t>();
    auto msg_result = msg::make(payload, encrypted_request);
    
    if (!msg_result)
    {
        co_return false;
    }
    
    auto buf = msg::serialize(*msg_result);
    auto [ec, n] = co_await net::async_write(sock, net::buffer(buf), net::as_tuple(net::use_awaitable));
    if (ec)
    {
        LOG_DEBUG("Connection {} send_broadcast write failed: {}", conn_idx, ec.message());
    }
    co_return !ec;
}

net::awaitable<void> LoadConnection::read_loop(const LoadTestConfig& cfg)
{
    LOG_DEBUG("Connection {} read_loop started", conn_idx);
    while (true)
    {
        auto m = co_await read_msg(std::chrono::seconds(cfg.timeout_sec));
        if (!m)
        {
            LOG_DEBUG("Connection {} read_loop msg read failed or timeout", conn_idx);
            co_return;
        }
        LOG_DEBUG("Connection {} read_loop received msg type={} len={}", conn_idx, static_cast<int>(m->type), m->len);
    }
}

net::awaitable<std::optional<Msg>> LoadConnection::read_msg(std::chrono::seconds to)
{
    LOG_DEBUG("Connection {} read_msg waiting", conn_idx);
    using net::experimental::awaitable_operators::operator||;
    
    net::steady_timer timer(sock.get_executor());
    timer.expires_after(to);
    
    auto read_op = [&]() -> net::awaitable<Msg>
    {
        std::array<std::byte, 5> hdr{};
        auto [ec1, n1] = co_await net::async_read(sock, net::buffer(hdr), net::as_tuple(net::use_awaitable));
        timer.cancel();
        
        if (ec1 || n1 != 5)
        {
            LOG_DEBUG("Connection {} read_msg header error ec={} n={}", conn_idx, ec1.message(), n1);
            co_return Msg{};
        }
        
        uint32_t len = to_int(hdr);
        if (len < 5 || len > Msg::max_len)
        {
            LOG_DEBUG("Connection {} read_msg bad len={}", conn_idx, len);
            co_return Msg{};
        }
        
        std::vector<std::byte> buf(len);
        std::ranges::copy(hdr, buf.begin());
        size_t body_len = len - 5;
        
        if (body_len > 0)
        {
            auto [ec2, n2] = co_await net::async_read(sock, net::buffer(buf.data() + 5, body_len), net::as_tuple(net::use_awaitable));
            if (ec2 || n2 != body_len)
            {
                LOG_DEBUG("Connection {} read_msg body error ec={} n={}", conn_idx, ec2.message(), n2);
                co_return Msg{};
            }
        }
        
        auto parsed = msg::parse(buf);
        co_return parsed.value_or(Msg{});
    };
    
    auto timer_op = [&]() -> net::awaitable<void>
    {
        std::ignore = co_await timer.async_wait(net::as_tuple(net::use_awaitable));
        co_return;
    };
    
    auto result = co_await (read_op() || timer_op());
    if (result.index() == 0)
    {
        auto m = std::get<0>(result);
        if (m.len < 5)
        {
            LOG_DEBUG("Connection {} read_msg invalid msg after read", conn_idx);
            co_return std::nullopt;
        }
        LOG_DEBUG("Connection {} read_msg completed len={}", conn_idx, m.len);
        co_return m;
    }
    
    LOG_DEBUG("Connection {} read_msg timeout", conn_idx);
    co_return std::nullopt;
}

void LoadConnection::shutdown() noexcept
{
    LOG_DEBUG("Connection {} shutdown", conn_idx);
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
}
