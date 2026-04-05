#pragma once

#include <boost/asio.hpp>
#include <optional>
#include <chrono>
#include "client/config.hpp"
#include "client/metrics.hpp"
#include "crypto/kyber768.hpp"
#include "crypto/session_key.hpp"
#include "fundamentals/types.hpp"

namespace net = boost::asio;
using tcp = net::ip::tcp;

class LoadConnection : public std::enable_shared_from_this<LoadConnection>
{
public:
    LoadConnection(net::io_context& io, std::string host, uint16_t port, size_t idx);

    net::awaitable<void> run(const LoadTestConfig& cfg, MetricsCollector& mts);

    [[nodiscard]] size_t get_idx() const { return conn_idx; }

private:
    net::awaitable<bool> do_handshake(const LoadTestConfig& cfg);
    net::awaitable<bool> do_auth(const LoadTestConfig& cfg, size_t user_idx);
    net::awaitable<bool> send_loop(const LoadTestConfig& cfg, MetricsCollector& mts);
    net::awaitable<bool> send_broadcast(std::string_view payload_data);
    net::awaitable<void> read_loop(const LoadTestConfig& cfg);
    net::awaitable<std::optional<Msg>> read_msg(std::chrono::seconds to);
    void shutdown() noexcept;

    tcp::socket sock;
    std::string host;
    uint16_t port;
    size_t conn_idx;
    crypto::Kyber768 kem;
    crypto::SessionKey cipher;
    std::optional<crypto::Kyber768::shared_secret_t> ss_local;
    std::optional<crypto::Kyber768::shared_secret_t> ss_remote;
    std::optional<crypto::Kyber768::keypair_t> kp;
};
