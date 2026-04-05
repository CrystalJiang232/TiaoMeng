#include "client/config.hpp"
#include "client/metrics.hpp"
#include "client/connection.hpp"
#include "client/client.hpp"
#include "logger/logger.hpp"

#include <boost/asio.hpp>
#include <thread>
#include <latch>
#include <atomic>
#include <print>
#include <cstdlib>
#include <format>

namespace net = boost::asio;

std::expected<void, std::string> setup_test_users(const LoadTestConfig& cfg)
{
    for (size_t i = 0; i < cfg.users_count; ++i)
    {
        auto u = std::format("{}{}", cfg.username_prefix, i);
        auto p = std::format("{}{}", cfg.password_prefix, i);
        auto cmd = std::format("./build/bin/user_admin add {} {}", u, p);
        
        if (std::system(cmd.c_str()) != 0)
        {
            return std::unexpected(std::format("Failed to add user {}", u));
        }
    }
    
    return {};
}

std::expected<void, std::string> teardown_test_users(const LoadTestConfig& cfg)
{
    for (size_t i = 0; i < cfg.users_count; ++i)
    {
        auto u = std::format("{}{}", cfg.username_prefix, i);
        auto cmd = std::format("./build/bin/user_admin remove {}", u);
        int rc = std::system(cmd.c_str());
        (void)rc;
    }
    
    return {};
}

net::awaitable<void> watchdog_timer(net::io_context& io, std::chrono::seconds duration, std::atomic<bool>& stopped)
{
    net::steady_timer timer(io);
    timer.expires_after(duration);
    co_await timer.async_wait(net::use_awaitable);
    LOG_INFO("Watchdog: Test duration reached, stopping io_context");
    stopped.store(true, std::memory_order_release);
    io.stop();
}

int run_load_test(const LoadTestConfig& cfg)
{
    LOG_DEBUG("Parsed config: host={}, port={}, connections={}, duration={}",
              cfg.host, cfg.port, cfg.connections, cfg.duration_sec);
    
    if (auto r = setup_test_users(cfg); !r)
    {
        std::println(stderr, "Setup failed: {}", r.error());
        Logger::shutdown();
        return 1;
    }
    
    size_t hw_threads = std::thread::hardware_concurrency();
    if (hw_threads == 0)
    {
        hw_threads = 2;
    }
    
    LOG_DEBUG("Using {} worker threads", hw_threads);
    
    net::io_context io(static_cast<int>(hw_threads));
    MetricsCollector mts;
    std::latch completion_latch(cfg.connections);
    std::atomic<bool> stopped{false};
    
    auto work_guard = net::make_work_guard(io);
    
    for (size_t i = 0; i < cfg.connections; ++i)
    {
        auto conn = std::make_shared<LoadConnection>(io, cfg.host, cfg.port, i);
        net::co_spawn(io,
            [conn, &conf = cfg, &mts, &completion_latch]() -> net::awaitable<void>
            {
                LOG_DEBUG("Spawning connection {}", conn->get_idx());
                co_await conn->run(conf, mts);
                LOG_DEBUG("Connection {} coroutine exited", conn->get_idx());
                completion_latch.count_down();
            },
            net::detached);
    }
    
    net::co_spawn(io, watchdog_timer(io, 
        std::chrono::seconds(cfg.duration_sec + cfg.warmup_sec + 10), stopped), net::detached);
    
    std::vector<std::jthread> pool;
    for (size_t t = 0; t < hw_threads; ++t)
    {
        pool.emplace_back([&io]() { io.run(); });
    }
    
    LOG_DEBUG("Waiting for all connections to complete...");
    completion_latch.wait();
    LOG_DEBUG("All connections completed");
    
    work_guard.reset();
    
    for (auto& th : pool)
    {
        th.join();
    }
    
    LOG_DEBUG("All worker threads joined");
    
    std::println("OK: {}  FAIL: {}  RPS: {:.2f}",
                 mts.ok_count(), mts.fail_count(),
                 static_cast<double>(mts.ok_count()) / static_cast<double>(cfg.duration_sec));
    
    if (auto r = teardown_test_users(cfg); !r)
    {
        std::println(stderr, "Teardown failed: {}", r.error());
    }
    
    return 0;
}

int run_interactive(const LoadTestConfig& cfg)
{
    Client client(cfg.host, cfg.port);
    client.run_interactive_loop();
    return 0;
}

int main(int argc, char** argv)
{
    auto cfg = LoadTestConfigParser::parse(argc, argv);
    if (!cfg)
    {
        if (!cfg.error().empty())
        {
            std::println(stderr, "Config error: {}", cfg.error());
            return 1;
        }
        return 0;
    }
    
    if (cfg->interactive)
    {
        return run_interactive(*cfg);
    }
    
    if (auto r = Logger::init(cfg->log_level, cfg->log_file, cfg->log_max_size_mb, cfg->log_console); !r)
    {
        std::println(stderr, "Logger init failed: {}", r.error());
        return 1;
    }
    
    int ret = run_load_test(*cfg);
    
    Logger::shutdown();
    return ret;
}
