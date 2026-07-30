#include "client/config.hpp"
#include "client/metrics.hpp"
#include "client/client.hpp"
#include "logger/logger.hpp"

#include <boost/asio.hpp>
#include <thread>
#include <print>
#include <cstdlib>
#include <format>
#include <deque>
#include <exception>

namespace net = boost::asio;

namespace
{

constexpr auto shutdown_grace = std::chrono::seconds(5);
constexpr size_t max_reported_errors = 8;

struct LoadRunSummary
{
    size_t completed = 0;
    size_t failed = 0;
    size_t cancelled = 0;
    size_t timed_out = 0;
    std::vector<std::string> errors;

    [[nodiscard]] size_t total() const
    {
        return completed + failed + cancelled + timed_out;
    }

    [[nodiscard]] bool succeeded(size_t expected_clients) const
    {
        return total() == expected_clients
            && failed == 0 && cancelled == 0 && timed_out == 0;
    }
};

struct CompletionEvent
{
    size_t client_index = 0;
    ClientRunResult result;
};

using ControlExecutor = net::strand<net::io_context::executor_type>;

struct SupervisorState
{
    SupervisorState(ControlExecutor executor, size_t connection_count)
        : control(std::move(executor))
        , wake_timer(control)
        , clients(connection_count)
        , reported(connection_count, false)
    {
    }

    void enqueue(CompletionEvent event)
    {
        completions.push_back(std::move(event));
        wake_timer.cancel_one();
    }

    void record(CompletionEvent event)
    {
        if (reported[event.client_index])
        {
            return;
        }

        reported[event.client_index] = true;
        ++reported_count;
        switch (event.result.status)
        {
        case ClientRunResult::Status::Completed:
            ++summary.completed;
            break;
        case ClientRunResult::Status::Failed:
            ++summary.failed;
            break;
        case ClientRunResult::Status::Cancelled:
            ++summary.cancelled;
            break;
        }

        if (!event.result.error.empty() && summary.errors.size() < max_reported_errors)
        {
            summary.errors.push_back(std::format(
                "client {}: {}", event.client_index, event.result.error));
        }
    }

    void drain()
    {
        while (!completions.empty())
        {
            auto event = std::move(completions.front());
            completions.pop_front();
            record(std::move(event));
        }
    }

    void cancel_unreported()
    {
        for (size_t i = 0; i < clients.size(); ++i)
        {
            if (!reported[i] && clients[i])
            {
                clients[i]->request_stop();
            }
        }
    }

    void classify_timeouts()
    {
        for (size_t i = 0; i < reported.size(); ++i)
        {
            if (reported[i])
            {
                continue;
            }

            reported[i] = true;
            ++reported_count;
            ++summary.timed_out;
            if (summary.errors.size() < max_reported_errors)
            {
                summary.errors.push_back(std::format(
                    "client {}: did not stop within cancellation grace", i));
            }
        }
    }

    ControlExecutor control;
    net::steady_timer wake_timer;
    std::vector<std::shared_ptr<Client>> clients;
    std::vector<bool> reported;
    std::deque<CompletionEvent> completions;
    LoadRunSummary summary;
    size_t reported_count = 0;
};

std::string exception_message(const std::exception_ptr& exception)
{
    try
    {
        std::rethrow_exception(exception);
    }
    catch (const std::exception& e)
    {
        return e.what();
    }
    catch (...)
    {
        return "Unknown root client exception";
    }
}

net::awaitable<LoadRunSummary> supervise_load_test(
    const LoadTestConfig& cfg, net::io_context& io, MetricsCollector& metrics,
    ControlExecutor control)
{
    auto state = std::make_shared<SupervisorState>(control, cfg.connections);
    auto start = std::chrono::steady_clock::now();
    LoadTestWindow window{
        .warmup_end = start + std::chrono::seconds(cfg.warmup_sec),
        .deadline = start + std::chrono::seconds(cfg.warmup_sec + cfg.duration_sec)};
    auto global_deadline = window.deadline + std::chrono::seconds(cfg.timeout_sec);

    for (size_t i = 0; i < cfg.connections; ++i)
    {
        ClientConfig client_cfg;
        client_cfg.host = cfg.host;
        client_cfg.port = cfg.port;
        client_cfg.connect_timeout = std::chrono::seconds(cfg.timeout_sec);
        client_cfg.handshake_timeout = std::chrono::seconds(cfg.timeout_sec);
        client_cfg.request_timeout = std::chrono::seconds(cfg.timeout_sec);
        client_cfg.rate_per_sec = cfg.rate_per_sec;
        client_cfg.payload_size = cfg.payload_size;
        client_cfg.username_prefix = cfg.username_prefix;
        client_cfg.password_prefix = cfg.password_prefix;
        client_cfg.user_index = i % cfg.users_count;

        try
        {
            auto client = std::make_shared<Client>(client_cfg, io);
            state->clients[i] = client;
            net::co_spawn(
                client->get_executor(),
                client->run(window, metrics),
                [state, i](std::exception_ptr exception, ClientRunResult result)
                {
                    if (exception)
                    {
                        result = ClientRunResult{
                            ClientRunResult::Status::Failed,
                            exception_message(exception)};
                    }
                    net::post(state->control,
                        [state, event = CompletionEvent{i, std::move(result)}]() mutable
                        {
                            state->enqueue(std::move(event));
                        });
                });
        }
        catch (const std::exception& e)
        {
            state->record(CompletionEvent{
                i, ClientRunResult{ClientRunResult::Status::Failed, e.what()}});
        }
        catch (...)
        {
            state->record(CompletionEvent{
                i, ClientRunResult{ClientRunResult::Status::Failed, "Failed to spawn client"}});
        }
    }

    while (state->reported_count != cfg.connections)
    {
        state->drain();
        if (state->reported_count == cfg.connections)
        {
            co_return state->summary;
        }

        state->wake_timer.expires_at(global_deadline);
        auto [ec] = co_await state->wake_timer.async_wait(net::as_tuple(net::use_awaitable));
        if (!ec)
        {
            break;
        }
    }

    state->drain();
    if (state->reported_count == cfg.connections)
    {
        co_return state->summary;
    }

    LOG_INFO("Global load-test deadline reached; cancelling remaining clients");
    state->cancel_unreported();
    auto grace_deadline = std::chrono::steady_clock::now() + shutdown_grace;

    while (state->reported_count != cfg.connections)
    {
        state->drain();
        if (state->reported_count == cfg.connections)
        {
            co_return state->summary;
        }

        state->wake_timer.expires_at(grace_deadline);
        auto [ec] = co_await state->wake_timer.async_wait(net::as_tuple(net::use_awaitable));
        if (!ec)
        {
            break;
        }
    }

    state->drain();
    state->classify_timeouts();
    co_return state->summary;
}

} // namespace

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

    MetricsCollector mts;
    LoadRunSummary summary;
    bool supervisor_failed = false;
    try
    {
        net::io_context io(static_cast<int>(hw_threads));
        auto work_guard = net::make_work_guard(io);
        auto control = net::make_strand(io);
        auto result = net::co_spawn(
            control, supervise_load_test(cfg, io, mts, control), net::use_future);

        std::vector<std::jthread> pool;
        try
        {
            pool.reserve(hw_threads);
            for (size_t t = 0; t < hw_threads; ++t)
            {
                pool.emplace_back([&io]() { io.run(); });
            }
        }
        catch (const std::exception& e)
        {
            supervisor_failed = true;
            std::println(stderr, "Failed to start load-test workers: {}", e.what());
        }
        catch (...)
        {
            supervisor_failed = true;
            std::println(stderr, "Failed to start load-test workers");
        }

        if (!supervisor_failed)
        {
            try
            {
                summary = result.get();
            }
            catch (const std::exception& e)
            {
                supervisor_failed = true;
                std::println(stderr, "Load-test supervisor failed: {}", e.what());
            }
            catch (...)
            {
                supervisor_failed = true;
                std::println(stderr, "Load-test supervisor failed with an unknown exception");
            }
        }

        work_guard.reset();
        if (supervisor_failed || summary.timed_out != 0)
        {
            io.stop();
        }

        for (auto& th : pool)
        {
            th.join();
        }
    }
    catch (const std::exception& e)
    {
        supervisor_failed = true;
        std::println(stderr, "Failed to initialize load-test runtime: {}", e.what());
    }
    catch (...)
    {
        supervisor_failed = true;
        std::println(stderr, "Failed to initialize load-test runtime");
    }

    LOG_DEBUG("All worker threads joined");
    
    std::println("OK: {}  FAIL: {}  RPS: {:.2f}",
                 mts.ok_count(), mts.fail_count(),
                 static_cast<double>(mts.ok_count()) / static_cast<double>(cfg.duration_sec));
    std::println("CLIENTS: completed={} failed={} cancelled={} timed_out={}",
                 summary.completed, summary.failed, summary.cancelled, summary.timed_out);
    if (!supervisor_failed && summary.total() != cfg.connections)
    {
        std::println(stderr, "Client accounting mismatch: expected {}, recorded {}",
                     cfg.connections, summary.total());
    }
    for (const auto& error : summary.errors)
    {
        std::println(stderr, "{}", error);
    }
    
    if (auto r = teardown_test_users(cfg); !r)
    {
        std::println(stderr, "Teardown failed: {}", r.error());
    }
    
    return !supervisor_failed && summary.succeeded(cfg.connections) ? 0 : 1;
}

int run_interactive(const LoadTestConfig& cfg)
{
    ClientConfig client_cfg;
    client_cfg.host = cfg.host;
    client_cfg.port = cfg.port;
    client_cfg.connect_timeout = std::chrono::seconds(cfg.timeout_sec);
    client_cfg.handshake_timeout = std::chrono::seconds(cfg.timeout_sec);
    client_cfg.request_timeout = std::chrono::seconds(cfg.timeout_sec);
    
    Client client(client_cfg);
    client.run_interactive();
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
