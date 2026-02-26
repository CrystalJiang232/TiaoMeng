#include "server.hpp"
#include "config.hpp"
#include "logger/logger.hpp"

#include <print>
#include <cstring>
#include <charconv>
#include <optional>
#include <thread>
#include <vector>

int main(int argc, char** argv)
{
    std::optional<uint16_t> cli_port;
    if (argc > 1)
    {
        uint16_t port = 0;
        if (auto [ptr, ec] = std::from_chars(argv[1], argv[1] + strlen(argv[1]), port); ec == std::errc{} && port > 0)
        {
            cli_port = port;
        }
    }
    
    auto config = Config::load_or_defaults("server_config.json", cli_port);

    auto log_cfg = config.logging();
    if (auto result = Logger::init(log_cfg.level, log_cfg.file, log_cfg.max_size_mb, log_cfg.enable_console);
        !result)
    {
        std::println(stderr, "Failed to initialize logger: {}", result.error());
        return 1;
    }

    try
    {
        net::io_context ic;
        Server svr(ic, config);

        LOG_INFO("Server starting on {}:{}", config.server().bind_address, config.server().port);
        
        svr.start();
        
        size_t thread_count = std::thread::hardware_concurrency();
        std::vector<std::jthread> threads;
        threads.reserve(thread_count - 1);
        
        for (size_t i = 1; i < thread_count; ++i)
        {
            threads.emplace_back([&ic] { ic.run(); });
        }
        
        ic.run();
    }
    catch (const std::exception& e)
    {
        LOG_ERROR("Fatal: {}", e.what());
        Logger::shutdown();
        return 1;
    }

    LOG_INFO("Server exiting...");
    Logger::shutdown();
    return 0;
}
