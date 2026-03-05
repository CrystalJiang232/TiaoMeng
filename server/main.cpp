#include "server.hpp"
#include "config.hpp"
#include "logger/logger.hpp"
#include "extern/CLI11/CLI11.hpp"

#include <print>
#include <cstring>
#include <charconv>
#include <optional>
#include <thread>
#include <vector>

int main(int argc, char** argv)
{
    CLI::App a;
    
    a.add_option("port");
    
    CLI11_PARSE(a, argc, argv);
    
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
        Server svr(config);
        
        if (!svr.start())
        {
            LOG_ERROR("Failed to start server");
            return 1;
        }
        
        LOG_INFO("Server running. Press Ctrl+C to stop.");
        
        // Wait for shutdown
        while (svr.is_running())
        {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
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
