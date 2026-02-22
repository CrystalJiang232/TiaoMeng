#include "server.hpp"
#include "config.hpp"
#include "logger.hpp"

#include <print>
#include <cstring>
#include <charconv>

int main(int argc, char** argv)
{
    auto config = Config::load_or_defaults("server_config.json");
    
    if (argc > 1)
    {
        uint16_t cli_port = 0;
        auto [ptr, ec] = std::from_chars(argv[1], argv[1] + strlen(argv[1]), cli_port);
        if (ec == std::errc{} && cli_port > 0)
        {
            config.set_port(cli_port);
        }
    }

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
