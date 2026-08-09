#include "server.hpp"
#include "config.hpp"
#include "logger/logger.hpp"
#include "extern/CLI11/CLI11.hpp"

#include <print>
#include <filesystem>
#include <thread>

int main(int argc, char** argv)
{
    CLI::App a;

    std::string config_file;
    a.add_option("config", config_file, "Path to server config JSON file")->required();
    // CLI parse errors (including a missing required argument) print error + usage, then exit non-zero.
    a.failure_message(CLI::FailureMessage::help);

    CLI11_PARSE(a, argc, argv);

    auto config = Config::load(config_file);
    if (!config)
    {
        std::println(stderr, "Config error: {}", config.error());
        std::println(stderr, "{}", a.get_usage());
        return 1;
    }

    if (!std::filesystem::exists(config->auth().db_path))
    {
        std::println(stderr, "Auth database file not found: {}", config->auth().db_path);
        return 1;
    }

    auto log_cfg = config->logging();
    if (auto result = Logger::init(log_cfg.level, log_cfg.file, log_cfg.max_size_mb, log_cfg.enable_console); !result)
    {
        std::println(stderr, "Failed to initialize logger: {}", result.error());
        return 1;
    }

    try
    {
        Server svr(*config);

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
