#pragma once

#include <fstream>
#include <iostream>
#include <mutex>
#include <string>
#include <string_view>
#include <expected>
#include <format>
#include <chrono>
#include <ctime>

class Logger
{
public:
    enum class Level { Debug, Info, Warn, Error };

    [[nodiscard]] static std::expected<void, std::string> init(std::string_view level,
                                                                std::string_view file,
                                                                size_t max_size_mb,
                                                                bool enable_console);
    static void shutdown();

    template<typename... Args>
    static void debug(std::format_string<Args...> fmt, Args&&... args)
    {
        if (instance().lvl <= Level::Debug)
        {
            log_msg(Level::Debug, std::format(fmt, std::forward<Args>(args)...));
        }
    }

    template<typename... Args>
    static void info(std::format_string<Args...> fmt, Args&&... args)
    {
        if (instance().lvl <= Level::Info)
        {
            log_msg(Level::Info, std::format(fmt, std::forward<Args>(args)...));
        }
    }

    template<typename... Args>
    static void warn(std::format_string<Args...> fmt, Args&&... args)
    {
        if (instance().lvl <= Level::Warn)
        {
            log_msg(Level::Warn, std::format(fmt, std::forward<Args>(args)...));
        }
    }

    template<typename... Args>
    static void error(std::format_string<Args...> fmt, Args&&... args)
    {
        if (instance().lvl <= Level::Error)
        {
            log_msg(Level::Error, std::format(fmt, std::forward<Args>(args)...));
        }
    }

private:
    struct State
    {
        Level lvl = Level::Info;
        std::ofstream file;
        bool console = true;
        std::mutex mtx;
        size_t max_size = 100 * 1024 * 1024;
        std::string filename;
    };

    static State& instance();
    static Level parse_level(std::string_view lvl);
    static std::string level_str(Level l);
    static std::string timestamp();
    static void log_msg(Level l, const std::string& msg);
};

#define LOG_DEBUG(...) Logger::debug(__VA_ARGS__)
#define LOG_INFO(...)  Logger::info(__VA_ARGS__)
#define LOG_WARN(...)  Logger::warn(__VA_ARGS__)
#define LOG_ERROR(...) Logger::error(__VA_ARGS__)
