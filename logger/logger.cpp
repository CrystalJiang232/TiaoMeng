#include "logger.hpp"

#include <algorithm>
#include <cctype>

Logger::State& Logger::instance()
{
    static State s;
    return s;
}

Logger::Level Logger::parse_level(std::string_view lvl)
{
    std::string lower;
    lower.reserve(lvl.size());
    std::ranges::transform(lvl, std::back_inserter(lower),
                           [](unsigned char c){ return std::tolower(c); });
    if (lower == "debug") return Level::Debug;
    if (lower == "warn" || lower == "warning") return Level::Warn;
    if (lower == "error") return Level::Error;
    return Level::Info;
}

std::string Logger::level_str(Level l)
{
    switch (l)
    {
        case Level::Debug: return "DEBUG";
        case Level::Warn:  return "WARN";
        case Level::Error: return "ERROR";
        default:           return "INFO";
    }
}

std::string Logger::timestamp()
{
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()) % 1000;
    std::tm tm;
    localtime_r(&time, &tm);
    return std::format("{:04d}-{:02d}-{:02d} {:02d}:{:02d}:{:02d}.{:03d}",
                       tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                       tm.tm_hour, tm.tm_min, tm.tm_sec, ms.count());
}

std::expected<void, std::string> Logger::init(std::string_view level,
                                               std::string_view file,
                                               size_t max_size_mb,
                                               bool enable_console)
{
    State& s = instance();
    s.lvl = parse_level(level);
    s.console = enable_console;
    s.max_size = max_size_mb * 1024 * 1024;
    s.filename = std::string(file);
    if (!s.filename.empty())
    {
        s.file.open(s.filename, std::ios::app);
        if (!s.file.is_open())
        {
            return std::unexpected("Failed to open log file: " + s.filename);
        }
    }
    return {};
}

void Logger::shutdown()
{
    State& s = instance();
    std::lock_guard<std::mutex> lock(s.mtx);
    s.file.close();
}

void Logger::log_msg(Level l, const std::string& msg)
{
    State& s = instance();
    std::lock_guard<std::mutex> lock(s.mtx);
    std::string line = std::format("[{}] [{}] {}", timestamp(), level_str(l), msg);
    if (s.console)
    {
        auto& out = (l == Level::Error) ? std::cerr : std::cout;
        out << line << "\n";
    }
    if (s.file.is_open())
    {
        s.file << line << "\n";
        s.file.flush();
    }
}
