#include "client/config.hpp"

#include "extern/CLI11/CLI11.hpp"
#include <fstream>
#include <sstream>
#include <format>
#include <print>

namespace {

template<std::unsigned_integral Ty>
std::expected<Ty, std::string> get_uint(const json::object& obj, std::string_view key,
                                        Ty min_val, Ty max_val, Ty default_val)
{
    auto it = obj.find(key);
    if (it == obj.end())
    {
        return default_val;
    }
    
    if (!it->value().is_int64() && !it->value().is_uint64())
    {
        return std::unexpected(std::format("'{}' must be an integer", key));
    }
    
    auto val = it->value().to_number<uint64_t>();
    if (val < static_cast<uint64_t>(min_val) || val > static_cast<uint64_t>(max_val))
    {
        return std::unexpected(std::format("'{}' must be between {} and {}",
                                           key, min_val, max_val));
    }
    
    return static_cast<Ty>(val);
}

std::string get_string(const json::object& obj, std::string_view key, std::string_view default_val)
{
    auto it = obj.find(key);
    if (it == obj.end() || !it->value().is_string())
    {
        return std::string(default_val);
    }
    
    return std::string(it->value().as_string());
}

bool get_bool(const json::object& obj, std::string_view key, bool default_val)
{
    auto it = obj.find(key);
    if (it == obj.end() || !it->value().is_bool())
    {
        return default_val;
    }
    return it->value().as_bool();
}

} // namespace

std::expected<LoadTestConfig, std::string> LoadTestConfigParser::parse(int argc, char** argv)
{
    LoadTestConfig cfg;
    std::string config_file;
    
    CLI::App app{"TiaoMeng Load Test Client"};
    
    auto opt_host = app.add_option("--host", cfg.host, "Server host address")
        ->default_val(cfg.host);
    auto opt_port = app.add_option("-p,--port", cfg.port, "Server port")
        ->default_val(cfg.port)
        ->check(CLI::Range(1, 65535));
    app.add_option("-c,--config", config_file, "Path to JSON config file");
    auto opt_conn = app.add_option("-n,--connections", cfg.connections, "Concurrent connections")
        ->default_val(cfg.connections)
        ->check(CLI::Range(1, 10000));
    auto opt_dur = app.add_option("-d,--duration", cfg.duration_sec, "Test duration in seconds")
        ->default_val(cfg.duration_sec)
        ->check(CLI::Range(1, 3600));
    auto opt_rate = app.add_option("-r,--rate", cfg.rate_per_sec, "Messages per second per connection")
        ->default_val(cfg.rate_per_sec)
        ->check(CLI::Range(1, 10000));
    auto opt_ps = app.add_option("-s,--payload-size", cfg.payload_size, "Broadcast payload size in bytes")
        ->default_val(cfg.payload_size)
        ->check(CLI::Range(1, 65536));
    auto opt_to = app.add_option("-t,--timeout", cfg.timeout_sec, "Operation timeout in seconds")
        ->default_val(cfg.timeout_sec)
        ->check(CLI::Range(1, 300));
    auto opt_wu = app.add_option("-w,--warmup", cfg.warmup_sec, "Warmup duration in seconds")
        ->default_val(cfg.warmup_sec)
        ->check(CLI::Range(0, 300));
    auto opt_uc = app.add_option("--users", cfg.users_count, "Test users to create")
        ->default_val(cfg.users_count)
        ->check(CLI::Range(1, 10000));
    auto opt_up = app.add_option("--user-prefix", cfg.username_prefix, "Prefix for test usernames")
        ->default_val(cfg.username_prefix);
    auto opt_pp = app.add_option("--pass-prefix", cfg.password_prefix, "Prefix for test passwords")
        ->default_val(cfg.password_prefix);
    auto opt_ll = app.add_option("--log-level", cfg.log_level, "Log level")
        ->default_val(cfg.log_level);
    auto opt_lf = app.add_option("--log-file", cfg.log_file, "Log file path")
        ->default_val(cfg.log_file);
    auto opt_lmc = app.add_option("--log-max-size", cfg.log_max_size_mb, "Max log size in MB")
        ->default_val(cfg.log_max_size_mb)
        ->check(CLI::Range(1, 10000));
    auto opt_lc = app.add_flag("--log-console", cfg.log_console, "Enable console logging")
        ->default_val(cfg.log_console);
    auto opt_interactive = app.add_flag("-i,--interactive", cfg.interactive, "Run in interactive mode")
        ->default_val(cfg.interactive);
    
    try
    {
        app.parse(argc, argv);
    }
    catch (const CLI::CallForHelp& e)
    {
        (void)app.exit(e);
        return std::unexpected("");
    }
    catch (const CLI::ParseError& e)
    {
        return std::unexpected(std::format("CLI parse error: {}", e.what()));
    }
    
    if (!config_file.empty())
    {
        auto base = loadFromFile(config_file);
        if (!base)
        {
            return std::unexpected(base.error());
        }
        
        cfg = *base;
        
        if (opt_host->count() > 0)
        {
            cfg.host = opt_host->as<std::string>();
        }
        if (opt_port->count() > 0)
        {
            cfg.port = opt_port->as<uint16_t>();
        }
        if (opt_conn->count() > 0)
        {
            cfg.connections = opt_conn->as<size_t>();
        }
        if (opt_dur->count() > 0)
        {
            cfg.duration_sec = opt_dur->as<size_t>();
        }
        if (opt_rate->count() > 0)
        {
            cfg.rate_per_sec = opt_rate->as<size_t>();
        }
        if (opt_ps->count() > 0)
        {
            cfg.payload_size = opt_ps->as<size_t>();
        }
        if (opt_to->count() > 0)
        {
            cfg.timeout_sec = opt_to->as<size_t>();
        }
        if (opt_wu->count() > 0)
        {
            cfg.warmup_sec = opt_wu->as<size_t>();
        }
        if (opt_uc->count() > 0)
        {
            cfg.users_count = opt_uc->as<size_t>();
        }
        if (opt_up->count() > 0)
        {
            cfg.username_prefix = opt_up->as<std::string>();
        }
        if (opt_pp->count() > 0)
        {
            cfg.password_prefix = opt_pp->as<std::string>();
        }
        if (opt_ll->count() > 0)
        {
            cfg.log_level = opt_ll->as<std::string>();
        }
        if (opt_lf->count() > 0)
        {
            cfg.log_file = opt_lf->as<std::string>();
        }
        if (opt_lmc->count() > 0)
        {
            cfg.log_max_size_mb = opt_lmc->as<size_t>();
        }
        if (opt_lc->count() > 0)
        {
            cfg.log_console = opt_lc->as<bool>();
        }
        if (opt_interactive->count() > 0)
        {
            cfg.interactive = opt_interactive->as<bool>();
        }
    }
    
    return cfg;
}

std::expected<LoadTestConfig, std::string> LoadTestConfigParser::loadFromFile(const std::string& filepath)
{
    std::ifstream file(filepath);
    if (!file.is_open())
    {
        return std::unexpected(std::format("Failed to open config file: {}", filepath));
    }
    
    std::stringstream buffer;
    buffer << file.rdbuf();
    
    json::value jv;
    try
    {
        jv = json::parse(buffer.str());
    }
    catch (const std::exception& e)
    {
        return std::unexpected(std::format("JSON parse error: {}", e.what()));
    }
    
    return parseJson(jv);
}

std::expected<LoadTestConfig, std::string> LoadTestConfigParser::parseJson(const json::value& jv)
{
    if (!jv.is_object())
    {
        return std::unexpected("Config root must be a JSON object");
    }
    
    const auto& root = jv.as_object();
    LoadTestConfig cfg;
    
    if (auto it = root.find("server"); it != root.end() && it->value().is_object())
    {
        const auto& srv = it->value().as_object();
        cfg.host = get_string(srv, "host", cfg.host);
        
        if (auto port = get_uint<uint16_t>(srv, "port", 1, 65535, cfg.port); port)
        {
            cfg.port = *port;
        }
        else
        {
            return std::unexpected(port.error());
        }
    }
    
    if (auto it = root.find("load"); it != root.end() && it->value().is_object())
    {
        const auto& ld = it->value().as_object();
        
        if (auto v = get_uint<size_t>(ld, "connections", 1, 10000, cfg.connections); v)
        {
            cfg.connections = *v;
        }
        else
        {
            return std::unexpected(v.error());
        }
        
        if (auto v = get_uint<size_t>(ld, "duration_sec", 1, 3600, cfg.duration_sec); v)
        {
            cfg.duration_sec = *v;
        }
        else
        {
            return std::unexpected(v.error());
        }
        
        if (auto v = get_uint<size_t>(ld, "rate_per_sec", 1, 10000, cfg.rate_per_sec); v)
        {
            cfg.rate_per_sec = *v;
        }
        else
        {
            return std::unexpected(v.error());
        }
        
        if (auto v = get_uint<size_t>(ld, "payload_size", 1, 65536, cfg.payload_size); v)
        {
            cfg.payload_size = *v;
        }
        else
        {
            return std::unexpected(v.error());
        }
        
        if (auto v = get_uint<size_t>(ld, "timeout_sec", 1, 300, cfg.timeout_sec); v)
        {
            cfg.timeout_sec = *v;
        }
        else
        {
            return std::unexpected(v.error());
        }
        
        if (auto v = get_uint<size_t>(ld, "warmup_sec", 0, 300, cfg.warmup_sec); v)
        {
            cfg.warmup_sec = *v;
        }
        else
        {
            return std::unexpected(v.error());
        }
    }
    
    if (auto it = root.find("users"); it != root.end() && it->value().is_object())
    {
        const auto& usr = it->value().as_object();
        
        if (auto v = get_uint<size_t>(usr, "count", 1, 10000, cfg.users_count); v)
        {
            cfg.users_count = *v;
        }
        else
        {
            return std::unexpected(v.error());
        }
        
        cfg.username_prefix = get_string(usr, "username_prefix", cfg.username_prefix);
        cfg.password_prefix = get_string(usr, "password_prefix", cfg.password_prefix);
    }
    
    if (auto it = root.find("logging"); it != root.end() && it->value().is_object())
    {
        const auto& lg = it->value().as_object();
        cfg.log_level = get_string(lg, "level", cfg.log_level);
        cfg.log_file = get_string(lg, "file", cfg.log_file);
        if (auto v = get_uint<size_t>(lg, "max_size_mb", 1, 10000, cfg.log_max_size_mb); v)
        {
            cfg.log_max_size_mb = *v;
        }
        else
        {
            return std::unexpected(v.error());
        }
        cfg.log_console = get_bool(lg, "enable_console", cfg.log_console);
    }
    
    return cfg;
}
