#include "config.hpp"

#include <fstream>
#include <sstream>
#include <format>

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

std::expected<Config, std::string> Config::load(const std::string& filepath, std::optional<uint16_t> cli_port)
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
    auto result = parse(jv);
    if (result && cli_port.has_value())
    {
        result->srv.port = *cli_port;
    }
    return result;
}

Config Config::load_defaults(std::optional<uint16_t> cli_port)
{
    Config cfg{};
    if (cli_port.has_value())
    {
        cfg.srv.port = *cli_port;
    }
    return cfg;
}

Config Config::load_or_defaults(const std::string& filepath, std::optional<uint16_t> cli_port)
{
    auto result = load(filepath, cli_port);
    if (result)
    {
        return *result;
    }
    return load_defaults(cli_port);
}

std::expected<Config, std::string> Config::parse(const json::value& jv)
{
    if (!jv.is_object())
    {
        return std::unexpected("Config root must be a JSON object");
    }
    const auto& root = jv.as_object();
    Config config;
    if (auto it = root.find("server"); it != root.end() && it->value().is_object())
    {
        const auto& srv = it->value().as_object();
        if (auto port = get_uint<uint16_t>(srv, "port", 1, 65535, 8080); port)
        {
            config.srv.port = *port;
        }
        else
        {
            return std::unexpected(port.error());
        }
        config.srv.bind_address = get_string(srv, "bind_address", "0.0.0.0");
        if (auto max_conn = get_uint<size_t>(srv, "max_connections", 1, 100000, 1000); max_conn)
        {
            config.srv.max_connections = *max_conn;
        }
        else
        {
            return std::unexpected(max_conn.error());
        }
        if (auto max_msg = get_uint<size_t>(srv, "max_message_size", 1024, 100 * 1024 * 1024, 1024 * 1024); max_msg)
        {
            config.srv.max_message_size = *max_msg;
        }
        else
        {
            return std::unexpected(max_msg.error());
        }
    }
    if (auto it = root.find("security"); it != root.end() && it->value().is_object())
    {
        const auto& sec = it->value().as_object();
        if (auto max_fail = get_uint<size_t>(sec, "max_failures_before_disconnect", 1, 100, 5); max_fail)
        {
            config.sec.max_failures_before_disconnect = *max_fail;
        }
        else
        {
            return std::unexpected(max_fail.error());
        }
        if (auto session_to = get_uint<uint64_t>(sec, "session_timeout_sec", 10, 86400 * 30, 3600); session_to)
        {
            config.sec.session_timeout = std::chrono::seconds(*session_to);
        }
        else
        {
            return std::unexpected(session_to.error());
        }
        if (auto key_rot = get_uint<uint64_t>(sec, "key_rotation_interval_sec", 60, 86400 * 365, 86400); key_rot)
        {
            config.sec.key_rotation_interval = std::chrono::seconds(*key_rot);
        }
        else
        {
            return std::unexpected(key_rot.error());
        }
        config.sec.require_client_auth = get_bool(sec, "require_client_auth", false);
    }
    if (auto it = root.find("timeouts"); it != root.end() && it->value().is_object())
    {
        const auto& to = it->value().as_object();
        if (auto hs_to = get_uint<uint64_t>(to, "handshake_timeout_sec", 1, 300, 30); hs_to)
        {
            config.to.handshake_timeout = std::chrono::seconds(*hs_to);
        }
        else
        {
            return std::unexpected(hs_to.error());
        }
        if (auto read_to = get_uint<uint64_t>(to, "read_timeout_sec", 1, 3600, 300); read_to)
        {
            config.to.read_timeout = std::chrono::seconds(*read_to);
        }
        else
        {
            return std::unexpected(read_to.error());
        }
        if (auto write_to = get_uint<uint64_t>(to, "write_timeout_sec", 1, 300, 30); write_to)
        {
            config.to.write_timeout = std::chrono::seconds(*write_to);
        }
        else
        {
            return std::unexpected(write_to.error());
        }
    }
    if (auto it = root.find("logging"); it != root.end() && it->value().is_object())
    {
        const auto& log = it->value().as_object();
        config.log.level = get_string(log, "level", "info");
        config.log.file = get_string(log, "file", "");
        if (auto max_size = get_uint<size_t>(log, "max_size_mb", 1, 10000, 100); max_size)
        {
            config.log.max_size_mb = *max_size;
        }
        else
        {
            return std::unexpected(max_size.error());
        }
        config.log.enable_console = get_bool(log, "enable_console", true);
    }
    return config;
}
