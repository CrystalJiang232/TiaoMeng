#include "config.hpp"

#include <fstream>
#include <sstream>
#include <format>

namespace
{

    template <std::unsigned_integral Ty>
    std::expected<Ty, std::string> get_uint(const json::object& obj, std::string_view key, Ty min_val, Ty max_val,
                                            Ty default_val)
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
        if (it->value().is_int64() && it->value().get_int64() < 0)
        {
            return std::unexpected(std::format("'{}' cannot be negative", key));
        }
        auto val = it->value().to_number<uint64_t>();
        if (val < static_cast<uint64_t>(min_val) || val > static_cast<uint64_t>(max_val))
        {
            return std::unexpected(std::format("'{}' must be between {} and {}", key, min_val, max_val));
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
    Config      config;

    // New layout: all sections are nested under the top-level "server" object:
    //   server.connection / server.security / server.timeouts / server.logging.
    // Missing server sub-sections fall back to defaults (existing lenient behavior);
    // the top-level "auth" section is required and must provide a non-empty db_path.
    const json::object* srv_section = nullptr;
    const json::object* sec_section = nullptr;
    const json::object* to_section  = nullptr;
    const json::object* log_section = nullptr;
    const json::object* auth_section = nullptr;
    if (auto it = root.find("server"); it != root.end() && it->value().is_object())
    {
        const auto& server_obj = it->value().as_object();
        if (auto sub = server_obj.find("connection"); sub != server_obj.end() && sub->value().is_object())
        {
            srv_section = &sub->value().as_object();
        }
        if (auto sub = server_obj.find("security"); sub != server_obj.end() && sub->value().is_object())
        {
            sec_section = &sub->value().as_object();
        }
        if (auto sub = server_obj.find("timeouts"); sub != server_obj.end() && sub->value().is_object())
        {
            to_section = &sub->value().as_object();
        }
        if (auto sub = server_obj.find("logging"); sub != server_obj.end() && sub->value().is_object())
        {
            log_section = &sub->value().as_object();
        }
    }
    if (auto it = root.find("auth"); it != root.end() && it->value().is_object())
    {
        auth_section = &it->value().as_object();
    }
    if (srv_section)
    {
        const auto& srv = *srv_section;
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
        if (auto cpu_t = get_uint<size_t>(srv, "cpu_threads", 0, 256, 0); cpu_t)
        {
            config.srv.cpu_threads = *cpu_t;
        }
        else
        {
            return std::unexpected(cpu_t.error());
        }
        if (auto io_t = get_uint<size_t>(srv, "io_threads", 1, 64, 4); io_t)
        {
            config.srv.io_threads = *io_t;
        }
        else
        {
            return std::unexpected(io_t.error());
        }
    }
    if (sec_section)
    {
        const auto& sec = *sec_section;
        if (auto max_fail = get_uint<size_t>(sec, "max_failures_before_disconnect", 1, 100, 5); max_fail)
        {
            config.sec.max_failures_before_disconnect = *max_fail;
        }
        else
        {
            return std::unexpected(max_fail.error());
        }
        if (auto key_lf = get_uint<uint64_t>(sec, "key_lifetime_sec", 30, 86400, 45); key_lf)
        {
            config.sec.key_lifetime = std::chrono::seconds(*key_lf);
        }
        else
        {
            return std::unexpected(key_lf.error());
        }
        config.sec.require_client_auth = get_bool(sec, "require_client_auth", true);
    }
    if (to_section)
    {
        const auto& to = *to_section;
        if (auto hs_to = get_uint<uint64_t>(to, "handshake_timeout_sec", 1, 300, 30); hs_to)
        {
            config.to.handshake_timeout = std::chrono::seconds(*hs_to);
        }
        else
        {
            return std::unexpected(hs_to.error());
        }
        if (auto read_to = get_uint<uint64_t>(to, "read_timeout_sec", 1, 3600, 30); read_to)
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
    if (log_section)
    {
        const auto& log = *log_section;
        config.log.level = get_string(log, "level", "info");
        config.log.file  = get_string(log, "file", "");
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
    if (auth_section)
    {
        const auto& auth = *auth_section;
        config.auth_cfg.db_path = get_string(auth, "db_path", config.auth_cfg.db_path);
    }
    if (config.auth_cfg.db_path.empty())
    {
        return std::unexpected("Config missing required 'auth.db_path'");
    }
    return config;
}
