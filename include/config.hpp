#pragma once

#include <boost/json.hpp>
#include <string>
#include <expected>
#include <optional>
#include <cstdint>
#include <chrono>

namespace json = boost::json;

/**
 * Server configuration loaded from JSON file.
 * Load-once at startup, immutable thereafter.
 */
class Config
{
public:
    struct ServerCfg
    {
        uint16_t    port             = 8080;
        std::string bind_address     = "0.0.0.0";
        size_t      max_connections  = 1000;
        size_t      max_message_size = 1024 * 1024;
        size_t      io_threads       = 4;
        size_t      cpu_threads      = 0;
    };

    struct SecurityCfg
    {
        size_t               max_failures_before_disconnect = 5;
        std::chrono::seconds key_lifetime{350};
        bool                 require_client_auth = false;
    };

    struct TimeoutsCfg
    {
        std::chrono::seconds handshake_timeout{30};
        std::chrono::seconds read_timeout{300};
        std::chrono::seconds write_timeout{30};
    };

    struct LoggingCfg
    {
        std::string level          = "info";
        std::string file           = "";
        size_t      max_size_mb    = 100;
        bool        enable_console = true;
    };

    struct AuthCfg
    {
        // Empty by default: the config file must provide the path explicitly.
        std::string db_path;
    };

    [[nodiscard]]
    static std::expected<Config, std::string> load(const std::string&      filepath,
                                                   std::optional<uint16_t> cli_port = std::nullopt);
    [[nodiscard]]
    static Config load_defaults(std::optional<uint16_t> cli_port = std::nullopt);
    [[nodiscard]]
    static Config load_or_defaults(const std::string& filepath, std::optional<uint16_t> cli_port = std::nullopt);

    [[nodiscard]]
    const ServerCfg& server() const
    {
        return srv;
    }

    [[nodiscard]]
    const SecurityCfg& security() const
    {
        return sec;
    }

    [[nodiscard]]
    const TimeoutsCfg& timeouts() const
    {
        return to;
    }

    [[nodiscard]]
    const LoggingCfg& logging() const
    {
        return log;
    }

    [[nodiscard]]
    const AuthCfg& auth() const
    {
        return auth_cfg;
    }

private:
    ServerCfg   srv;
    SecurityCfg sec;
    TimeoutsCfg to;
    LoggingCfg  log;
    AuthCfg     auth_cfg;

    [[nodiscard]]
    static std::expected<Config, std::string> parse(const json::value& jv);
};
