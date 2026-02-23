#include <catch2/catch_test_macros.hpp>

#include "config.hpp"

#include <fstream>
#include <filesystem>

namespace fs = std::filesystem;

TEST_CASE("Config::load_defaults returns valid config with defaults")
{
    auto cfg = Config::load_defaults();
    
    CHECK(cfg.server().port == 8080);
    CHECK(cfg.server().bind_address == "0.0.0.0");
    CHECK(cfg.server().max_connections == 1000);
    CHECK(cfg.server().max_message_size == 1024 * 1024);
    CHECK(cfg.security().max_failures_before_disconnect == 5);
    CHECK(cfg.logging().level == "info");
    CHECK(cfg.logging().enable_console == true);
}

TEST_CASE("Config::load parses valid JSON file")
{
    const char* test_file = "/tmp/test_config_valid.json";
    
    std::ofstream f(test_file);
    f << R"({
        "server": {
            "port": 7777,
            "bind_address": "127.0.0.1",
            "max_connections": 500,
            "max_message_size": 2048
        },
        "security": {
            "max_failures_before_disconnect": 3,
            "session_timeout_sec": 1800,
            "key_rotation_interval_sec": 43200,
            "require_client_auth": true
        },
        "timeouts": {
            "handshake_timeout_sec": 15,
            "read_timeout_sec": 60,
            "write_timeout_sec": 10
        },
        "logging": {
            "level": "debug",
            "file": "/var/log/test.log",
            "max_size_mb": 50,
            "enable_console": false
        }
    })";
    f.close();
    
    auto result = Config::load(test_file);
    
    REQUIRE(result.has_value());
    CHECK(result->server().port == 7777);
    CHECK(result->server().bind_address == "127.0.0.1");
    CHECK(result->server().max_connections == 500);
    CHECK(result->server().max_message_size == 2048);
    CHECK(result->security().max_failures_before_disconnect == 3);
    CHECK(result->security().require_client_auth == true);
    CHECK(result->logging().level == "debug");
    CHECK(result->logging().file == "/var/log/test.log");
    CHECK(result->logging().enable_console == false);
    
    fs::remove(test_file);
}

TEST_CASE("Config::load returns error for missing file")
{
    auto result = Config::load("/nonexistent/path/config.json");
    
    REQUIRE(!result.has_value());
}

TEST_CASE("Config::load returns error for invalid JSON")
{
    const char* test_file = "/tmp/test_config_invalid.json";
    
    std::ofstream f(test_file);
    f << "{ invalid json }";
    f.close();
    
    auto result = Config::load(test_file);
    
    REQUIRE(!result.has_value());
    
    fs::remove(test_file);
}

TEST_CASE("Config::load returns error for port out of range")
{
    const char* test_file = "/tmp/test_config_bad_port.json";
    
    std::ofstream f(test_file);
    f << R"({"server": {"port": 99999}})";
    f.close();
    
    auto result = Config::load(test_file);
    
    REQUIRE(!result.has_value());
    
    fs::remove(test_file);
}

TEST_CASE("Config::load_or_defaults uses defaults when file missing")
{
    auto cfg = Config::load_or_defaults("/nonexistent/config.json");
    
    CHECK(cfg.server().port == 8080);
    CHECK(cfg.logging().level == "info");
}

TEST_CASE("Config::load applies defaults for missing sections")
{
    const char* test_file = "/tmp/test_config_partial.json";
    
    std::ofstream f(test_file);
    f << R"({"server": {"port": 6000}})";
    f.close();
    
    auto result = Config::load(test_file);
    
    REQUIRE(result.has_value());
    CHECK(result->server().port == 6000);
    CHECK(result->server().bind_address == "0.0.0.0");
    CHECK(result->security().max_failures_before_disconnect == 5);
    CHECK(result->logging().level == "info");
    
    fs::remove(test_file);
}

TEST_CASE("Config::load handles empty JSON object")
{
    const char* test_file = "/tmp/test_config_empty.json";
    
    std::ofstream f(test_file);
    f << "{}";
    f.close();
    
    auto result = Config::load(test_file);
    
    REQUIRE(result.has_value());
    CHECK(result->server().port == 8080);
    CHECK(result->security().max_failures_before_disconnect == 5);
    
    fs::remove(test_file);
}
