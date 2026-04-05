#pragma once

#include <boost/json.hpp>
#include <string>
#include <expected>
#include <cstdint>

namespace json = boost::json;

struct LoadTestConfig
{
    std::string host = "127.0.0.1";
    uint16_t port = 8080;
    size_t connections = 100;
    size_t duration_sec = 60;
    size_t rate_per_sec = 10;
    size_t payload_size = 256;
    size_t timeout_sec = 10;
    size_t warmup_sec = 5;
    size_t users_count = 10;
    std::string username_prefix = "loadtest_";
    std::string password_prefix = "loadpass_";
    std::string log_level = "debug";
    std::string log_file = "client.log";
    size_t log_max_size_mb = 100;
    bool log_console = true;
    bool interactive = false;
};

class LoadTestConfigParser
{
public:
    [[nodiscard]] static std::expected<LoadTestConfig, std::string> parse(int argc, char** argv);

private:
    [[nodiscard]] static std::expected<LoadTestConfig, std::string> loadFromFile(const std::string& filepath);
    [[nodiscard]] static std::expected<LoadTestConfig, std::string> parseJson(const json::value& jv);
};
