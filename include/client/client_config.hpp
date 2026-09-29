#pragma once

#include <string>
#include <cstdint>
#include <chrono>
#include <functional>
#include <boost/json.hpp>

namespace json = boost::json;

struct ClientConfig
{
    // Network
    std::string          host = "127.0.0.1";
    uint16_t             port = 8080;
    std::chrono::seconds connect_timeout{10};
    std::chrono::seconds handshake_timeout{30};
    std::chrono::seconds request_timeout{30};

    // Callbacks
    std::function<void(const json::object&)> on_notification;
    std::function<void(int)>                 on_state_change;
};
