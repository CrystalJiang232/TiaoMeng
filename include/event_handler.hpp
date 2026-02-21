#pragma once

#include <boost/json.hpp>
#include <memory>

class Connection;

namespace EventHandler
{
    // Action handlers - implementation in event_handler.cpp
    // First parameter must be named 'self' per requirement
    
    void handle_auth(std::shared_ptr<Connection> self, const boost::json::object& request);
    void handle_command(std::shared_ptr<Connection> self, const boost::json::object& request);
    void handle_broadcast(std::shared_ptr<Connection> self, const boost::json::object& request);
    void handle_logout(std::shared_ptr<Connection> self);
    
} // namespace EventHandler
