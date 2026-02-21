#pragma once

#include <boost/json.hpp>
#include <memory>
#include <unordered_map>
#include <functional>

class Connection;

class EventHandler
{
public:
    using Handler = std::function<void(std::shared_ptr<Connection>, const boost::json::object&)>;
    
    EventHandler();
    
    void route(std::shared_ptr<Connection> conn, const boost::json::object& request);
    
    static void handle_auth(std::shared_ptr<Connection> self, const boost::json::object& request);
    static void handle_command(std::shared_ptr<Connection> self, const boost::json::object& request);
    static void handle_broadcast(std::shared_ptr<Connection> self, const boost::json::object& request);
    static void handle_logout(std::shared_ptr<Connection> self, const boost::json::object& request);
    
private:
    std::unordered_map<std::string, Handler> hdls;
};
