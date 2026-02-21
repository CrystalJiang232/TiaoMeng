#include "event_handler.hpp"
#include "server.hpp"
#include "helper.hpp"
#include <print>

namespace json = boost::json;
using namespace Hibiscus;

EventHandler::EventHandler() : hdls{
    {"auth",handle_auth},
    {"command", handle_command},
    {"broadcast", handle_broadcast},
    {"logout", handle_logout}
}
{
    
}

void EventHandler::route(std::shared_ptr<Connection> conn, const json::object& request)
{
    auto it = request.find("action");
    if (it == request.end())
    {
        conn->send_encrypted(status_msg("Error", "Missing 'action' field"));
        if (conn->record_failure())
        {
            conn->close("Missing action threshold exceeded");
        }
        return;
    }
    
    if (!it->value().is_string())
    {
        conn->send_encrypted(status_msg("Error", "'action' must be string"));
        if (conn->record_failure())
        {
            conn->close("Invalid action format threshold exceeded");
        }
        return;
    }
    
    std::string action_str = std::string(it->value().as_string());
    
    auto handler_it = hdls.find(action_str);
    if (handler_it == hdls.end())
    {
        conn->send_encrypted(status_msg("Error", std::format("Unknown action: {}", action_str)));
        if (conn->record_failure())
        {
            conn->close("Unknown action threshold exceeded");
        }
        return;
    }
    
    handler_it->second(conn, request);
}

void EventHandler::handle_auth(std::shared_ptr<Connection> self, const json::object& request)
{
    (void)request;
    
    self->setstate(ConnState::Authenticated);
    self->reset_failures();
    self->send_encrypted(status_msg("Success", "Authentication successful"));
    std::println("Client {} authenticated", self->get_id());
}

void EventHandler::handle_command(std::shared_ptr<Connection> self, const json::object& request)
{
    if (!self->is_authenticated())
    {
        self->send_encrypted(status_msg("Error", "Not authenticated"));
        if (self->record_failure())
        {
            self->close("Unauthenticated request threshold exceeded");
        }
        return;
    }
    
    std::println("Received command from {}: {}", self->get_id(), json::serialize(request));
    self->send_encrypted(status_msg("Success", "Command accepted by server"));
}

void EventHandler::handle_broadcast(std::shared_ptr<Connection> self, const json::object& request)
{
    if (!self->is_authenticated())
    {
        self->send_encrypted(status_msg("Error", "Not authenticated"));
        if (self->record_failure())
        {
            self->close("Unauthenticated request threshold exceeded");
        }
        return;
    }
    
    std::println("Broadcast request from {}: {}", self->get_id(), json::serialize(request));
    self->send_encrypted(status_msg("Success", "Broadcast request processed"));
}

void EventHandler::handle_logout(std::shared_ptr<Connection> self, const json::object& request)
{
    (void)request;
    
    if (self->getstate() == ConnState::Authenticated)
    {
        self->setstate(ConnState::Established);
        self->reset_failures();
        self->send_encrypted(status_msg("Success", "Logged out successfully"));
        std::println("Client {} logged out", self->get_id());
    }
    else
    {
        self->send_encrypted(status_msg("Error", "Not authenticated"));
    }
}
