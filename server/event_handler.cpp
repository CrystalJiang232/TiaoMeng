#include "event_handler.hpp"
#include "server.hpp"
#include "json_utils.hpp"
#include "logger.hpp"
#include "fundamentals/msg_serialize.hpp"

namespace json = boost::json;
using namespace json_utils;

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
        std::ignore = conn->send_error("Missing 'action' field");
        return;
    }
    
    if (!it->value().is_string())
    {
        std::ignore = conn->send_error("'action' must be string");
        return;
    }
    
    std::string action_str = std::string(it->value().as_string());
    
    auto handler_it = hdls.find(action_str);
    if (handler_it == hdls.end())
    {
        std::ignore = conn->send_error(std::format("Unknown action: {}", action_str));
        return;
    }
    
    conn->reset_session_timer();
    handler_it->second(conn, request);
}

void EventHandler::handle_auth(std::shared_ptr<Connection> self, const json::object& request)
{
    if(self->is_authenticated())
    {
        std::ignore = self->send_error("Already authenticated");
        return;
    }

    std::string username, password;

    if (auto ret = json_utils::extract_str(request, "username"); !ret)
    {
        if (self->server) self->server->metrics().authentications_failed++;
        std::ignore = self->send_error(ret.error()); //Returns anyway, uses std::ignore to bypass [[nodiscard]]
        return;
    }
    else
    {
        username = *ret;
    }

    if (auto ret = json_utils::extract_str(request, "password"); !ret)
    {
        if (self->server) self->server->metrics().authentications_failed++;
        std::ignore = self->send_error(ret.error());
        return;
    }
    else
    {
        password = *ret;
    }

    std::ignore = username, password; //Placeholder
    
    if(true)
    {
        self->setstate(ConnState::Authenticated);
        self->reset_failures();
        self->send_encrypted(status_msg("Success", "Authentication successful"));
        if (self->server) self->server->metrics().authentications_successful++;
        LOG_INFO("Client {} authenticated", self->get_id());
    }
    else
    {
        std::ignore = self->send_error("Authentication Failed");
        LOG_INFO("Client {} authentication failed", self->get_id());
        return;
    }
    
}

void EventHandler::handle_command(std::shared_ptr<Connection> self, const json::object& request)
{
    if (!self->is_authenticated())
    {
        std::ignore = self->send_error("Not authenticated");
        return;
    }
    
    LOG_INFO("Received command from {}: {}", self->get_id(), json::serialize(request));
    self->send_encrypted(status_msg("Success", "Command accepted by server"));
}

void EventHandler::handle_broadcast(std::shared_ptr<Connection> self, const json::object& request)
{
    if (!self->is_authenticated())
    {
        std::ignore = self->send_error("Not authenticated");
        return;
    }
    
    LOG_INFO("Broadcast request from {}: {}", self->get_id(), json::serialize(request));
    self->send_encrypted(status_msg("Success", "Broadcast request processed"));

    auto json_payload = json::serialize(json::object{{"From",self->get_id()}, {"msg", json_utils::extract_str(request,"msg").value_or("")}})
            | std::views::transform([](auto&& ch){return static_cast<std::byte>(ch);})
            | std::ranges::to<Msg::payload_t>();

    auto m = msg::make(json_payload, encrypted_notify);
    if(!m)
    {
        LOG_ERROR("Unexpected broadcast message make error");
        return;
    }

    self->server->broadcast(*m, self->get_id());
}

void EventHandler::handle_logout(std::shared_ptr<Connection> self, const json::object& request)
{
    std::ignore = request; //...
    
    if (self->getstate() == ConnState::Authenticated)
    {
        self->setstate(ConnState::Established);
        self->reset_failures();
        self->send_encrypted(status_msg("Success", "Logged out successfully"));
        LOG_INFO("Client {} logged out", self->get_id());
    }
    else
    {
        std::ignore = self->send_error("Not authenticated");
        return;
    }
}
