#include "event_handler.hpp"
#include "server.hpp"
#include "fundamentals/json_utils.hpp"
#include "logger/logger.hpp"
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
    
    if (conn->is_authenticated() && !conn->get_auth_user().empty() && conn->server && conn->server->has_auth())
    {
        auto current = conn->server->auth().db().get_current_conn(conn->get_auth_user());
        if (!current || *current != conn->get_id())
        {
            std::ignore = conn->send_error("Session terminated", Connection::CloseMode::CancelOthers, true);
            return;
        }
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

    if (!self->server || !self->server->has_auth())
    {
        std::ignore = self->send_error("Authentication unavailable");
        return;
    }

    std::string username, password;

    if (auto ret = json_utils::extract_str(request, "username"); !ret)
    {
        if (self->server) self->server->metrics().authentications_failed++;
        std::ignore = self->send_error("Authentication failed");
        return;
    }
    else
    {
        username = *ret;
    }

    if (auto ret = json_utils::extract_str(request, "password"); !ret)
    {
        if (self->server) self->server->metrics().authentications_failed++;
        std::ignore = self->send_error("Authentication failed");
        return;
    }
    else
    {
        password = *ret;
    }
    
    auto future_result = self->server->cpu_pool().submit([&]() -> auth::AuthManager::AuthResult
    {
        net::io_context temp_ic;
        auth::AuthManager::AuthResult local_result{false, false};
        
        net::co_spawn(temp_ic,
            [&]() -> net::awaitable<void>
            {
                local_result = co_await self->server->auth().verify(username, password);
            },
            net::detached
        );
        
        temp_ic.run();
        return local_result;
    });
    
    if (!future_result)
    {
        std::ignore = self->send_error("Authentication failed");
        if (self->server) self->server->metrics().authentications_failed++;
        LOG_INFO("Client {} authentication failed", self->get_id());
        return;
    }
    
    auto result = *future_result;
    
    if (result.locked)
    {
        std::ignore = self->send_error("Account locked");
        if (self->server) self->server->metrics().authentications_failed++;
        LOG_INFO("Client {} authentication failed: account locked", self->get_id());
        return;
    }
    
    if (!result.success)
    {
        std::ignore = self->send_error("Authentication failed");
        if (self->server) self->server->metrics().authentications_failed++;
        LOG_INFO("Client {} authentication failed", self->get_id());
        return;
    }
    
    self->server->register_user_session(username, self->get_id());
    
    self->set_auth_user(username);
    self->setstate(ConnState::Authenticated);
    self->reset_failures();
    self->send_encrypted(status_msg("Success", "Authentication successful"));
    if (self->server) self->server->metrics().authentications_successful++;
    LOG_INFO("Client {} authenticated as {}", self->get_id(), username);
}

void EventHandler::handle_command(std::shared_ptr<Connection> self, const json::object& request)
{
    std::ignore = request;

    if (!self->is_authenticated())
    {
        std::ignore = self->send_error("Not authenticated");
        return;
    }
    
    LOG_INFO("Received command from {}", self->get_id());
    self->send_encrypted(status_msg("Success", "Command accepted by server"));
}

void EventHandler::handle_broadcast(std::shared_ptr<Connection> self, const json::object& request)
{
    if (!self->is_authenticated())
    {
        std::ignore = self->send_error("Not authenticated");
        return;
    }
    
    LOG_INFO("Broadcast request from {}", self->get_id());
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
        std::ignore = self->server->auth().db().clear_conn_id_if_matches(self->get_auth_user(), self->get_id()); //Server-side
        self->clear_auth_user(); //Connection-side
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
