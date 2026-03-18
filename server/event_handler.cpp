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
    LOG_DEBUG("[EVT] {} route() ENTER", conn->get_id());
    
    auto it = request.find("action");
    if (it == request.end())
    {
        std::ignore = conn->send_error("Missing 'action' field");
        LOG_DEBUG("[EVT] {} route() EXIT: missing action", conn->get_id());
        return;
    }
    
    if (!it->value().is_string())
    {
        std::ignore = conn->send_error("'action' must be string");
        LOG_DEBUG("[EVT] {} route() EXIT: action not string", conn->get_id());
        return;
    }
    
    std::string action_str = std::string(it->value().as_string());
    LOG_DEBUG("[EVT] {} route() action='{}'", conn->get_id(), action_str);
    
    auto handler_it = hdls.find(action_str);
    if (handler_it == hdls.end())
    {
        std::ignore = conn->send_error(std::format("Unknown action: {}", action_str));
        LOG_DEBUG("[EVT] {} route() EXIT: unknown action", conn->get_id());
        return;
    }
    
    LOG_DEBUG("[EVT] {} route() checking auth...", conn->get_id());
    if (conn->is_authenticated() && !conn->get_auth_user().empty() && conn->server && conn->server->has_auth())
    {
        LOG_DEBUG("[EVT] {} route() validating conn...", conn->get_id());
        if (!conn->server->validate_conn(conn->get_auth_user(), conn->get_id()))
        {
            LOG_DEBUG("[EVT] {} route() session invalid, closing", conn->get_id());
            conn->error_and_close("Session terminated");
        }
        LOG_DEBUG("[EVT] {} route() conn validated", conn->get_id());
    }
    
    LOG_DEBUG("[EVT] {} route() calling handler...", conn->get_id());
    handler_it->second(conn, request);
    LOG_DEBUG("[EVT] {} route() EXIT", conn->get_id());
}

void EventHandler::handle_auth(std::shared_ptr<Connection> self, const json::object& request)
{
    LOG_DEBUG("[EVT] {} handle_auth ENTER", self->get_id());
    
    if(self->is_authenticated())
    {
        std::ignore = self->send_error("Already authenticated");
        LOG_DEBUG("[EVT] {} handle_auth EXIT: already auth", self->get_id());
        return;
    }

    if (!self->server || !self->server->has_auth())
    {
        std::ignore = self->send_error("Authentication unavailable");
        LOG_DEBUG("[EVT] {} handle_auth EXIT: auth unavailable", self->get_id());
        return;
    }

    std::string username, password;

    if (auto ret = json_utils::extract_str(request, "username"); !ret)
    {
        if (self->server) self->server->metrics().inc_authentications_failed();
        std::ignore = self->send_error("Authentication failed");
        LOG_DEBUG("[EVT] {} handle_auth EXIT: no username", self->get_id());
        return;
    }
    else
    {
        username = *ret;
    }

    if (auto ret = json_utils::extract_str(request, "password"); !ret)
    {
        if (self->server) self->server->metrics().inc_authentications_failed();
        std::ignore = self->send_error("Authentication failed");
        LOG_DEBUG("[EVT] {} handle_auth EXIT: no password", self->get_id());
        return;
    }
    else
    {
        password = *ret;
    }
    
    LOG_DEBUG("[EVT] {} handle_auth starting verify...", self->get_id());
    net::io_context auth_io;
    auth::AuthManager::AuthResult auth_result{false, false};
    
    net::co_spawn(auth_io,
        [&]() -> net::awaitable<void>
        {
            LOG_DEBUG("[EVT] {} handle_auth verify coro START", self->get_id());
            auth_result = co_await self->server->auth().verify(username, password);
            LOG_DEBUG("[EVT] {} handle_auth verify coro DONE", self->get_id());
        },
        net::detached
    );
    
    LOG_DEBUG("[EVT] {} handle_auth auth_io.run() START", self->get_id());
    auth_io.run();
    LOG_DEBUG("[EVT] {} handle_auth auth_io.run() DONE", self->get_id());
    LOG_DEBUG("[EVT] {} handle_auth got result: locked={} success={}", self->get_id(), auth_result.locked, auth_result.success);
    
    if (auth_result.locked)
    {
        std::ignore = self->send_error("Account locked");
        if (self->server) self->server->metrics().inc_authentications_failed();
        LOG_INFO("Client {} authentication failed: account locked", self->get_id());
        LOG_DEBUG("[EVT] {} handle_auth EXIT: account locked", self->get_id());
        return;
    }
    
    if (!auth_result.success)
    {
        std::ignore = self->send_error("Authentication failed");
        if (self->server) self->server->metrics().inc_authentications_failed();
        LOG_INFO("Client {} authentication failed", self->get_id());
        LOG_DEBUG("[EVT] {} handle_auth EXIT: auth failed", self->get_id());
        return;
    }
    
    LOG_DEBUG("[EVT] {} handle_auth success, registering session...", self->get_id());
    self->server->register_user_session(username, self->get_id());
    
    self->set_auth_user(username);
    self->setstate(ConnState::Authenticated);
    self->reset_failures();
    self->send_encrypted(status_msg("Success", "Authentication successful"));
    if (self->server) self->server->metrics().inc_authentications_successful();
    LOG_INFO("Client {} authenticated as {}", self->get_id(), username);
    LOG_DEBUG("[EVT] {} handle_auth EXIT", self->get_id());
}

void EventHandler::handle_command(std::shared_ptr<Connection> self, const json::object& request)
{
    std::ignore = request;
    LOG_DEBUG("[EVT] {} handle_command ENTER", self->get_id());

    if (!self->is_authenticated())
    {
        std::ignore = self->send_error("Not authenticated");
        LOG_DEBUG("[EVT] {} handle_command EXIT: not auth", self->get_id());
        return;
    }
    
    LOG_INFO("Received command from {}", self->get_id());
    LOG_DEBUG("[EVT] {} handle_command sending response...", self->get_id());
    self->send_encrypted(status_msg("Success", "Command accepted by server"));
    LOG_DEBUG("[EVT] {} handle_command EXIT", self->get_id());
}

void EventHandler::handle_broadcast(std::shared_ptr<Connection> self, const json::object& request)
{
    LOG_DEBUG("[EVT] {} handle_broadcast ENTER", self->get_id());
    
    if (!self->is_authenticated())
    {
        std::ignore = self->send_error("Not authenticated");
        LOG_DEBUG("[EVT] {} handle_broadcast EXIT: not auth", self->get_id());
        return;
    }
    
    LOG_INFO("Broadcast request from {}", self->get_id());
    LOG_DEBUG("[EVT] {} handle_broadcast sending ack...", self->get_id());
    self->send_encrypted(status_msg("Success", "Broadcast request processed"));

    LOG_DEBUG("[EVT] {} handle_broadcast creating msg...", self->get_id());
    auto json_payload = json::serialize(json::object{{"From",self->get_id()}, {"msg", json_utils::extract_str(request,"msg").value_or("")}})
            | std::views::transform([](auto&& ch){return static_cast<std::byte>(ch);})
            | std::ranges::to<Msg::payload_t>();

    auto m = msg::make(json_payload, encrypted_notify);
    if(!m)
    {
        LOG_ERROR("Unexpected broadcast message make error");
        LOG_DEBUG("[EVT] {} handle_broadcast EXIT: msg make error", self->get_id());
        return;
    }

    LOG_DEBUG("[EVT] {} handle_broadcast calling server->broadcast()...", self->get_id());
    self->server->broadcast(*m, self->get_id());
    LOG_DEBUG("[EVT] {} handle_broadcast EXIT", self->get_id());
}

void EventHandler::handle_logout(std::shared_ptr<Connection> self, const json::object& request)
{
    std::ignore = request; //...
    LOG_DEBUG("[EVT] {} handle_logout ENTER", self->get_id());
    
    if (self->getstate() == ConnState::Authenticated)
    {
        LOG_DEBUG("[EVT] {} handle_logout clearing session...", self->get_id());
        self->setstate(ConnState::Established);
        std::ignore = self->server->auth().db().clear_conn_id_if_matches(self->get_auth_user(), self->get_id()); //Server-side
        self->clear_auth_user(); //Connection-side
        self->reset_failures();
        self->send_encrypted(status_msg("Success", "Logged out successfully"));
        LOG_INFO("Client {} logged out", self->get_id());
        LOG_DEBUG("[EVT] {} handle_logout EXIT", self->get_id());
    }
    else
    {
        std::ignore = self->send_error("Not authenticated");
        LOG_DEBUG("[EVT] {} handle_logout EXIT: not auth", self->get_id());
        return;
    }
}
