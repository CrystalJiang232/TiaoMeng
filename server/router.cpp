#include "server.hpp"
#include "helper.hpp"

void Router::register_handler(MsgType type, Handler hdl)
{
    handlers[type] = std::move(hdl);
}

void Router::route(std::shared_ptr<Connection> conn, const Msg& msg)
{
    if (auto it = handlers.find(static_cast<MsgType>(msg.type));it != handlers.end())
    {
        it->second(std::move(conn), msg);
    }
    else
    {
        conn->send(Hibiscus::get_err("Invalid route message type"));
    }
}