#include "server.hpp"
#include "helper.hpp"

// Router is deprecated - action-based routing is now handled internally by Connection
// See Connection::handle_request() for the new routing logic

void Router::register_handler(MsgType type, Handler hdl)
{
    // Deprecated: Handlers are now managed internally by Connection class
    (void)type;
    (void)hdl;
}

void Router::route(std::shared_ptr<Connection> conn, const Msg& msg)
{
    // Deprecated: Routing is now handled internally by Connection::handle_request()
    // This function is kept for backward compatibility but does nothing
    (void)conn;
    (void)msg;
}
