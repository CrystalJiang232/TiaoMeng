#pragma once
#include <unordered_map>
#include <memory>
#include <functional>

#include "msg.hpp"

class Connection;

class Router
{

public:
    using Handler = std::function<void(std::shared_ptr<Connection>, const Msg&)>;
    
    void register_handler(MsgType type, Handler hdl);
    void route(std::shared_ptr<Connection> conn, const Msg& msg);

private:
    std::unordered_map<MsgType, Handler> handlers;

};
