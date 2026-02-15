#include "server.hpp"


int main(int argc, char** argv)
{
    uint16_t port = 8080;
    if(argc > 1)
    {
        std::ignore = std::from_chars(argv[1], argv[1] + strlen(argv[1]), port);
    }

    try
    {
        net::io_context ic;
        Server svr(ic, port);
        
        auto conv = [](char ch){return static_cast<std::byte>(ch);};

        auto cmd_handler = [conv](std::shared_ptr<Connection> conn, const Msg& msg)
            {
                std::println("Received cmd from {}: {} bytes", 
                    conn->get_id(), msg.payload.size());
                
                if(auto echo = Msg::create(std::string("nihao") | std::views::transform(conv) | std::ranges::to<Msg::payload_t>(),MsgType::Broadcast);
                    echo)
                {
                    conn->send(*echo);
                }
            };

        auto handshake_handler = [](std::shared_ptr<Connection> conn, const Msg& msg)
            {
                std::println("Handshake from {}: {} bytes", 
                    conn->get_id(), msg.payload.size());
            };

        auto broadcast_handler = [&svr](std::shared_ptr<Connection> conn, const Msg& msg)
            {
                std::println("Broadcast request from {}: {} bytes",
                    conn->get_id(),msg.payload.size());
                svr.broadcast(msg, conn->get_id());
            };


        svr.get_router()->register_handler(MsgType::Command,cmd_handler);  
        svr.get_router()->register_handler(MsgType::Handshake,handshake_handler);
        svr.get_router()->register_handler(MsgType::Broadcast,broadcast_handler);

        std::println("Server starting on port {}", port);
        svr.start();
    }
    catch (const std::exception& e)
    {
        std::println(stderr, "Fatal: {}", e.what());
        return 1;
    }

    std::println("Server exiting...");
    return 0;
}