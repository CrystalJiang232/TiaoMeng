#include "event_handler.hpp"
#include "server.hpp"
#include "helper.hpp"
#include <print>

namespace json = boost::json;
using namespace Hibiscus;

namespace EventHandler
{

void handle_auth(std::shared_ptr<Connection> self, const json::object& request)
{
    (void)request;  // Unused for now - placeholder
    
    // Placeholder: Always succeed for now
    // TODO: Implement actual authentication logic
    
    /*
    // Original auth placeholder code:
    auto auth_data_view = msg.payload | std::views::drop(Kyber768::ciphertext_size);
    if (auth_data_view)
    {
        auto decrypted = sess.decrypt(auth_data_view
        | std::views::transform(std::to_underlying<std::byte>)
        | std::ranges::to<std::vector<uint8_t>>());
        if (decrypted)
        {
            std::println("Auth received from {}: {} bytes", id, decrypted->size());
        }
    }
    */
    
    // Placeholder: Accept any auth for now
    self->setstate(ConnState::Authenticated);
    self->reset_failures();
    
    self->send_encrypted(status_msg("Success", "Authentication successful"));
    
    std::println("Client {} authenticated", self->get_id());
}

void handle_command(std::shared_ptr<Connection> self, const json::object& request)
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
    
    /*
    // Original Command handler code (from main.cpp):
    auto cmd_handler = [](std::shared_ptr<Connection> conn, const Msg& msg)
    {
        std::println("Received cmd from {}: {} bytes", 
            conn->get_id(), msg.payload.size());
        
        if(auto echo = Msg::make(Hibiscus::to_bytes("Command accepted by server"),MsgType::Command);
            echo)
        {
            conn->send_encrypted(*echo);
        }
    };
    */
    
    // Placeholder implementation
    std::println("Received command from {}: {}", self->get_id(), json::serialize(request));
    
    self->send_encrypted(status_msg("Success", "Command accepted by server"));
}

void handle_broadcast(std::shared_ptr<Connection> self, const json::object& request)
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
    
    /*
    // Original Broadcast handler code (from main.cpp):
    auto broadcast_handler = [&svr](std::shared_ptr<Connection> conn, const Msg& msg)
    {
        std::println("Broadcast request from {}: {} bytes",
            conn->get_id(),msg.payload.size());
        svr.broadcast(msg, conn->get_id());
    };
    */
    
    // Placeholder implementation
    std::println("Broadcast request from {}: {}", self->get_id(), json::serialize(request));
    
    // TODO: Implement actual broadcast logic
    self->send_encrypted(status_msg("Success", "Broadcast request processed"));
}

void handle_logout(std::shared_ptr<Connection> self)
{
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

} // namespace EventHandler
