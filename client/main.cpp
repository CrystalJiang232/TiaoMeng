#include "client.hpp"
#include "json_utils.hpp"
#include <print>
#include <charconv>
#include <cstring>

int main(int argc, char** argv)
{
    std::string host = (argc > 1) ? argv[1] : "127.0.0.1";
    uint16_t port = 8080;
    if (argc > 2)
    {
        std::ignore = std::from_chars(argv[2], argv[2] + std::strlen(argv[2]), port);
    }

    try
    {
        net::io_context ic;
        Client c(ic, host, port);
        
        if (auto conn_result = c.connect(); !conn_result)
        {
            throw std::runtime_error(std::format("Connect failed: {}", conn_result.error()));
        }
        
        if (auto handshake_result = c.perform_handshake(); !handshake_result)
        {
            throw std::runtime_error(std::format("Handshake failed: {}", handshake_result.error()));
        }
        
        if (auto auth_result = c.authenticate("Barker", "ju bue"); !auth_result)
        {
            throw std::runtime_error(std::format("Authentication failed: {}", auth_result.error()));
        }

        if (auto broadcast_result = c.send_broadcast({
            {"TrainNo", "G148"},
            {"Message", "Christmas Operation"}
        }); broadcast_result)
        {
            std::println("[+] Response: {}", json_utils::extract_str(*broadcast_result, "status").value_or("None"));
        }
        else
        {
            std::println(stderr, "[-] Broadcast failed: {}", broadcast_result.error());
        }

        if (auto logout_result = c.logout(); !logout_result)
        {
            std::println(stderr, "[-] Logout failed (non-fatal): {}", logout_result.error());
        }
        
        if (auto disconnect_result = c.disconnect(); !disconnect_result)
        {
            throw std::runtime_error(std::format("Disconnect failed: {}", disconnect_result.error()));
        }
    }
    catch (const std::exception& e)
    {
        std::println(stderr, "Fatal: {}", e.what());
        return 1;
    }
    
    return 0;
}
