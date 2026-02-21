#include "client.hpp"
#include "json_utils.hpp"
#include <print>

int main(int argc, char** argv)
{
    std::string host = (argc > 1) ? argv[1] : "127.0.0.1";
    uint16_t port = 8080;
    if(argc > 2)
    {
        std::ignore = std::from_chars(argv[2], argv[2] + std::strlen(argv[2]), port);
    }

    try
    {
        net::io_context ic;
        Client c(ic,host,port);
        
        if(!c.connect() || !c.perform_handshake() || !c.authenticate("Barker","ju bue"))
        {
            throw std::runtime_error(std::format("Failed to connect to {}:{}",host,port));
        }

        c.send_broadcast({
            {"TrainNo","G148"},
            {"Message","Christmas Operation"}
        });

        if(auto r = c.recv_response(); r)
        {
            //std::println("[+] Response: {}", json_utils::extract_str(*r, "status").value_or("None"));
        }

        c.logout();
        c.disconnect();
    }
    catch (const std::exception& e)
    {
        std::println(stderr, "Fatal: {}", e.what());
        return 1;
    }
    
    return 0;
}
