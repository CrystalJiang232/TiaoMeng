#include "server.hpp"
#include "config.hpp"

#include <print>
#include <cstring>
#include <charconv>

int main(int argc, char** argv)
{
    // Load configuration from working directory
    // CLI port argument overrides config file if provided
    auto config = Config::load_or_defaults("server_config.json");
    
    // CLI override for port (backward compatible)
    if (argc > 1)
    {
        uint16_t cli_port = 0;
        auto [ptr, ec] = std::from_chars(argv[1], argv[1] + strlen(argv[1]), cli_port);
        if (ec == std::errc{} && cli_port > 0)
        {
            config.set_port(cli_port);
        }
    }

    try
    {
        net::io_context ic;
        Server svr(ic, config);

        std::println("Server starting on {}:{}", 
                     config.server().bind_address, 
                     config.server().port);
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
