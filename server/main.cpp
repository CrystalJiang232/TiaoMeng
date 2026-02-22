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
