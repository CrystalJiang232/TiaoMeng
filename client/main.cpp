#include "client/client.hpp"
#include "client/client_config.hpp"

#include <cstdio>
#include <exception>
#include <print>

int main()
{
    try
    {
        Client client(ClientConfig{});
        client.run_interactive();
    }
    catch (const std::exception& e)
    {
        std::println(stderr, "Client error: {}", e.what());
        return 1;
    }
    catch (...)
    {
        std::println(stderr, "Client error: unknown exception");
        return 1;
    }

    return 0;
}
