#include "client/client.hpp"
#include "extern/CLI11/CLI11.hpp"
#include <print>
#include <string>
#include <cstdint>
#include <functional>
#include <unordered_map>

// Mode handler base class
class ModeHandler
{
public:
    virtual ~ModeHandler() = default;
    virtual int run(const std::string& host, uint16_t port) = 0;
};

// Stub implementations for mode handlers (to be filled by user)
class InteractiveMode : public ModeHandler
{
public:
    int run(const std::string& host, uint16_t port) override
    {
        std::println("Interactive mode selected");
        std::println("Connecting to {}:{}...", host, port);
        std::println("");
        std::println("TODO: Implement interactive REPL");
        std::println("  - Kyber768 handshake");
        std::println("  - Auth prompt");
        std::println("  - Command loop with tab completion");
        std::println("  - Background recv thread");
        return 0;
    }
};

class ScriptMode : public ModeHandler
{
public:
    int run(const std::string& host, uint16_t port) override
    {
        std::println("Script mode selected");
        std::println("Server: {}:{}", host, port);
        std::println("");
        std::println("TODO: Implement script execution");
        std::println("  - Parse JSON script file");
        std::println("  - Execute steps sequentially");
        std::println("  - Optional response verification");
        return 0;
    }
};

class BenchMode : public ModeHandler
{
public:
    int run(const std::string& host, uint16_t port) override
    {
        std::println("Benchmark mode selected");
        std::println("Server: {}:{}", host, port);
        std::println("");
        std::println("TODO: Implement load testing");
        std::println("  - Spawn N concurrent connections");
        std::println("  - Each sends at R rate for D duration");
        std::println("  - Collect and report metrics");
        return 0;
    }
};

class SingleMode : public ModeHandler
{
public:
    int run(const std::string& host, uint16_t port) override
    {
        std::println("Single action mode selected");
        std::println("Server: {}:{}", host, port);
        std::println("");
        std::println("TODO: Implement single action execution");
        std::println("  - Connect, handshake, auth");
        std::println("  - Execute specified action");
        std::println("  - Print response and exit");
        return 0;
    }
};

// Router/Dispatcher for client modes
class ClientRouter
{
public:
    ClientRouter()
        : host("127.0.0.1")
        , port(8080)
    {
        setup_app();
        setup_interactive_mode();
        setup_script_mode();
        setup_bench_mode();
        setup_single_mode();
        register_modes();
    }

    int dispatch(int argc, char** argv)
    {
        try
        {
            app.parse(argc, argv);
            
            if (selected_mode.empty())
            {
                std::println(stderr, "Error: No mode specified");
                std::println("Use --help for usage information");
                return 1;
            }
            
            auto it = modes.find(selected_mode);
            if (it == modes.end())
            {
                std::println(stderr, "Error: Unknown mode '{}'", selected_mode);
                return 1;
            }
            
            return it->second->run(host, port);
        }
        catch (const CLI::ParseError& e)
        {
            return app.exit(e);
        }
        catch (const std::exception& e)
        {
            std::println(stderr, "Fatal error: {}", e.what());
            return 1;
        }
    }

private:
    void setup_app()
    {
        app.name("client");
        app.description("TiaoMeng Test Client - Multi-mode client for testing the messaging server");
        app.set_help_all_flag("--help-all", "Expand all help");
        
        app.add_option("--host", host, "Server host address")
            ->default_val("127.0.0.1");
        
        app.add_option("-p,--port", port, "Server port")
            ->default_val(8080)
            ->check(CLI::Range(1, 65535));
    }

    void setup_interactive_mode()
    {
        auto* cmd = app.add_subcommand("interactive", "Interactive REPL mode");
        
        cmd->callback([this]() 
        {
            selected_mode = "interactive";
        });
    }

    void setup_script_mode()
    {
        auto* cmd = app.add_subcommand("script", "Execute commands from script file");
        
        cmd->add_option("-f,--file", script_file, "Path to script file (JSON)")
            ->required();
        
        cmd->add_flag("-v,--verify", script_verify, "Verify responses against expected values");
        
        cmd->callback([this]() 
        {
            selected_mode = "script";
        });
    }

    void setup_bench_mode()
    {
        auto* cmd = app.add_subcommand("bench", "Benchmark/Load testing mode");
        
        cmd->add_option("-c,--connections", bench_connections, "Number of concurrent connections")
            ->default_val(10)
            ->check(CLI::Range(1, 10000));
        
        cmd->add_option("-d,--duration", bench_duration_sec, "Test duration in seconds")
            ->default_val(60)
            ->check(CLI::Range(1, 3600));
        
        cmd->add_option("-r,--rate", bench_rate, "Messages per second per connection")
            ->default_val(10)
            ->check(CLI::Range(1, 10000));
        
        cmd->add_option("-s,--payload-size", bench_payload_size, "Broadcast payload size in bytes")
            ->default_val(256)
            ->check(CLI::Range(16, 65536));
        
        cmd->add_option("-u,--users", bench_users, "CSV file with username:password pairs");
        
        cmd->callback([this]() 
        {
            selected_mode = "bench";
        });
    }

    void setup_single_mode()
    {
        auto* cmd = app.add_subcommand("single", "Execute single action and exit");
        
        cmd->add_option("-a,--auth", single_auth, "Credentials in format 'username:password'")
            ->required();
        
        cmd->add_option("--action", single_action, "Action to perform")
            ->required()
            ->check(CLI::IsMember({"auth", "broadcast", "command", "logout"}));
        
        cmd->add_option("--data", single_data, "JSON data for action (optional)");
        
        cmd->callback([this]() 
        {
            selected_mode = "single";
        });
    }

    void register_modes()
    {
        modes["interactive"] = std::make_unique<InteractiveMode>();
        modes["script"] = std::make_unique<ScriptMode>();
        modes["bench"] = std::make_unique<BenchMode>();
        modes["single"] = std::make_unique<SingleMode>();
    }

    CLI::App app{"TiaoMeng Test Client"};
    
    // Common options
    std::string host;
    uint16_t port;
    
    // Mode selection
    std::string selected_mode;
    std::unordered_map<std::string, std::unique_ptr<ModeHandler>> modes;
    
    // Script mode options
    std::string script_file;
    bool script_verify = false;
    
    // Bench mode options
    int bench_connections = 10;
    int bench_duration_sec = 60;
    int bench_rate = 10;
    int bench_payload_size = 256;
    std::string bench_users;
    
    // Single mode options
    std::string single_auth;
    std::string single_action;
    std::string single_data;
};

int main(int argc, char** argv)
{
    ClientRouter router;
    return router.dispatch(argc, argv);
}
