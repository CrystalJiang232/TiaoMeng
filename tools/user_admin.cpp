#include "tools/user_admin.hpp"
#include "extern/CLI11/CLI11.hpp"

#include <expected>
#include <filesystem>
#include <print>
#include <string>

int main(int argc, char** argv)
{
    CLI::App app{"TiaoMeng User Administration Tool"};
    app.require_subcommand(1);
    
    std::string db_path = "auth.db";
    app.add_option("-d,--database", db_path, "Database file path")
       ->default_val("auth.db");
    
    auto init_cmd = app.add_subcommand("init", "Initialize database schema");
    std::string init_user;
    std::string init_pass;
    init_cmd->add_option("admin_user", init_user, "Bootstrap admin username");
    init_cmd->add_option("admin_password", init_pass, "Bootstrap admin password");
    
    init_cmd->callback([&]()
    {
        std::optional<std::string> u = init_user.empty() ? std::nullopt : std::optional(init_user);
        std::optional<std::string> p = init_pass.empty() ? std::nullopt : std::optional(init_pass);
        
        auto res = tools::cmd_init(db_path, u, p);
        if (!res)
        {
            std::println(stderr, "Error: {}", res.error());
            std::exit(1);
        }
        std::println("{}", *res);
    });
    
    auto add_cmd = app.add_subcommand("add", "Create new user");
    std::string add_user;
    std::string add_pass;
    add_cmd->add_option("username", add_user, "Username")->required();
    add_cmd->add_option("password", add_pass, "Password")->required();
    
    add_cmd->callback([&]()
    {
        ThreadPool pool(1);
        auto auth_res = auth::AuthManager::create(db_path, pool);
        if (!auth_res)
        {
            std::println(stderr, "Error: {}", auth_res.error());
            std::exit(1);
        }
        
        auto res = tools::cmd_add(*auth_res, add_user, add_pass);
        if (!res)
        {
            std::println(stderr, "Error: {}", res.error());
            std::exit(1);
        }
        std::println("{}", *res);
    });
    
    auto list_cmd = app.add_subcommand("list", "List all users");
    list_cmd->callback([&]()
    {
        ThreadPool pool(1);
        auto auth_res = auth::AuthManager::create(db_path, pool);
        if (!auth_res)
        {
            std::println(stderr, "Error: {}", auth_res.error());
            std::exit(1);
        }
        
        auto res = tools::cmd_list(auth_res->db());
        if (!res)
        {
            std::println(stderr, "Error: {}", res.error());
            std::exit(1);
        }
        if (!res->empty())
        {
            std::println("{}", *res);
        }
    });
    
    auto disable_cmd = app.add_subcommand("disable", "Deactivate user");
    std::string disable_user;
    disable_cmd->add_option("username", disable_user, "Username to disable")->required();
    disable_cmd->callback([&]()
    {
        ThreadPool pool(1);
        auto auth_res = auth::AuthManager::create(db_path, pool);
        if (!auth_res)
        {
            std::println(stderr, "Error: {}", auth_res.error());
            std::exit(1);
        }
        
        auto res = tools::cmd_disable(auth_res->db(), disable_user);
        if (!res)
        {
            std::println(stderr, "Error: {}", res.error());
            std::exit(1);
        }
        std::println("{}", *res);
    });
    
    auto enable_cmd = app.add_subcommand("enable", "Reactivate user");
    std::string enable_user;
    enable_cmd->add_option("username", enable_user, "Username to enable")->required();
    enable_cmd->callback([&]()
    {
        ThreadPool pool(1);
        auto auth_res = auth::AuthManager::create(db_path, pool);
        if (!auth_res)
        {
            std::println(stderr, "Error: {}", auth_res.error());
            std::exit(1);
        }
        
        auto res = tools::cmd_enable(auth_res->db(), enable_user);
        if (!res)
        {
            std::println(stderr, "Error: {}", res.error());
            std::exit(1);
        }
        std::println("{}", *res);
    });
    
    auto reset_cmd = app.add_subcommand("reset", "Reset user password");
    std::string reset_user;
    std::string reset_pass;
    reset_cmd->add_option("username", reset_user, "Username")->required();
    reset_cmd->add_option("password", reset_pass, "New password")->required();
    reset_cmd->callback([&]()
    {
        ThreadPool pool(1);
        auto auth_res = auth::AuthManager::create(db_path, pool);
        if (!auth_res)
        {
            std::println(stderr, "Error: {}", auth_res.error());
            std::exit(1);
        }
        
        auto res = tools::cmd_reset(auth_res->db(), reset_user, reset_pass);
        if (!res)
        {
            std::println(stderr, "Error: {}", res.error());
            std::exit(1);
        }
        std::println("{}", *res);
    });
    
    auto kick_cmd = app.add_subcommand("kick", "Clear user connection");
    std::string kick_user;
    kick_cmd->add_option("username", kick_user, "Username")->required();
    kick_cmd->callback([&]()
    {
        ThreadPool pool(1);
        auto auth_res = auth::AuthManager::create(db_path, pool);
        if (!auth_res)
        {
            std::println(stderr, "Error: {}", auth_res.error());
            std::exit(1);
        }
        
        auto res = tools::cmd_kick(auth_res->db(), kick_user);
        if (!res)
        {
            std::println(stderr, "Error: {}", res.error());
            std::exit(1);
        }
        std::println("{}", *res);
    });
    
    auto remove_cmd = app.add_subcommand("remove", "Permanently delete user");
    std::string remove_user;
    remove_cmd->add_option("username", remove_user, "Username to delete")->required();
    remove_cmd->callback([&]()
    {
        ThreadPool pool(1);
        auto auth_res = auth::AuthManager::create(db_path, pool);
        if (!auth_res)
        {
            std::println(stderr, "Error: {}", auth_res.error());
            std::exit(1);
        }
        
        auto res = tools::cmd_remove(auth_res->db(), remove_user);
        if (!res)
        {
            std::println(stderr, "Error: {}", res.error());
            std::exit(1);
        }
        std::println("{}", *res);
    });
    
    auto exists_cmd = app.add_subcommand("exists", "Check if database file exists");
    exists_cmd->callback([&]()
    {
        if (tools::db_exists(db_path))
        {
            std::println("Database '{}' exists", db_path);
        }
        else
        {
            std::println("Database '{}' does not exist", db_path);
            std::exit(1);
        }
    });
    
    CLI11_PARSE(app, argc, argv);
    return 0;
}
