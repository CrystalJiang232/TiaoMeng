#include "auth/auth_manager.hpp"
#include "auth/user_db.hpp"
#include "auth/argon2_hasher.hpp"
#include "threadpool/threadpool.hpp"

#include <print>
#include <string>
#include <vector>
#include <cstring>

void print_usage(const char* prog)
{
    std::println("Usage: {} <command> [args]", prog);
    std::println("Commands:");
    std::println("  add <username> <password>    Create new user");
    std::println("  list                         List all users");
    std::println("  disable <username>           Deactivate user");
    std::println("  enable <username>            Reactivate user");
    std::println("  reset <username> <password>  Reset password");
    std::println("  kick <username>              Clear current connection");
}

int cmd_add(auth::AuthManager& auth, std::string_view user, std::string_view pass)
{
    if (!auth::check_password(pass))
    {
        std::println(stderr, "Password too short (min 8 chars)");
        return 1;
    }
    
    if (auth.register_user(user, pass))
    {
        std::println("User '{}' created", user);
        return 0;
    }
    
    std::println(stderr, "Failed to create user (may already exist)");
    return 1;
}

int cmd_list(auth::UserDB& db)
{
    auto users = db.list_users();
    if (users.empty())
    {
        std::println("No users found");
        return 0;
    }
    
    std::println("{:<20} {:<10} {}", "Username", "Status", "Last Login");
    std::println("{}", std::string(50, '-'));
    
    for (const auto& u : users)
    {
        auto status = u.active ? "active" : "disabled";
        auto last = u.last_login == 0 ? "never" : std::to_string(u.last_login);
        std::println("{:<20} {:<10} {}", u.username, status, last);
    }
    
    return 0;
}

int cmd_disable(auth::UserDB& db, std::string_view user)
{
    if (db.deactivate_user(user))
    {
        std::println("User '{}' disabled", user);
        return 0;
    }
    
    std::println(stderr, "Failed to disable user (not found)");
    return 1;
}

int cmd_enable(auth::UserDB& db, std::string_view user)
{
    if (db.activate_user(user))
    {
        std::println("User '{}' enabled", user);
        return 0;
    }
    
    std::println(stderr, "Failed to enable user (not found)");
    return 1;
}

int cmd_reset(auth::UserDB& db, std::string_view user, std::string_view pass)
{
    if (!auth::check_password(pass))
    {
        std::println(stderr, "Password too short (min 8 chars)");
        return 1;
    }
    
    auto hash_res = auth::Argon2Hasher::hash(pass);
    if (!hash_res)
    {
        std::println(stderr, "Failed to hash password");
        return 1;
    }
    
    if (db.update_password(user, hash_res->encoded))
    {
        std::println("Password reset for '{}'", user);
        return 0;
    }
    
    std::println(stderr, "Failed to reset password (user not found)");
    return 1;
}

int cmd_kick(auth::UserDB& db, std::string_view user)
{
    if (db.set_current_conn(user, ""))
    {
        std::println("User '{}' connection cleared", user);
        return 0;
    }
    
    std::println(stderr, "Failed to clear connection (user not found)");
    return 1;
}

int main(int argc, char** argv)
{
    if (argc < 2)
    {
        print_usage(argv[0]);
        return 1;
    }
    
    std::string cmd = argv[1];
    
    ThreadPool pool(1);
    
    auto auth_res = auth::AuthManager::create("auth.db", pool);
    if (!auth_res)
    {
        std::println(stderr, "Failed to open auth.db: {}", auth_res.error());
        return 1;
    }
    
    auto& auth = *auth_res;
    auto& db = auth.db();
    
    if (cmd == "add" && argc == 4)
    {
        return cmd_add(auth, argv[2], argv[3]);
    }
    else if (cmd == "list")
    {
        return cmd_list(db);
    }
    else if (cmd == "disable" && argc == 3)
    {
        return cmd_disable(db, argv[2]);
    }
    else if (cmd == "enable" && argc == 3)
    {
        return cmd_enable(db, argv[2]);
    }
    else if (cmd == "reset" && argc == 4)
    {
        return cmd_reset(db, argv[2], argv[3]);
    }
    else if (cmd == "kick" && argc == 3)
    {
        return cmd_kick(db, argv[2]);
    }
    else
    {
        print_usage(argv[0]);
        return 1;
    }
}
