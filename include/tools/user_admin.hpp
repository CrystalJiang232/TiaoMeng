#pragma once

#include "auth/auth_manager.hpp"
#include "auth/user_db.hpp"
#include "auth/argon2_hasher.hpp"
#include "threadpool/threadpool.hpp"

#include <expected>
#include <filesystem>
#include <print>
#include <string>

namespace tools
{

using Result = std::expected<std::string, std::string>;

[[nodiscard]] inline bool db_exists(std::string_view db_path)
{
    return std::filesystem::exists(db_path);
}

[[nodiscard]] inline Result cmd_init(
    std::string_view db_path,
    std::optional<std::string> admin_user,
    std::optional<std::string> admin_pass)
{
    ThreadPool pool(1);
    
    auto auth_res = auth::AuthManager::create(db_path, pool);
    if (!auth_res)
    {
        return std::unexpected(std::format("Failed to open {}: {}", db_path, auth_res.error()));
    }
    
    if (!admin_user || !admin_pass)
    {
        return "Database initialized successfully";
    }
    
    auto& auth = *auth_res;
    auto& db = auth.db();
    
    auto users = db.list_users();
    if (!users.empty())
    {
        return "Database initialized; users already exist, skipping admin creation";
    }
    
    if (auto res = auth::check_password(*admin_pass, *admin_user); !res)
    {
        return std::unexpected(res.error());
    }
    
    if (!auth.register_user(*admin_user, *admin_pass))
    {
        return std::unexpected("Failed to create admin user");
    }
    
    return std::format("Database initialized; admin user '{}' created", *admin_user);
}

[[nodiscard]] inline Result cmd_add(auth::AuthManager& auth, std::string_view user, std::string_view pass)
{
    if (auto res = auth::check_password(pass, user); !res)
    {
        return std::unexpected(res.error());
    }
    
    if (!auth.register_user(user, pass))
    {
        return std::unexpected("Failed to create user (may already exist)");
    }
    
    return std::format("User '{}' created", user);
}

[[nodiscard]] inline Result cmd_list(auth::UserDB& db)
{
    auto users = db.list_users();
    if (users.empty())
    {
        return "No users found";
    }
    
    std::println("{:<20} {:<10} {}", "Username", "Status", "Last Login");
    std::println("{}", std::string(50, '-'));
    
    for (const auto& u : users)
    {
        auto status = u.active ? "active" : "disabled";
        auto last = u.last_login == 0 ? "never" : std::to_string(u.last_login);
        std::println("{:<20} {:<10} {}", u.username, status, last);
    }
    
    return "";
}

[[nodiscard]] inline Result cmd_disable(auth::UserDB& db, std::string_view user)
{
    if (!db.deactivate_user(user))
    {
        return std::unexpected("Failed to disable user (not found)");
    }
    
    return std::format("User '{}' disabled", user);
}

[[nodiscard]] inline Result cmd_enable(auth::UserDB& db, std::string_view user)
{
    if (!db.activate_user(user))
    {
        return std::unexpected("Failed to enable user (not found)");
    }
    
    return std::format("User '{}' enabled", user);
}

[[nodiscard]] inline Result cmd_reset(auth::UserDB& db, std::string_view user, std::string_view pass)
{
    if (auto res = auth::check_password(pass, user); !res)
    {
        return std::unexpected(res.error());
    }
    
    auto hash_res = auth::Argon2Hasher::hash(pass);
    if (!hash_res)
    {
        return std::unexpected("Failed to hash password");
    }
    
    if (!db.update_password(user, hash_res->encoded))
    {
        return std::unexpected("Failed to reset password (user not found)");
    }
    
    return std::format("Password reset for '{}'", user);
}

[[nodiscard]] inline Result cmd_kick(auth::UserDB& db, std::string_view user)
{
    if (!db.set_current_conn(user, ""))
    {
        return std::unexpected("Failed to clear connection (user not found)");
    }
    
    return std::format("User '{}' connection cleared", user);
}

[[nodiscard]] inline Result cmd_remove(auth::UserDB& db, std::string_view user)
{
    if (!db.delete_user(user))
    {
        return std::unexpected("Failed to remove user (not found or database error)");
    }
    
    return std::format("User '{}' permanently removed", user);
}

}
