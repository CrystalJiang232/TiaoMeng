#include "auth/auth_manager.hpp"

#include <ctime>

namespace auth
{

std::expected<AuthManager, std::string> AuthManager::create(
    std::string_view db_path, 
    ThreadPool& tp
)
{
    auto db_result = UserDB::open(db_path);
    if (!db_result)
    {
        return std::unexpected(db_result.error());
    }
    
    return AuthManager(std::move(*db_result), tp);
}

AuthManager::AuthManager(UserDB db, ThreadPool& tp)
    : user_db(std::move(db))
    , cpu_pool(tp)
{
}

// Access cpu_pool via cpu_pool.get() when needed

net::awaitable<AuthManager::AuthResult> AuthManager::verify(
    std::string_view username, 
    std::string_view password
)
{
    auto rec_opt = user_db.find_user(username);
    if (!rec_opt)
    {
        co_return AuthResult{false, false};
    }
    
    auto& rec = *rec_opt;
    
    if (!auth::check_password(password))
    {
        co_return AuthResult{false, false};
    }
    
    bool verified = cpu_pool.get().submit([&]() -> bool {
        return Argon2Hasher::verify(password, rec.password_hash);
    }).value_or(false);
    
    if (!verified)
    {
        if(user_db.record_failed_attempt(username))
        {
            //Database exception: ignored for now, decayed to returning false
        }
        co_return AuthResult{false, false};
    }
    
    //if (rec.lockout_placeholder.index() == 1)
    if (!rec.lockout_placeholder) //locked  
    {
        auto now = static_cast<uint64_t>(std::time(nullptr));
        if (rec.lockout_placeholder.error() > now)
        {
            co_return AuthResult{false, true};
        }
    }
    
    if (!user_db.clear_failed_attempts(username) || !user_db.update_last_login(username))
    {
        //Exception handling?  
        //Treat as auth failed FOR NOW  
        co_return AuthResult{false, false};
    }
    
    co_return AuthResult{true, false};
}

bool AuthManager::register_user(std::string_view username, std::string_view password)
{
    if (!auth::check_password(password))
    {
        return false;
    }
    
    auto hash_result = Argon2Hasher::hash(password);
    if (!hash_result)
    {
        return false;
    }
    
    return user_db.create_user(username, hash_result->encoded);
}

}
