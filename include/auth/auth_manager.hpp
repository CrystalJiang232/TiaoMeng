#pragma once

#include "auth/user_db.hpp"
#include "auth/argon2_hasher.hpp"
#include "threadpool/threadpool.hpp"
#include <boost/asio.hpp>
#include <expected>
#include <string>
#include <functional>

namespace net = boost::asio;

namespace auth
{

class AuthManager
{
public:
    struct AuthResult
    {
        bool success;
        bool locked;
    };
    
    [[nodiscard]] static std::expected<AuthManager, std::string> create(
        std::string_view db_path, 
        ThreadPool& tp
    );
    
    [[nodiscard]] net::awaitable<AuthResult> verify(
        std::string_view username, 
        std::string_view password
    );
    
    [[nodiscard]] bool register_user(std::string_view username, std::string_view password);
    
    [[nodiscard]] UserDB& db() { return user_db; }

private:
    AuthManager(UserDB db, ThreadPool& tp);
    
    UserDB user_db;
    std::reference_wrapper<ThreadPool> cpu_pool;
};

}
