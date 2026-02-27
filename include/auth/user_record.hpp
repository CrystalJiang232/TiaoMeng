#pragma once

#include <string>
#include <cstdint>
#include <expected>

namespace auth
{

struct UserRecord
{
    std::string username;
    std::string password_hash;
    int64_t created_at;
    int64_t last_login;
    bool active;
    
    std::expected<int, uint64_t> lockout_placeholder;
};

}
