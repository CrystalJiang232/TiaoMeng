#pragma once

#include <string>
#include <cstdint>
#include <expected>
#include <optional>

namespace auth
{

struct UserRecord
{
    std::string username;
    std::string password_hash;
    int64_t created_at;
    int64_t last_login;
    bool active;
    std::optional<std::string> current_conn_id;
    
    std::expected<int, uint64_t> lockout_placeholder;
};

}
