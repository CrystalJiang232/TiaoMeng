#pragma once

#include "auth/user_record.hpp"
#include <sqlite3.h>
#include <expected>
#include <optional>
#include <string>
#include <vector>

namespace auth
{

class UserDB
{
public:
    [[nodiscard]] static std::expected<UserDB, std::string> open(std::string_view db_path);
    ~UserDB();
    
    UserDB(const UserDB&) = delete;
    UserDB& operator=(const UserDB&) = delete;
    UserDB(UserDB&& other) noexcept;
    UserDB& operator=(UserDB&& other) noexcept;
    
    [[nodiscard]] bool init_schema();
    
    [[nodiscard]] bool create_user(std::string_view username, std::string_view password_hash);
    [[nodiscard]] std::optional<UserRecord> find_user(std::string_view username);
    [[nodiscard]] bool update_last_login(std::string_view username);
    [[nodiscard]] bool deactivate_user(std::string_view username);
    
    [[nodiscard]] bool record_failed_attempt(std::string_view username);
    [[nodiscard]] bool clear_failed_attempts(std::string_view username);
    
    [[nodiscard]] bool set_current_conn(std::string_view username, std::string_view conn_id);
    [[nodiscard]] std::optional<std::string> get_current_conn(std::string_view username);
    [[nodiscard]] bool clear_conn_id_if_matches(std::string_view username, std::string_view conn_id);
    
    [[nodiscard]] std::vector<UserRecord> list_users();
    [[nodiscard]] bool activate_user(std::string_view username);
    [[nodiscard]] bool update_password(std::string_view username, std::string_view password_hash);

private:
    explicit UserDB(sqlite3* db);
    sqlite3* db;
};

}
