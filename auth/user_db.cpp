#include "auth/user_db.hpp"

#include <ctime>

namespace auth
{

std::expected<UserDB, std::string> UserDB::open(std::string_view db_path)
{
    sqlite3* handle = nullptr;
    int rc = sqlite3_open(std::string(db_path).c_str(), &handle);
    if (rc != SQLITE_OK)
    {
        std::string err = sqlite3_errmsg(handle);
        sqlite3_close(handle);
        return std::unexpected(err);
    }
    
    UserDB db(handle);
    
    sqlite3_exec(handle, "PRAGMA journal_mode=WAL;", nullptr, nullptr, nullptr);
    sqlite3_exec(handle, "PRAGMA synchronous=NORMAL;", nullptr, nullptr, nullptr);
    sqlite3_exec(handle, "PRAGMA foreign_keys=ON;", nullptr, nullptr, nullptr);
    
    return db;
}

UserDB::UserDB(sqlite3* handle)
    : db(handle)
{
}

UserDB::~UserDB()
{
    if (db)
    {
        sqlite3_close(db);
    }
}

UserDB::UserDB(UserDB&& other) noexcept
    : db(other.db)
{
    other.db = nullptr;
}

UserDB& UserDB::operator=(UserDB&& other) noexcept
{
    if (this != &other)
    {
        if (db) sqlite3_close(db);
        db = other.db;
        other.db = nullptr;
    }
    return *this;
}

bool UserDB::init_schema()
{
    const char* sql = R"(
        CREATE TABLE IF NOT EXISTS users (
            username TEXT PRIMARY KEY,
            password_hash TEXT NOT NULL,
            created_at INTEGER DEFAULT (strftime('%s', 'now')),
            last_login INTEGER DEFAULT 0,
            active INTEGER DEFAULT 1,
            failed_attempts INTEGER DEFAULT 0,
            locked_until INTEGER DEFAULT 0
        ) WITHOUT ROWID;
        
        CREATE INDEX IF NOT EXISTS idx_users_active ON users(active) WHERE active = 1;
    )";
    
    char* err = nullptr;
    int rc = sqlite3_exec(db, sql, nullptr, nullptr, std::addressof(err));
    if (rc != SQLITE_OK && err)
    {
        sqlite3_free(err);
        return false;
    }
    return rc == SQLITE_OK;
}

bool UserDB::create_user(std::string_view username, std::string_view password_hash)
{
    const char* sql = "INSERT INTO users (username, password_hash) VALUES (?, ?);";
    sqlite3_stmt* stmt = nullptr;
    
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK)
    {
        return false;
    }
    
    sqlite3_bind_text(stmt, 1, username.data(), static_cast<int>(username.size()), SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, password_hash.data(), static_cast<int>(password_hash.size()), SQLITE_STATIC);
    
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE;
}

std::optional<UserRecord> UserDB::find_user(std::string_view username)
{
    const char* sql = "SELECT username, password_hash, created_at, last_login, active, failed_attempts, locked_until FROM users WHERE username = ? AND active = 1;";
    sqlite3_stmt* stmt = nullptr;
    
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK)
    {
        return std::nullopt;
    }
    
    sqlite3_bind_text(stmt, 1, username.data(), static_cast<int>(username.size()), SQLITE_STATIC);
    
    std::optional<UserRecord> result;
    if (sqlite3_step(stmt) == SQLITE_ROW)
    {
        UserRecord rec;
        rec.username = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        rec.password_hash = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
        rec.created_at = sqlite3_column_int64(stmt, 2);
        rec.last_login = sqlite3_column_int64(stmt, 3);
        rec.active = sqlite3_column_int(stmt, 4) != 0;
        rec.lockout_placeholder = std::expected<int, uint64_t>(0);
        result = std::move(rec);
    }
    
    sqlite3_finalize(stmt);
    return result;
}

bool UserDB::update_last_login(std::string_view username)
{
    const char* sql = "UPDATE users SET last_login = ? WHERE username = ?;";
    sqlite3_stmt* stmt = nullptr;
    
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK)
    {
        return false;
    }
    
    sqlite3_bind_int64(stmt, 1, std::time(nullptr));
    sqlite3_bind_text(stmt, 2, username.data(), static_cast<int>(username.size()), SQLITE_STATIC);
    
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE;
}

bool UserDB::deactivate_user(std::string_view username)
{
    const char* sql = "UPDATE users SET active = 0 WHERE username = ?;";
    sqlite3_stmt* stmt = nullptr;
    
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK)
    {
        return false;
    }
    
    sqlite3_bind_text(stmt, 1, username.data(), static_cast<int>(username.size()), SQLITE_STATIC);
    
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE;
}

bool UserDB::record_failed_attempt(std::string_view username)
{
    const char* sql = "UPDATE users SET failed_attempts = failed_attempts + 1 WHERE username = ?;";
    sqlite3_stmt* stmt = nullptr;
    
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK)
    {
        return false;
    }
    
    sqlite3_bind_text(stmt, 1, username.data(), static_cast<int>(username.size()), SQLITE_STATIC);
    
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE;
}

bool UserDB::clear_failed_attempts(std::string_view username)
{
    const char* sql = "UPDATE users SET failed_attempts = 0, locked_until = 0 WHERE username = ?;";
    sqlite3_stmt* stmt = nullptr;
    
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK)
    {
        return false;
    }
    
    sqlite3_bind_text(stmt, 1, username.data(), static_cast<int>(username.size()), SQLITE_STATIC);
    
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE;
}

bool UserDB::set_current_conn(std::string_view username, std::string_view conn_id)
{
    const char* sql = "UPDATE users SET current_conn_id = ? WHERE username = ?;";
    sqlite3_stmt* stmt = nullptr;
    
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK)
    {
        return false;
    }
    
    sqlite3_bind_text(stmt, 1, conn_id.data(), static_cast<int>(conn_id.size()), SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, username.data(), static_cast<int>(username.size()), SQLITE_STATIC);
    
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE;
}

std::optional<std::string> UserDB::get_current_conn(std::string_view username)
{
    const char* sql = "SELECT current_conn_id FROM users WHERE username = ? AND active = 1;";
    sqlite3_stmt* stmt = nullptr;
    
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK)
    {
        return std::nullopt;
    }
    
    sqlite3_bind_text(stmt, 1, username.data(), static_cast<int>(username.size()), SQLITE_STATIC);
    
    std::optional<std::string> result;
    if (sqlite3_step(stmt) == SQLITE_ROW)
    {
        const char* val = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
        if (val)
        {
            result = std::string(val);
        }
    }
    
    sqlite3_finalize(stmt);
    return result;
}

bool UserDB::clear_conn_id_if_matches(std::string_view username, std::string_view conn_id)
{
    const char* sql = "UPDATE users SET current_conn_id = NULL WHERE username = ? AND current_conn_id = ?;";
    sqlite3_stmt* stmt = nullptr;
    
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK)
    {
        return false;
    }
    
    sqlite3_bind_text(stmt, 1, username.data(), static_cast<int>(username.size()), SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, conn_id.data(), static_cast<int>(conn_id.size()), SQLITE_STATIC);
    
    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE;
}

}
