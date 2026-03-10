#include "auth/argon2_hasher.hpp"

#include <sodium.h>
#include <array>
#include <algorithm>
#include <ranges>
#include <unordered_map>
#include <format>
#include <functional>

namespace auth
{

std::expected<Argon2Hasher::HashResult, std::string> Argon2Hasher::hash(std::string_view password)
{
    if (sodium_init() < 0)
    {
        return std::unexpected("Failed to initialize libsodium");
    }
    
    std::array<char, crypto_pwhash_STRBYTES> encoded;
    int result = crypto_pwhash_str(
        encoded.data(),
        password.data(), password.size(),
        crypto_pwhash_OPSLIMIT_INTERACTIVE,
        crypto_pwhash_MEMLIMIT_INTERACTIVE
    );
    
    if (result != 0)
    {
        return std::unexpected("Failed to hash password");
    }
    
    return HashResult{std::string(encoded.data())};
}

bool Argon2Hasher::verify(std::string_view password, std::string_view encoded_hash)
{
    if (sodium_init() < 0)
    {
        return false;
    }
    
    int result = crypto_pwhash_str_verify(
        encoded_hash.data(),
        password.data(), password.size()
    );
    return result == 0;
}

std::expected<void, std::string> check_password(std::string_view password, std::string_view ref_username)
{
    auto count_chart_fn = [](std::string_view sv) -> size_t
    {
        bool has_lower = false;
        bool has_upper = false;
        bool has_digit = false;
        bool has_symbol = false;
        
        for (unsigned char ch : sv)
        {
            if (std::islower(ch)) has_lower = true;
            else if (std::isupper(ch)) has_upper = true;
            else if (std::isdigit(ch)) has_digit = true;
            else if (std::ispunct(ch) || ch == ' ') has_symbol = true;
        }
        
        return static_cast<size_t>(has_lower) 
            + static_cast<size_t>(has_upper) 
            + static_cast<size_t>(has_digit) 
            + static_cast<size_t>(has_symbol);
    };

    std::vector<std::pair<std::string, bool>> cons
    {
        {"Minimum length: 8 characters",password.size() >= 8},
        {"At least three types of {lowercase, uppercase, number, symbol}", count_chart_fn(password) >= 3},
        {"Does not contain username", ref_username.empty() ? true : !password.contains(ref_username)}
    };

    std::string ret;
    bool pass = true;
    for(auto&& [s, b] : cons)
    {
        ret += std::format("[{}] {}\n",b ? "√" : "×", s);
        pass &= b;
    }

    if(!pass)
    {
        return std::unexpected(ret);
    }

    return {};
}

}
