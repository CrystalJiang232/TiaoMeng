#include "auth/argon2_hasher.hpp"

#include <sodium.h>
#include <array>
#include <algorithm>
#include <ranges>

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

bool check_password(std::string_view password)
{
    return password.size() >= 8;
}

}
