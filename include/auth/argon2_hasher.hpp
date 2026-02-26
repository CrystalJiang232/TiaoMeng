#pragma once

#include <string>
#include <expected>
#include <cstdint>

namespace auth
{

class Argon2Hasher
{
public:
    struct HashResult
    {
        std::string encoded;
    };
    
    [[nodiscard]] static std::expected<HashResult, std::string> hash(std::string_view password);
    [[nodiscard]] static bool verify(std::string_view password, std::string_view encoded_hash);

private:
    static constexpr uint32_t time_cost = 3;
    static constexpr uint32_t memory_kb = 65536;
    static constexpr uint32_t parallelism = 4;
    static constexpr uint32_t hash_len = 32;
    static constexpr uint32_t salt_len = 16;
};

[[nodiscard]] bool check_password(std::string_view password);

}
