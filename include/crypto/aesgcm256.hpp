#pragma once
#include <openssl/evp.h>
#include <vector>
#include <array>
#include <span>
#include <optional>

namespace crypto
{

class AES256GCM
{
public:
    static constexpr size_t key_sz = 32;
    static constexpr size_t nonce_sz = 12;
    static constexpr size_t tag_sz = 16;

    using key_t = std::array<uint8_t, key_sz>;
    using nonce_t = std::array<uint8_t, nonce_sz>;
    using tag_t = std::array<uint8_t, tag_sz>;
    using data_t = std::vector<uint8_t>;
    
    struct ciphertext_t
    {
        data_t data;
        tag_t tag;
    };
    
    static std::optional<ciphertext_t> encrypt(
        std::span<const uint8_t> key,
        std::span<const uint8_t> nonce,
        std::span<const uint8_t> plaintext,
        std::span<const uint8_t> aad = {}
    );
    
    static std::optional<std::vector<uint8_t>> decrypt(
        std::span<const uint8_t> key,
        std::span<const uint8_t> nonce,
        const ciphertext_t& ct,
        std::span<const uint8_t> aad = {}
    );

private:
    static bool chk_sz(std::span<const uint8_t> key, std::span<const uint8_t> nonce);
};

} // namespace crypto
