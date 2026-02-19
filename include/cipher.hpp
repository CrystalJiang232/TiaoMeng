#pragma once
#include <oqs/oqs.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <memory>
#include <vector>
#include <array>
#include <span>
#include <atomic>
#include <optional>

class Kyber768 
{
public:
    using key_t = std::vector<uint8_t>;
    using shared_secret_t = std::array<uint8_t, 32>;
    
    struct keypair_t 
    {
        key_t public_key;
        key_t secret_key;
    };
    
    struct encaps_result_t 
    {
        shared_secret_t shared_secret;
        key_t ciphertext;
    };

    Kyber768();
    ~Kyber768() = default;

    Kyber768(const Kyber768&) = delete;
    Kyber768& operator=(const Kyber768&) = delete;
    Kyber768(Kyber768&&) = default;
    Kyber768& operator=(Kyber768&&) = default;

    [[nodiscard]] std::optional<keypair_t> generate_keypair() const;
    [[nodiscard]] std::optional<encaps_result_t> encapsulate(std::span<const uint8_t> remote_pk) const;
    [[nodiscard]] std::optional<shared_secret_t> decapsulate(
        std::span<const uint8_t> ciphertext, 
        std::span<const uint8_t> secret_key
    ) const;

    [[nodiscard]] static std::array<uint8_t, 32> combine_secrets(
        std::span<const uint8_t> secret_a, 
        std::span<const uint8_t> secret_b
    );

    static constexpr size_t public_key_size = 1184;
    static constexpr size_t secret_key_size = 2400;
    static constexpr size_t ciphertext_size = 1088;
    static constexpr size_t shared_secret_size = 32;

private:
    std::unique_ptr<OQS_KEM, decltype(&OQS_KEM_free)> kem;
};

class SessionKey 
{
public:
    using key_t = std::array<uint8_t, 32>;
    
    SessionKey() = default;
    
    void init_local(const Kyber768::keypair_t& kp);
    void complete_handshake(
        std::span<const uint8_t> local_secret,
        std::span<const uint8_t> remote_secret
    );
    
    [[nodiscard]] bool is_established() const { return ready; }
    [[nodiscard]] std::span<const uint8_t> key() const { return std::span(key_); }
    
    [[nodiscard]] std::optional<std::vector<uint8_t>> encrypt(std::span<const uint8_t> plaintext);
    [[nodiscard]] std::optional<std::vector<uint8_t>> decrypt(std::span<const uint8_t> ciphertext);
    
    void clear();

private:
    key_t key_;
    bool ready = false;
    std::atomic<uint64_t> nonce_ctr{0};
};

template<class T>
void secure_clear(T& cont)
{
    if constexpr (requires { cont.data(); cont.size(); })
    {
        OPENSSL_cleanse(cont.data(), cont.size());
    }
    else
    {
        OPENSSL_cleanse(std::addressof(cont), sizeof(cont));
    }
}

namespace crypto
{

class AES256GCM
{
public:
    static constexpr size_t key_sz = 32;
    static constexpr size_t nonce_sz = 12;
    static constexpr size_t tag_sz = 16;
    
    struct ciphertext_t
    {
        std::vector<uint8_t> data;
        std::array<uint8_t, tag_sz> tag;
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

}
