#pragma once
#include <oqs/oqs.h>
#include <memory>
#include <vector>
#include <array>
#include <span>

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

    // Non-copyable, movable
    Kyber768(const Kyber768&) = delete;
    Kyber768& operator=(const Kyber768&) = delete;
    Kyber768(Kyber768&&) = default;
    Kyber768& operator=(Kyber768&&) = default;

    // Generate a new keypair (for this side)
    [[nodiscard]] std::optional<keypair_t> generate_keypair() const;
    
    // Encapsulate to a remote public key, returns (shared_secret, ciphertext)
    [[nodiscard]] std::optional<encaps_result_t> encapsulate(std::span<const uint8_t> remote_pk) const;
    
    // Decapsulate a ciphertext using local secret key
    [[nodiscard]] std::optional<shared_secret_t> decapsulate(
        std::span<const uint8_t> ciphertext, 
        std::span<const uint8_t> secret_key
    ) const;

    // Combine two shared secrets into a single symmetric key (for bidirectional KEM)
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

// Session key manager for bidirectional KEM
class SessionKey 
{
public:
    using key_t = std::array<uint8_t, 32>;
    
    SessionKey() = default;
    
    // Initialize with local keypair (called at connection start)
    void init_local(const Kyber768::keypair_t& kp);
    
    // Complete handshake with remote encapsulation result
    void complete_handshake(
        std::span<const uint8_t> local_secret,  // from decapsulating remote's ciphertext
        std::span<const uint8_t> remote_secret  // from encapsulating to remote's pubkey
    );
    
    [[nodiscard]] bool is_established() const { return ready; }
    [[nodiscard]] std::span<const uint8_t> key() const { return std::span(key_); }
    
    void clear();

private:
    key_t key_;
    bool ready = false;
};
