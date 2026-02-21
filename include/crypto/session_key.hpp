#pragma once
#include "crypto/aesgcm256.hpp"
#include "crypto/kyber768.hpp"
#include <atomic>
#include <optional>

namespace crypto
{

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
    
    void reset_nonce();
    void clear();

private:
    key_t key_;
    bool ready = false;
    std::atomic<uint64_t> nonce_ctr{0};
};

} // namespace crypto
