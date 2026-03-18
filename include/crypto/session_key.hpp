#pragma once
#include "crypto/aesgcm256.hpp"
#include "crypto/kyber768.hpp"
#include <atomic>
#include <optional>
#include <chrono>

namespace crypto
{

enum class KeyStat : uint8_t
{
    None = 0,
    Active,
    Expired
};

class SessionKey
{
public:
    using key_t = std::array<uint8_t, 32>;
    using clock_t = std::chrono::steady_clock;
    using time_point_t = clock_t::time_point;

    SessionKey() = default;
    
    void complete_handshake(
        std::span<const uint8_t> local_secret,
        std::span<const uint8_t> remote_secret
    );
    
    [[nodiscard]] bool is_established() const { return last_update.has_value(); }
    [[nodiscard]] bool valid() const {return status() == KeyStat::Active;}
    [[nodiscard]] KeyStat status() const {return last_update.has_value() ? 
        *last_update + KEY_LIFETIME >= clock_t::now() ? KeyStat::Active : KeyStat::Expired : 
        KeyStat::None;}
    [[nodiscard]] std::span<const uint8_t> key() const { return std::span(ky); }
    
    [[nodiscard]] std::optional<std::vector<uint8_t>> encrypt(std::span<const uint8_t> plaintext);
    [[nodiscard]] std::optional<std::vector<uint8_t>> decrypt(std::span<const uint8_t> ciphertext);
    
    void reset_nonce();
    void clear();

private:
    key_t ky;
    std::optional<time_point_t> last_update;
    std::atomic<uint64_t> nonce_ctr{0};

    static constexpr auto KEY_LIFETIME = std::chrono::seconds(350);
};

} // namespace crypto
