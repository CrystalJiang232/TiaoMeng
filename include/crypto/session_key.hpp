#pragma once
#include "crypto/aesgcm256.hpp"
#include "crypto/kyber768.hpp"
#include "crypto/utils.hpp"
#include <atomic>
#include <optional>
#include <chrono>
#include <span>
#include <vector>

namespace crypto
{

    class SessionKey
    {
    public:
        using key_t        = std::array<uint8_t, 32>;
        using clock_t      = std::chrono::steady_clock;
        using time_point_t = clock_t::time_point;

        SessionKey(std::span<const uint8_t> local_secret, std::span<const uint8_t> remote_secret);
        ~SessionKey();

        SessionKey(const SessionKey&)            = delete;
        SessionKey& operator=(const SessionKey&) = delete;
        SessionKey(SessionKey&&)                 = delete;
        SessionKey& operator=(SessionKey&&)      = delete;

        [[nodiscard]]
        time_point_t update_timepoint() const
        {
            return update_tp;
        }

        [[nodiscard]]
        std::span<const uint8_t> key() const
        {
            return std::span(ky);
        }

        // Does not validates key lifetime, keep validation in connection-layer
        [[nodiscard]]
        std::optional<std::vector<uint8_t>> encrypt(std::span<const uint8_t> plaintext);
        // Does not validates key lifetime, keep validation in connection-layer
        [[nodiscard]]
        std::optional<std::vector<uint8_t>> decrypt(std::span<const uint8_t> ciphertext);

        void reset_nonce();

    private:
        key_t                 ky;
        time_point_t          update_tp;
        std::atomic<uint64_t> nonce_ctr{0};
    };

} // namespace crypto
