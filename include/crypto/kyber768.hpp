#pragma once
#include <oqs/oqs.h>
#include <memory>
#include <vector>
#include <array>
#include <span>
#include <optional>

namespace crypto
{

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
    Kyber768(Kyber768&&) noexcept = default;
    Kyber768& operator=(Kyber768&&) noexcept = default;

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

} // namespace crypto
