#include "crypto/kyber768.hpp"
#include "crypto/utils.hpp"
#include <openssl/evp.h>
#include <algorithm>
#include <cstring>

namespace crypto
{

Kyber768::Kyber768()
    : kem(OQS_KEM_new("Kyber768"), OQS_KEM_free)
{
    if (!kem)
    {
        throw std::runtime_error("Kyber768 not available");
    }
}

std::optional<Kyber768::keypair_t> Kyber768::generate_keypair() const
{
    keypair_t kp;
    kp.public_key.resize(public_key_size);
    kp.secret_key.resize(secret_key_size);
    
    if (OQS_KEM_keypair(kem.get(), kp.public_key.data(), kp.secret_key.data()) != OQS_SUCCESS)
    {
        return std::nullopt;
    }
    return kp;
}

std::optional<Kyber768::encaps_result_t> Kyber768::encapsulate(std::span<const uint8_t> remote_pk) const
{
    if (remote_pk.size() != public_key_size)
    {
        return std::nullopt;
    }
    
    encaps_result_t result;
    result.ciphertext.resize(ciphertext_size);
    
    if (OQS_KEM_encaps(
            kem.get(),
            result.ciphertext.data(),
            result.shared_secret.data(),
            remote_pk.data()) != OQS_SUCCESS)
    {
        return std::nullopt;
    }
    return result;
}

std::optional<Kyber768::shared_secret_t> Kyber768::decapsulate(
    std::span<const uint8_t> ciphertext,
    std::span<const uint8_t> secret_key) const
{
    if (ciphertext.size() != ciphertext_size || secret_key.size() != secret_key_size)
    {
        return std::nullopt;
    }
    
    shared_secret_t shared_secret;
    if (OQS_KEM_decaps(
            kem.get(),
            shared_secret.data(),
            ciphertext.data(),
            secret_key.data()) != OQS_SUCCESS)
    {
        return std::nullopt;
    }
    return shared_secret;
}

Kyber768::shared_secret_t Kyber768::combine_secrets(
    std::span<const uint8_t> secret_a,
    std::span<const uint8_t> secret_b)
{
    std::array<uint8_t, 64> combined{};
    std::copy_n(secret_a.begin(), std::min(secret_a.size(), shared_secret_size), combined.begin());
    std::copy_n(secret_b.begin(), std::min(secret_b.size(), shared_secret_size), combined.begin() + shared_secret_size);

    shared_secret_t result{};
    
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx)
    {
        return result;
    }
    
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) == 1 &&
        EVP_DigestUpdate(ctx, combined.data(), combined.size()) == 1 &&
        EVP_DigestFinal_ex(ctx, result.data(), nullptr) == 1)
    {
    }
    
    EVP_MD_CTX_free(ctx);
    return result;
}

} // namespace crypto
