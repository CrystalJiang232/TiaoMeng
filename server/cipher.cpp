#include "cipher.hpp"
#include <openssl/evp.h>
#include <algorithm>

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

std::array<uint8_t, 32> Kyber768::combine_secrets(
    std::span<const uint8_t> secret_a, 
    std::span<const uint8_t> secret_b)
{
    // Use HKDF-like construction: SHA256(s_a || s_b)
    std::array<uint8_t, 64> combined{};
    std::copy_n(secret_a.begin(), std::min(secret_a.size(), size_t{32}), combined.begin());
    std::copy_n(secret_b.begin(), std::min(secret_b.size(), size_t{32}), combined.begin() + 32);

    std::array<uint8_t, 32> result{};
    
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) 
    {
        return result;
    }
    
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) == 1 &&
        EVP_DigestUpdate(ctx, combined.data(), combined.size()) == 1 &&
        EVP_DigestFinal_ex(ctx, result.data(), nullptr) == 1) 
    {
        // success
    }
    
    EVP_MD_CTX_free(ctx);
    return result;
}

// ============================================================================
// SessionKey Implementation
// ============================================================================

void SessionKey::init_local(const Kyber768::keypair_t& kp)
{
    // Store logic if needed; currently session key is derived from shared secrets only
    (void)kp;
}

void SessionKey::complete_handshake(
    std::span<const uint8_t> local_secret,
    std::span<const uint8_t> remote_secret)
{
    key_ = Kyber768::combine_secrets(local_secret, remote_secret);
    ready = true;
}

void SessionKey::clear()
{
    key_.fill(0);
    ready = false;
}
