#include "cipher.hpp"
#include "helper.hpp"
#include <openssl/evp.h>
#include <openssl/crypto.h>
#include <algorithm>
#include <bit>
#include <memory>
#include <utility>
#include <cstring>


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

void SessionKey::init_local(const Kyber768::keypair_t& kp)
{
    (void)kp;
}

void SessionKey::complete_handshake(
    std::span<const uint8_t> local_secret,
    std::span<const uint8_t> remote_secret)
{
    key_ = Kyber768::combine_secrets(local_secret, remote_secret);
    ready = true;
}

std::optional<std::vector<uint8_t>> SessionKey::encrypt(std::span<const uint8_t> plaintext)
{
    if (!ready)
    {
        return std::nullopt;
    }
    
    uint64_t ctr = nonce_ctr.fetch_add(1);
    crypto::AES256GCM::nonce_t nonce{};
    
    Hibiscus::from_int<uint8_t>(nonce | std::views::drop(4), ctr);

    auto ct_result = crypto::AES256GCM::encrypt(key_, nonce, plaintext);
    if (!ct_result)
    {
        return std::nullopt;
    }
    
    std::vector<uint8_t> res;
    res.reserve(nonce.size() + ct_result->data.size() + ct_result->tag.size());

    auto ist = std::back_inserter(res);
    std::ranges::copy(nonce, ist);
    std::ranges::copy(ct_result->data, ist);
    std::ranges::copy(ct_result->tag, ist);
    
    return res;
}

std::optional<std::vector<uint8_t>> SessionKey::decrypt(std::span<const uint8_t> ciphertext)
{
    using namespace crypto;
    if (!ready || ciphertext.size() < 28)
    {
        return std::nullopt;
    }

    auto cp_view = ciphertext | std::views::all;
    
    auto nonce_view = cp_view.subspan(0, AES256GCM::nonce_sz);
    cp_view = cp_view.subspan(AES256GCM::nonce_sz);
    
    size_t data_sz = ciphertext.size() - (AES256GCM::nonce_sz + AES256GCM::tag_sz);
    auto data_view = cp_view.subspan(0, data_sz);
    cp_view = cp_view.subspan(data_sz);

    auto tag_view = cp_view.subspan(0, AES256GCM::tag_sz);
    cp_view = cp_view.subspan(AES256GCM::tag_sz);
    //cp_view should be empty right now
    
    AES256GCM::nonce_t nonce{};
    std::ranges::copy(nonce_view, nonce.begin());
    
    AES256GCM::ciphertext_t ct{};
    ct.data = data_view | std::ranges::to<AES256GCM::data_t>();
    std::ranges::copy(tag_view, ct.tag.begin());
    
    return crypto::AES256GCM::decrypt(key_, nonce, ct);
}

void SessionKey::clear()
{
    OPENSSL_cleanse(key_.data(), key_.size());
    ready = false;
    nonce_ctr.store(0);
}

namespace crypto
{

bool AES256GCM::chk_sz(std::span<const uint8_t> key, std::span<const uint8_t> nonce)
{
    return key.size() == key_sz && nonce.size() == nonce_sz;
}

std::optional<AES256GCM::ciphertext_t> AES256GCM::encrypt(
    std::span<const uint8_t> key,
    std::span<const uint8_t> nonce,
    std::span<const uint8_t> plaintext,
    std::span<const uint8_t> aad)
{
    if (!chk_sz(key, nonce))
    {
        return std::nullopt;
    }
    
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        return std::nullopt;
    }
    
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return std::nullopt;
    }
    
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(nonce.size()), nullptr) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return std::nullopt;
    }
    
    if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data()) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return std::nullopt;
    }
    
    if (!aad.empty())
    {
        int len;
        if (EVP_EncryptUpdate(ctx, nullptr, std::addressof(len), aad.data(), static_cast<int>(aad.size())) != 1)
        {
            EVP_CIPHER_CTX_free(ctx);
            return std::nullopt;
        }
    }
    
    ciphertext_t result;
    result.data.resize(plaintext.size());
    
    int len = 0;
    if (EVP_EncryptUpdate(ctx, result.data.data(), std::addressof(len), plaintext.data(), static_cast<int>(plaintext.size())) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return std::nullopt;
    }
    
    int final_len = 0;
    if (EVP_EncryptFinal_ex(ctx, result.data.data() + len, std::addressof(final_len)) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return std::nullopt;
    }
    
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, static_cast<int>(result.tag.size()), result.tag.data()) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return std::nullopt;
    }
    
    EVP_CIPHER_CTX_free(ctx);
    return result;
}

std::optional<std::vector<uint8_t>> AES256GCM::decrypt(
    std::span<const uint8_t> key,
    std::span<const uint8_t> nonce,
    const ciphertext_t& ct,
    std::span<const uint8_t> aad)
{
    if (!chk_sz(key, nonce))
    {
        return std::nullopt;
    }
    
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
    {
        return std::nullopt;
    }
    
    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return std::nullopt;
    }
    
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(nonce.size()), nullptr) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return std::nullopt;
    }
    
    if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce.data()) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return std::nullopt;
    }
    
    if (!aad.empty())
    {
        int len = 0;
        if (EVP_DecryptUpdate(ctx, nullptr, std::addressof(len), aad.data(), static_cast<int>(aad.size())) != 1)
        {
            EVP_CIPHER_CTX_free(ctx);
            return std::nullopt;
        }
    }
    
    std::vector<uint8_t> plaintext;
    plaintext.resize(ct.data.size());
    
    int len = 0;
    if (EVP_DecryptUpdate(ctx, plaintext.data(), std::addressof(len), ct.data.data(), static_cast<int>(ct.data.size())) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return std::nullopt;
    }
    
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, static_cast<int>(ct.tag.size()), const_cast<uint8_t*>(ct.tag.data())) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return std::nullopt;
    }
    
    int final_len = 0;
    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, std::addressof(final_len)) != 1)
    {
        EVP_CIPHER_CTX_free(ctx);
        return std::nullopt;
    }
    
    EVP_CIPHER_CTX_free(ctx);
    return plaintext;
}

}
