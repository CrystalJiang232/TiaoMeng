#include "crypto/aesgcm256.hpp"
#include <openssl/evp.h>
#include <openssl/crypto.h>

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
        int len = 0;
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

} // namespace crypto
