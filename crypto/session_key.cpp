#include "crypto/session_key.hpp"
#include "crypto/utils.hpp"
#include <openssl/rand.h>
#include <ranges>
#include <bit>

namespace crypto
{

void SessionKey::complete_handshake(
    std::span<const uint8_t> local_secret,
    std::span<const uint8_t> remote_secret)
{
    ky = Kyber768::combine_secrets(local_secret, remote_secret);
    ready = true;
}

void SessionKey::reset_nonce()
{
    // Generate random 64-bit value for nonce counter
    // This randomizes the starting point while maintaining sequential increments
    std::array<uint8_t, 8> random_bytes{};
    if (RAND_bytes(random_bytes.data(), static_cast<int>(random_bytes.size())) == 1)
    {
        uint64_t random_ctr = 0;
        for (size_t i = 0; i < 8; ++i)
        {
            random_ctr = (random_ctr << 8) | random_bytes[i];
        }
        nonce_ctr.store(random_ctr);
    }
    // If RAND_bytes fails, counter continues from current value (degraded but safe)
}

std::optional<std::vector<uint8_t>> SessionKey::encrypt(std::span<const uint8_t> plaintext)
{
    if (!ready)
    {
        return std::nullopt;
    }
    
    uint64_t ctr = nonce_ctr.fetch_add(1);
    AES256GCM::nonce_t nonce{};
    
    // First 4 bytes are zero, last 8 bytes are big-endian counter
    for (size_t i = 0; i < 4; ++i)
    {
        nonce[i] = 0;
    }
    for (size_t i = 0; i < 8; ++i)
    {
        nonce[4 + i] = static_cast<uint8_t>((ctr >> (56 - i * 8)) & 0xFF);
    }

    auto ct_result = AES256GCM::encrypt(ky, nonce, plaintext);
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
    if (!ready || ciphertext.size() < AES256GCM::nonce_sz + AES256GCM::tag_sz)
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
    
    AES256GCM::nonce_t nonce{};
    std::ranges::copy(nonce_view, nonce.begin());
    
    AES256GCM::ciphertext_t ct{};
    ct.data = data_view | std::ranges::to<AES256GCM::data_t>();
    std::ranges::copy(tag_view, ct.tag.begin());
    
    return AES256GCM::decrypt(ky, nonce, ct);
}

void SessionKey::clear()
{
    secure_clear(ky);
    ready = false;
    nonce_ctr.store(0);
}

} // namespace crypto
