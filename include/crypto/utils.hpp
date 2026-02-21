#pragma once
#include <openssl/crypto.h>
#include <cstddef>
#include <memory>

namespace crypto
{

template<class T>
void secure_clear(T& cont)
{
    if constexpr (requires { cont.data(); cont.size(); })
    {
        OPENSSL_cleanse(cont.data(), cont.size());
    }
    else
    {
        OPENSSL_cleanse(std::addressof(cont), sizeof(cont));
    }
}

} // namespace crypto
