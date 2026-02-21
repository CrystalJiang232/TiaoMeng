find_library(OQS_LIB oqs REQUIRED PATHS /usr/local/lib)
find_package(OpenSSL REQUIRED)

add_library(crypto STATIC
    kyber768.cpp
    aesgcm256.cpp
    session_key.cpp
)

target_include_directories(crypto PUBLIC
    ${CMAKE_SOURCE_DIR}/include
    /usr/local/include
)

target_link_libraries(crypto PUBLIC
    ${OQS_LIB}
    OpenSSL::Crypto
    fundamentals
)
