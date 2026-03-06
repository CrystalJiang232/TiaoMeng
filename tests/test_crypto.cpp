#include <catch2/catch_test_macros.hpp>

#include "crypto/kyber768.hpp"
#include "crypto/aesgcm256.hpp"
#include "crypto/session_key.hpp"

#include <array>
#include <vector>
#include <span>

using namespace crypto;

TEST_CASE("Kyber768 generates valid keypair")
{
    Kyber768 kem;
    auto kp = kem.generate_keypair();
    
    REQUIRE(kp.has_value());
    CHECK(kp->public_key.size() == Kyber768::public_key_size);
    CHECK(kp->secret_key.size() == Kyber768::secret_key_size);
}

TEST_CASE("Kyber768 encapsulate produces valid ciphertext")
{
    Kyber768 kem;
    auto kp = kem.generate_keypair();
    
    REQUIRE(kp.has_value());
    auto enc = kem.encapsulate(kp->public_key);
    
    REQUIRE(enc.has_value());
    CHECK(enc->ciphertext.size() == Kyber768::ciphertext_size);
    CHECK(enc->shared_secret.size() == Kyber768::shared_secret_size);
}

TEST_CASE("Kyber768 decapsulate recovers shared secret")
{
    Kyber768 kem_alice;
    Kyber768 kem_bob;
    
    auto kp = kem_alice.generate_keypair();
    REQUIRE(kp.has_value());
    
    auto enc = kem_bob.encapsulate(kp->public_key);
    REQUIRE(enc.has_value());
    
    auto ss = kem_alice.decapsulate(enc->ciphertext, kp->secret_key);
    
    REQUIRE(ss.has_value());
    CHECK(*ss == enc->shared_secret);
}

TEST_CASE("Kyber768 combine_secrets produces deterministic output")
{
    std::array<uint8_t, 32> secret_a{};
    std::array<uint8_t, 32> secret_b{};
    secret_a.fill(0xAA);
    secret_b.fill(0xBB);
    
    auto combined1 = Kyber768::combine_secrets(secret_a, secret_b);
    auto combined2 = Kyber768::combine_secrets(secret_a, secret_b);
    
    CHECK(combined1 == combined2);
}

TEST_CASE("Kyber768 full handshake establishes identical keys")
{
    Kyber768 client_kem;
    Kyber768 server_kem;
    
    auto client_kp = client_kem.generate_keypair();
    REQUIRE(client_kp.has_value());
    
    auto server_enc = server_kem.encapsulate(client_kp->public_key);
    REQUIRE(server_enc.has_value());
    
    auto client_ss = client_kem.decapsulate(server_enc->ciphertext, client_kp->secret_key);
    REQUIRE(client_ss.has_value());
    
    CHECK(*client_ss == server_enc->shared_secret);
}

TEST_CASE("AES256GCM encrypt produces ciphertext with authentication tag")
{
    std::array<uint8_t, 32> key{};
    std::array<uint8_t, 12> nonce{};
    std::vector<uint8_t> plaintext{0x01, 0x02, 0x03, 0x04};
    
    key.fill(0xAB);
    nonce.fill(0xCD);
    
    auto ct = AES256GCM::encrypt(key, nonce, plaintext);
    
    REQUIRE(ct.has_value());
    CHECK(ct->data.size() == plaintext.size());
    CHECK(ct->tag.size() == AES256GCM::tag_sz);
}

TEST_CASE("AES256GCM decrypt recovers original plaintext")
{
    std::array<uint8_t, 32> key{};
    std::array<uint8_t, 12> nonce{};
    std::vector<uint8_t> plaintext{0x48, 0x65, 0x6C, 0x6C, 0x6F};
    
    key.fill(0x12);
    nonce.fill(0x34);
    
    auto ct = AES256GCM::encrypt(key, nonce, plaintext);
    REQUIRE(ct.has_value());
    
    auto recovered = AES256GCM::decrypt(key, nonce, *ct);
    
    REQUIRE(recovered.has_value());
    CHECK(*recovered == plaintext);
}

TEST_CASE("AES256GCM decrypt detects tampered ciphertext")
{
    std::array<uint8_t, 32> key{};
    std::array<uint8_t, 12> nonce{};
    std::vector<uint8_t> plaintext{0x01, 0x02, 0x03};
    
    key.fill(0x45);
    nonce.fill(0x67);
    
    auto ct = AES256GCM::encrypt(key, nonce, plaintext);
    REQUIRE(ct.has_value());
    
    ct->data[0] ^= 0xFF;
    auto recovered = AES256GCM::decrypt(key, nonce, *ct);
    
    CHECK(!recovered.has_value());
}

TEST_CASE("AES256GCM decrypt detects tampered authentication tag")
{
    std::array<uint8_t, 32> key{};
    std::array<uint8_t, 12> nonce{};
    std::vector<uint8_t> plaintext{0x01, 0x02, 0x03};
    
    key.fill(0x89);
    nonce.fill(0xAB);
    
    auto ct = AES256GCM::encrypt(key, nonce, plaintext);
    REQUIRE(ct.has_value());
    
    ct->tag[0] ^= 0xFF;
    auto recovered = AES256GCM::decrypt(key, nonce, *ct);
    
    CHECK(!recovered.has_value());
}

TEST_CASE("AES256GCM large payload encryption roundtrip")
{
    std::array<uint8_t, 32> key{};
    std::array<uint8_t, 12> nonce{};
    std::vector<uint8_t> plaintext(65536, 0x42);
    
    key.fill(0xDE);
    nonce.fill(0xAD);
    
    auto ct = AES256GCM::encrypt(key, nonce, plaintext);
    REQUIRE(ct.has_value());
    CHECK(ct->data.size() == plaintext.size());
    
    auto recovered = AES256GCM::decrypt(key, nonce, *ct);
    REQUIRE(recovered.has_value());
    CHECK(*recovered == plaintext);
}

TEST_CASE("SessionKey initial state is not established")
{
    SessionKey sess;
    CHECK(sess.is_established() == false);
}

TEST_CASE("SessionKey complete_handshake establishes key material")
{
    SessionKey sess;
    std::array<uint8_t, 32> local{};
    std::array<uint8_t, 32> remote{};
    
    local.fill(0x11);
    remote.fill(0x22);
    
    sess.complete_handshake(local, remote);
    
    CHECK(sess.is_established() == true);
    CHECK(sess.key().size() == 32);
}

TEST_CASE("SessionKey encrypt requires established state")
{
    SessionKey sess;
    std::vector<uint8_t> plaintext{0x01, 0x02};
    
    auto ct = sess.encrypt(plaintext);
    CHECK(!ct.has_value());
}

TEST_CASE("SessionKey decrypt requires established state")
{
    SessionKey sess;
    std::vector<uint8_t> ciphertext{0x01, 0x02, 0x03, 0x04};
    
    auto pt = sess.decrypt(ciphertext);
    CHECK(!pt.has_value());
}

TEST_CASE("SessionKey encrypt decrypt roundtrip preserves data")
{
    SessionKey sess;
    std::array<uint8_t, 32> local{};
    std::array<uint8_t, 32> remote{};
    
    local.fill(0x33);
    remote.fill(0x44);
    
    sess.complete_handshake(local, remote);
    
    std::vector<uint8_t> plaintext{0x48, 0x65, 0x6C, 0x6C, 0x6F};
    auto ct = sess.encrypt(plaintext);
    REQUIRE(ct.has_value());
    
    auto recovered = sess.decrypt(*ct);
    REQUIRE(recovered.has_value());
    CHECK(*recovered == plaintext);
}

TEST_CASE("SessionKey multiple messages use unique nonces")
{
    SessionKey sess;
    std::array<uint8_t, 32> local{};
    std::array<uint8_t, 32> remote{};
    
    local.fill(0x55);
    remote.fill(0x66);
    sess.complete_handshake(local, remote);
    
    std::vector<uint8_t> msg1{0x01, 0x02};
    std::vector<uint8_t> msg2{0x03, 0x04};
    
    auto ct1 = sess.encrypt(msg1);
    auto ct2 = sess.encrypt(msg2);
    
    REQUIRE(ct1.has_value());
    REQUIRE(ct2.has_value());
    
    auto recovered1 = sess.decrypt(*ct1);
    auto recovered2 = sess.decrypt(*ct2);
    
    REQUIRE(recovered1.has_value());
    REQUIRE(recovered2.has_value());
    CHECK(*recovered1 == msg1);
    CHECK(*recovered2 == msg2);
}

TEST_CASE("SessionKey clear resets established state")
{
    SessionKey sess;
    std::array<uint8_t, 32> local{};
    std::array<uint8_t, 32> remote{};
    
    local.fill(0x77);
    remote.fill(0x88);
    
    sess.complete_handshake(local, remote);
    CHECK(sess.is_established() == true);
    
    sess.clear();
    
    CHECK(sess.is_established() == false);
}
