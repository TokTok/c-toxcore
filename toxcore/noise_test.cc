// clang-format off
#include "../testing/support/public/simulated_environment.hh"
#include "noise.h"
// clang-format on

#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <string>
#include <vector>

#include "crypto_core.h"
#include "crypto_core_test_util.hh"

namespace {

using SecretKey = std::array<std::uint8_t, CRYPTO_SECRET_KEY_SIZE>;

using tox::test::SimulatedEnvironment;

TEST(Noise, HKDF)
{
    SimulatedEnvironment env{12345};
    auto c_rng = env.fake_random().c_random();
    uint8_t chaining_key[CRYPTO_NOISE_BLAKE2B_HASH_SIZE];
    random_bytes(&c_rng, chaining_key, sizeof(chaining_key));

    uint8_t data[32];
    random_bytes(&c_rng, data, sizeof(data));

    uint8_t out1[32], out2[32];
    EXPECT_TRUE(
        noise_hkdf(out1, sizeof(out1), out2, sizeof(out2), data, sizeof(data), chaining_key));

    uint8_t zeros[32] = {0};
    EXPECT_NE(memcmp(out1, zeros, sizeof(out1)), 0);
    EXPECT_NE(memcmp(out2, zeros, sizeof(out2)), 0);
    // Outputs should be different (usually)
    EXPECT_NE(memcmp(out1, out2, sizeof(out1)), 0);
}

TEST(Noise, MixKey)
{
    SimulatedEnvironment env{12345};
    auto c_rng = env.fake_random().c_random();
    PublicKey pk;
    SecretKey sk;
    crypto_new_keypair(&c_rng, pk.data(), sk.data());

    uint8_t chaining_key[CRYPTO_NOISE_BLAKE2B_HASH_SIZE];
    random_bytes(&c_rng, chaining_key, sizeof(chaining_key));

    uint8_t shared_key[CRYPTO_SHARED_KEY_SIZE];

    EXPECT_EQ(noise_mix_key(chaining_key, shared_key, sk.data(), pk.data()), 0);

    uint8_t zeros[CRYPTO_SHARED_KEY_SIZE] = {0};
    EXPECT_NE(memcmp(shared_key, zeros, CRYPTO_SHARED_KEY_SIZE), 0);
}

TEST(Noise, MixHash)
{
    SimulatedEnvironment env{12345};
    auto c_rng = env.fake_random().c_random();
    uint8_t hash[CRYPTO_NOISE_BLAKE2B_HASH_SIZE];
    random_bytes(&c_rng, hash, sizeof(hash));

    uint8_t data[10] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
    uint8_t original_hash[CRYPTO_NOISE_BLAKE2B_HASH_SIZE];
    memcpy(original_hash, hash, sizeof(hash));

    noise_mix_hash(hash, data, sizeof(data));

    EXPECT_NE(memcmp(hash, original_hash, sizeof(hash)), 0);
}

TEST(Noise, MixHashNullData)
{
    SimulatedEnvironment env{12345};
    auto c_rng = env.fake_random().c_random();
    uint8_t hash[CRYPTO_NOISE_BLAKE2B_HASH_SIZE];
    random_bytes(&c_rng, hash, sizeof(hash));

    uint8_t original_hash[CRYPTO_NOISE_BLAKE2B_HASH_SIZE];
    memcpy(original_hash, hash, sizeof(hash));

    // Passing nullptr with length 0 should not crash
    noise_mix_hash(hash, nullptr, 0);

    // The hash state should still be updated (hash(hash || empty))
    EXPECT_NE(memcmp(hash, original_hash, sizeof(hash)), 0);
}

TEST(Noise, EncryptDecryptHash)
{
    SimulatedEnvironment env{12345};
    auto c_rng = env.fake_random().c_random();
    uint8_t shared_key[CRYPTO_SHARED_KEY_SIZE];
    new_symmetric_key(&c_rng, shared_key);

    uint8_t hash[CRYPTO_NOISE_BLAKE2B_HASH_SIZE];
    random_bytes(&c_rng, hash, sizeof(hash));
    uint8_t decrypt_hash[CRYPTO_NOISE_BLAKE2B_HASH_SIZE];
    memcpy(decrypt_hash, hash, sizeof(hash));

    const std::string plaintext = "Noise Message";
    std::vector<uint8_t> ciphertext(plaintext.size() + CRYPTO_MAC_SIZE);
    std::vector<uint8_t> decrypted(plaintext.size());

    noise_encrypt_and_hash(ciphertext.data(), reinterpret_cast<const uint8_t *>(plaintext.data()),
        plaintext.size(), shared_key, hash);

    int len = noise_decrypt_and_hash(
        decrypted.data(), ciphertext.data(), ciphertext.size(), shared_key, decrypt_hash);

    EXPECT_EQ(len, static_cast<int>(plaintext.size()));
    EXPECT_EQ(memcmp(plaintext.data(), decrypted.data(), plaintext.size()), 0);
    // Hashes should be updated identically
    EXPECT_EQ(memcmp(hash, decrypt_hash, sizeof(hash)), 0);
}

TEST(Noise, HandshakeInit)
{
    SimulatedEnvironment env{12345};
    auto c_rng = env.fake_random().c_random();
    Noise_Handshake handshake;

    PublicKey self_pk, peer_pk;
    SecretKey self_sk, peer_sk;
    crypto_new_keypair(&c_rng, self_pk.data(), self_sk.data());
    crypto_new_keypair(&c_rng, peer_pk.data(), peer_sk.data());

    const uint8_t prologue[] = "Prologue";

    // Initiator
    EXPECT_EQ(noise_handshake_init(
                  &handshake, self_pk.data(), peer_pk.data(), true, prologue, sizeof(prologue)),
        0);
    EXPECT_TRUE(handshake.initiator);
    EXPECT_EQ(memcmp(handshake.remote_static, peer_pk.data(), CRYPTO_PUBLIC_KEY_SIZE), 0);

    // Responder
    EXPECT_EQ(noise_handshake_init(
                  &handshake, peer_pk.data(), nullptr, false, prologue, sizeof(prologue)),
        0);
    EXPECT_FALSE(handshake.initiator);
}

// clang-format off
// Noise_IK_25519_ChaChaPoly_BLAKE2b test vectors from:
// https://github.com/rweather/noise-c/blob/cfe25410979a87391bb9ac8d4d4bef64e9f268c6/tests/vector/noise-c-basic.txt

// "init_prologue": "50726f6c6f677565313233" (same as resp_prologue)
static const uint8_t tv_prologue[11] = {
    0x50, 0x72, 0x6f, 0x6c, 0x6f, 0x67, 0x75, 0x65,
    0x31, 0x32, 0x33,
};

// "init_static": "e61ef9919cde45dd5f82166404bd08e38bceb5dfdfded0a34c8df7ed542214d1"
static const uint8_t tv_init_static[CRYPTO_SECRET_KEY_SIZE] = {
    0xe6, 0x1e, 0xf9, 0x91, 0x9c, 0xde, 0x45, 0xdd,
    0x5f, 0x82, 0x16, 0x64, 0x04, 0xbd, 0x08, 0xe3,
    0x8b, 0xce, 0xb5, 0xdf, 0xdf, 0xde, 0xd0, 0xa3,
    0x4c, 0x8d, 0xf7, 0xed, 0x54, 0x22, 0x14, 0xd1,
};

// "init_ephemeral": "893e28b9dc6ca8d611ab664754b8ceb7bac5117349a4439a6b0569da977c464a"
static const uint8_t tv_init_ephemeral[CRYPTO_SECRET_KEY_SIZE] = {
    0x89, 0x3e, 0x28, 0xb9, 0xdc, 0x6c, 0xa8, 0xd6,
    0x11, 0xab, 0x66, 0x47, 0x54, 0xb8, 0xce, 0xb7,
    0xba, 0xc5, 0x11, 0x73, 0x49, 0xa4, 0x43, 0x9a,
    0x6b, 0x05, 0x69, 0xda, 0x97, 0x7c, 0x46, 0x4a,
};

// "init_remote_static": "31e0303fd6418d2f8c0e78b91f22e8caed0fbe48656dcf4767e4834f701b8f62"
static const uint8_t tv_init_remote_static[CRYPTO_PUBLIC_KEY_SIZE] = {
    0x31, 0xe0, 0x30, 0x3f, 0xd6, 0x41, 0x8d, 0x2f,
    0x8c, 0x0e, 0x78, 0xb9, 0x1f, 0x22, 0xe8, 0xca,
    0xed, 0x0f, 0xbe, 0x48, 0x65, 0x6d, 0xcf, 0x47,
    0x67, 0xe4, 0x83, 0x4f, 0x70, 0x1b, 0x8f, 0x62,
};

// "resp_static": "4a3acbfdb163dec651dfa3194dece676d437029c62a408b4c5ea9114246e4893"
static const uint8_t tv_resp_static[CRYPTO_SECRET_KEY_SIZE] = {
    0x4a, 0x3a, 0xcb, 0xfd, 0xb1, 0x63, 0xde, 0xc6,
    0x51, 0xdf, 0xa3, 0x19, 0x4d, 0xec, 0xe6, 0x76,
    0xd4, 0x37, 0x02, 0x9c, 0x62, 0xa4, 0x08, 0xb4,
    0xc5, 0xea, 0x91, 0x14, 0x24, 0x6e, 0x48, 0x93,
};

// "resp_ephemeral": "bbdb4cdbd309f1a1f2e1456967fe288cadd6f712d65dc7b7793d5e63da6b375b"
static const uint8_t tv_resp_ephemeral[CRYPTO_SECRET_KEY_SIZE] = {
    0xbb, 0xdb, 0x4c, 0xdb, 0xd3, 0x09, 0xf1, 0xa1,
    0xf2, 0xe1, 0x45, 0x69, 0x67, 0xfe, 0x28, 0x8c,
    0xad, 0xd6, 0xf7, 0x12, 0xd6, 0x5d, 0xc7, 0xb7,
    0x79, 0x3d, 0x5e, 0x63, 0xda, 0x6b, 0x37, 0x5b,
};

// Initiator ephemeral public: "ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c7944"
static const uint8_t tv_init_ephemeral_public[CRYPTO_PUBLIC_KEY_SIZE] = {
    0xca, 0x35, 0xde, 0xf5, 0xae, 0x56, 0xce, 0xc3,
    0x3d, 0xc2, 0x03, 0x67, 0x31, 0xab, 0x14, 0x89,
    0x6b, 0xc4, 0xc7, 0x5d, 0xbb, 0x07, 0xa6, 0x1f,
    0x87, 0x9f, 0x8e, 0x3a, 0xfa, 0x4c, 0x79, 0x44,
};

// Encrypted initiator static public: "ba83a447b38c83e327ad936929812f624884847b7831e95e197b2f797088efdd232fe541af156ec6d0657602902a8c3e"
static const uint8_t tv_init_encrypted_static_public[CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_MAC_SIZE] = {
    0xba, 0x83, 0xa4, 0x47, 0xb3, 0x8c, 0x83, 0xe3,
    0x27, 0xad, 0x93, 0x69, 0x29, 0x81, 0x2f, 0x62,
    0x48, 0x84, 0x84, 0x7b, 0x78, 0x31, 0xe9, 0x5e,
    0x19, 0x7b, 0x2f, 0x79, 0x70, 0x88, 0xef, 0xdd,
    0x23, 0x2f, 0xe5, 0x41, 0xaf, 0x15, 0x6e, 0xc6,
    0xd0, 0x65, 0x76, 0x02, 0x90, 0x2a, 0x8c, 0x3e,
};

// "payload": "4c756477696720766f6e204d69736573"
static const uint8_t tv_init_payload_hs[16] = {
    0x4c, 0x75, 0x64, 0x77, 0x69, 0x67, 0x20, 0x76,
    0x6f, 0x6e, 0x20, 0x4d, 0x69, 0x73, 0x65, 0x73,
};

// Encrypted initiator payload: "e64e470f4b6fcd9298ce0b56fe20f86e60d9d933ec6e103ffb09e6001d6abb64"
static const uint8_t tv_init_payload_hs_encrypted[sizeof(tv_init_payload_hs) + CRYPTO_MAC_SIZE] = {
    0xe6, 0x4e, 0x47, 0x0f, 0x4b, 0x6f, 0xcd, 0x92,
    0x98, 0xce, 0x0b, 0x56, 0xfe, 0x20, 0xf8, 0x6e,
    0x60, 0xd9, 0xd9, 0x33, 0xec, 0x6e, 0x10, 0x3f,
    0xfb, 0x09, 0xe6, 0x00, 0x1d, 0x6a, 0xbb, 0x64,
};

// "payload": "4d757272617920526f746862617264"
static const uint8_t tv_resp_payload_hs[15] = {
    0x4d, 0x75, 0x72, 0x72, 0x61, 0x79, 0x20, 0x52,
    0x6f, 0x74, 0x68, 0x62, 0x61, 0x72, 0x64,
};

// Responder ephemeral public: "95ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f144808843"
static const uint8_t tv_resp_ephemeral_public[CRYPTO_PUBLIC_KEY_SIZE] = {
    0x95, 0xeb, 0xc6, 0x0d, 0x2b, 0x1f, 0xa6, 0x72,
    0xc1, 0xf4, 0x6a, 0x8a, 0xa2, 0x65, 0xef, 0x51,
    0xbf, 0xe3, 0x8e, 0x7c, 0xcb, 0x39, 0xec, 0x5b,
    0xe3, 0x40, 0x69, 0xf1, 0x44, 0x80, 0x88, 0x43,
};

// Encrypted responder payload: "9f069b267a06b3de3ecb1043bcb09807c6cd101f3826192a65f11ef3fe4317"
static const uint8_t tv_resp_payload_hs_encrypted[sizeof(tv_resp_payload_hs) + CRYPTO_MAC_SIZE] = {
    0x9f, 0x06, 0x9b, 0x26, 0x7a, 0x06, 0xb3, 0xde,
    0x3e, 0xcb, 0x10, 0x43, 0xbc, 0xb0, 0x98, 0x07,
    0xc6, 0xcd, 0x10, 0x1f, 0x38, 0x26, 0x19, 0x2a,
    0x65, 0xf1, 0x1e, 0xf3, 0xfe, 0x43, 0x17,
};

// "payload": "462e20412e20486179656b"
static const uint8_t tv_init_payload_transport1[11] = {
    0x46, 0x2e, 0x20, 0x41, 0x2e, 0x20, 0x48, 0x61,
    0x79, 0x65, 0x6b,
};

// "ciphertext": "cd54383060e7a28434cca27fb1cc524cfbabeb18181589df219d07"
static const uint8_t tv_init_payload_transport1_encrypted[sizeof(tv_init_payload_transport1) + CRYPTO_MAC_SIZE] = {
    0xcd, 0x54, 0x38, 0x30, 0x60, 0xe7, 0xa2, 0x84,
    0x34, 0xcc, 0xa2, 0x7f, 0xb1, 0xcc, 0x52, 0x4c,
    0xfb, 0xab, 0xeb, 0x18, 0x18, 0x15, 0x89, 0xdf,
    0x21, 0x9d, 0x07,
};

// "payload": "4361726c204d656e676572"
static const uint8_t tv_resp_payload_transport1[11] = {
    0x43, 0x61, 0x72, 0x6c, 0x20, 0x4d, 0x65, 0x6e,
    0x67, 0x65, 0x72,
};

// "ciphertext": "a856d3bf0246bfc476c655009cd1ed677b8dcc5b349ae8ef2a05f2"
static const uint8_t tv_resp_payload_transport1_encrypted[sizeof(tv_resp_payload_transport1) + CRYPTO_MAC_SIZE] = {
    0xa8, 0x56, 0xd3, 0xbf, 0x02, 0x46, 0xbf, 0xc4,
    0x76, 0xc6, 0x55, 0x00, 0x9c, 0xd1, 0xed, 0x67,
    0x7b, 0x8d, 0xcc, 0x5b, 0x34, 0x9a, 0xe8, 0xef,
    0x2a, 0x05, 0xf2,
};

// "handshake_hash": "00e51d2aac81a9b8ebe441d6af3e1c8efc0f030cc608332edcb42588ff6a0ce26415ddc106e95277a5e6d54132f1e5245976b89caf96d262f1fe5a7f0c55c078"
static const uint8_t tv_handshake_hash[CRYPTO_NOISE_BLAKE2B_HASH_SIZE] = {
    0x00, 0xe5, 0x1d, 0x2a, 0xac, 0x81, 0xa9, 0xb8,
    0xeb, 0xe4, 0x41, 0xd6, 0xaf, 0x3e, 0x1c, 0x8e,
    0xfc, 0x0f, 0x03, 0x0c, 0xc6, 0x08, 0x33, 0x2e,
    0xdc, 0xb4, 0x25, 0x88, 0xff, 0x6a, 0x0c, 0xe2,
    0x64, 0x15, 0xdd, 0xc1, 0x06, 0xe9, 0x52, 0x77,
    0xa5, 0xe6, 0xd5, 0x41, 0x32, 0xf1, 0xe5, 0x24,
    0x59, 0x76, 0xb8, 0x9c, 0xaf, 0x96, 0xd2, 0x62,
    0xf1, 0xfe, 0x5a, 0x7f, 0x0c, 0x55, 0xc0, 0x78,
};
// clang-format on

TEST(Noise, IKHandshakeTestVectors)
{
    // Derive public keys from the test vector secret keys
    uint8_t init_static_pub[CRYPTO_PUBLIC_KEY_SIZE];
    crypto_derive_public_key(init_static_pub, tv_init_static);

    uint8_t resp_static_pub[CRYPTO_PUBLIC_KEY_SIZE];
    crypto_derive_public_key(resp_static_pub, tv_resp_static);
    ASSERT_EQ(memcmp(resp_static_pub, tv_init_remote_static, CRYPTO_PUBLIC_KEY_SIZE), 0)
        << "responder static public keys differ";

    /* INITIATOR: Create handshake packet for responder */
    Noise_Handshake hs_init = {};
    noise_handshake_init(
        &hs_init, init_static_pub, tv_init_remote_static, true, tv_prologue, sizeof(tv_prologue));

    memcpy(hs_init.ephemeral_private, tv_init_ephemeral, CRYPTO_SECRET_KEY_SIZE);
    crypto_derive_public_key(hs_init.ephemeral_public, tv_init_ephemeral);
    ASSERT_EQ(memcmp(hs_init.ephemeral_public, tv_init_ephemeral_public, CRYPTO_PUBLIC_KEY_SIZE), 0)
        << "initiator ephemeral public keys differ";

    /* e */
    noise_mix_hash(hs_init.hash, hs_init.ephemeral_public, CRYPTO_PUBLIC_KEY_SIZE);

    /* es */
    uint8_t temp_key_init[CRYPTO_SHARED_KEY_SIZE];
    noise_mix_key(
        hs_init.chaining_key, temp_key_init, hs_init.ephemeral_private, hs_init.remote_static);

    /* s */
    uint8_t ciphertext1[CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_MAC_SIZE];
    noise_encrypt_and_hash(
        ciphertext1, init_static_pub, CRYPTO_PUBLIC_KEY_SIZE, temp_key_init, hs_init.hash);
    ASSERT_EQ(memcmp(ciphertext1, tv_init_encrypted_static_public,
                  sizeof(tv_init_encrypted_static_public)),
        0)
        << "initiator encrypted static public keys differ";

    /* ss */
    noise_mix_key(hs_init.chaining_key, temp_key_init, tv_init_static, hs_init.remote_static);

    /* Handshake payload */
    uint8_t ciphertext2[sizeof(tv_init_payload_hs) + CRYPTO_MAC_SIZE];
    noise_encrypt_and_hash(
        ciphertext2, tv_init_payload_hs, sizeof(tv_init_payload_hs), temp_key_init, hs_init.hash);
    ASSERT_EQ(
        memcmp(ciphertext2, tv_init_payload_hs_encrypted, sizeof(tv_init_payload_hs_encrypted)), 0)
        << "initiator encrypted handshake payloads differ";

    /* RESPONDER: Consume handshake packet from initiator */
    Noise_Handshake hs_resp = {};
    noise_handshake_init(
        &hs_resp, resp_static_pub, nullptr, false, tv_prologue, sizeof(tv_prologue));

    /* e */
    memcpy(hs_resp.remote_ephemeral, hs_init.ephemeral_public, CRYPTO_PUBLIC_KEY_SIZE);
    noise_mix_hash(hs_resp.hash, hs_init.ephemeral_public, CRYPTO_PUBLIC_KEY_SIZE);

    /* es */
    uint8_t temp_key_resp[CRYPTO_SHARED_KEY_SIZE];
    noise_mix_key(hs_resp.chaining_key, temp_key_resp, tv_resp_static, hs_resp.remote_ephemeral);

    /* s */
    noise_decrypt_and_hash(
        hs_resp.remote_static, ciphertext1, sizeof(ciphertext1), temp_key_resp, hs_resp.hash);

    /* ss */
    noise_mix_key(hs_resp.chaining_key, temp_key_resp, tv_resp_static, hs_resp.remote_static);

    /* Payload decryption */
    uint8_t payload_plain_init[sizeof(tv_init_payload_hs)];
    noise_decrypt_and_hash(
        payload_plain_init, ciphertext2, sizeof(ciphertext2), temp_key_resp, hs_resp.hash);

    /* RESPONDER: Create handshake packet for initiator */
    memcpy(hs_resp.ephemeral_private, tv_resp_ephemeral, CRYPTO_SECRET_KEY_SIZE);
    crypto_derive_public_key(hs_resp.ephemeral_public, tv_resp_ephemeral);
    ASSERT_EQ(memcmp(hs_resp.ephemeral_public, tv_resp_ephemeral_public, CRYPTO_PUBLIC_KEY_SIZE), 0)
        << "responder ephemeral public keys differ";

    /* e */
    noise_mix_hash(hs_resp.hash, hs_resp.ephemeral_public, CRYPTO_PUBLIC_KEY_SIZE);

    /* ee */
    uint8_t temp_key_resp2[CRYPTO_SHARED_KEY_SIZE];
    noise_mix_key(
        hs_resp.chaining_key, temp_key_resp2, hs_resp.ephemeral_private, hs_resp.remote_ephemeral);

    /* se */
    noise_mix_key(
        hs_resp.chaining_key, temp_key_resp2, hs_resp.ephemeral_private, hs_resp.remote_static);

    uint8_t ciphertext3[sizeof(tv_resp_payload_hs) + CRYPTO_MAC_SIZE];
    noise_encrypt_and_hash(
        ciphertext3, tv_resp_payload_hs, sizeof(tv_resp_payload_hs), temp_key_resp2, hs_resp.hash);
    ASSERT_EQ(
        memcmp(ciphertext3, tv_resp_payload_hs_encrypted, sizeof(tv_resp_payload_hs_encrypted)), 0)
        << "responder encrypted handshake payloads differ";

    /* INITIATOR: Consume handshake packet from responder */
    memcpy(hs_init.remote_ephemeral, hs_resp.ephemeral_public, CRYPTO_PUBLIC_KEY_SIZE);
    noise_mix_hash(hs_init.hash, hs_init.remote_ephemeral, CRYPTO_PUBLIC_KEY_SIZE);

    /* ee */
    uint8_t temp_key_init2[CRYPTO_SHARED_KEY_SIZE];
    noise_mix_key(
        hs_init.chaining_key, temp_key_init2, hs_init.ephemeral_private, hs_init.remote_ephemeral);

    /* se */
    noise_mix_key(hs_init.chaining_key, temp_key_init2, tv_init_static, hs_init.remote_ephemeral);

    uint8_t payload_plain_resp[sizeof(tv_resp_payload_hs)];
    ASSERT_EQ(noise_decrypt_and_hash(payload_plain_resp, ciphertext3, sizeof(ciphertext3),
                  temp_key_init2, hs_init.hash),
        static_cast<int>(sizeof(tv_resp_payload_hs)))
        << "initiator: HS decryption failed";

    /* Split: derive transport keys */
    uint8_t initiator_send_key[CRYPTO_SHARED_KEY_SIZE];
    uint8_t initiator_recv_key[CRYPTO_SHARED_KEY_SIZE];
    ASSERT_TRUE(noise_hkdf(initiator_send_key, CRYPTO_SHARED_KEY_SIZE, initiator_recv_key,
        CRYPTO_SHARED_KEY_SIZE, nullptr, 0, hs_init.chaining_key));

    ASSERT_EQ(memcmp(hs_init.hash, tv_handshake_hash, CRYPTO_NOISE_BLAKE2B_HASH_SIZE), 0)
        << "initiator handshake hash differs";

    uint8_t nonce[CRYPTO_NOISE_NONCE_SIZE] = {0};
    uint8_t ciphertext4[sizeof(tv_init_payload_transport1) + CRYPTO_MAC_SIZE];
    encrypt_data_symmetric_aead(initiator_send_key, nonce, tv_init_payload_transport1,
        sizeof(tv_init_payload_transport1), ciphertext4, nullptr, 0);
    ASSERT_EQ(memcmp(ciphertext4, tv_init_payload_transport1_encrypted,
                  sizeof(tv_init_payload_transport1_encrypted)),
        0)
        << "initiator transport1 ciphertext differs";

    uint8_t responder_recv_key[CRYPTO_SHARED_KEY_SIZE];
    uint8_t responder_send_key[CRYPTO_SHARED_KEY_SIZE];
    ASSERT_TRUE(noise_hkdf(responder_recv_key, CRYPTO_SYMMETRIC_KEY_SIZE, responder_send_key,
        CRYPTO_SYMMETRIC_KEY_SIZE, nullptr, 0, hs_resp.chaining_key));

    ASSERT_EQ(memcmp(hs_resp.hash, tv_handshake_hash, CRYPTO_NOISE_BLAKE2B_HASH_SIZE), 0)
        << "responder handshake hash differs";

    uint8_t ciphertext5[sizeof(tv_resp_payload_transport1) + CRYPTO_MAC_SIZE];
    encrypt_data_symmetric_aead(responder_send_key, nonce, tv_resp_payload_transport1,
        sizeof(tv_resp_payload_transport1), ciphertext5, nullptr, 0);
    ASSERT_EQ(memcmp(ciphertext5, tv_resp_payload_transport1_encrypted,
                  sizeof(tv_resp_payload_transport1_encrypted)),
        0)
        << "responder transport1 ciphertext differs";
}

}  // namespace
