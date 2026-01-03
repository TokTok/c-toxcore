#include "crypto_core.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <vector>

#include "../testing/support/public/simulated_environment.hh"
#include "crypto_core_test_util.hh"

namespace {

using HmacKey = std::array<uint8_t, CRYPTO_HMAC_KEY_SIZE>;
using Hmac = std::array<uint8_t, CRYPTO_HMAC_SIZE>;
using SecretKey = std::array<uint8_t, CRYPTO_SECRET_KEY_SIZE>;
using Signature = std::array<uint8_t, CRYPTO_SIGNATURE_SIZE>;
using Nonce = std::array<uint8_t, CRYPTO_NONCE_SIZE>;

using tox::test::SimulatedEnvironment;

TEST(PkEqual, TwoRandomIdsAreNotEqual)
{
    SimulatedEnvironment env;
    auto &rng = env.fake_random();

    uint8_t pk1[CRYPTO_PUBLIC_KEY_SIZE];
    uint8_t pk2[CRYPTO_PUBLIC_KEY_SIZE];

    rng.bytes(pk1, sizeof(pk1));
    rng.bytes(pk2, sizeof(pk2));

    EXPECT_FALSE(pk_equal(pk1, pk2));
}

TEST(PkEqual, IdCopyMakesKeysEqual)
{
    SimulatedEnvironment env;
    auto &rng = env.fake_random();

    uint8_t pk1[CRYPTO_PUBLIC_KEY_SIZE];
    uint8_t pk2[CRYPTO_PUBLIC_KEY_SIZE] = {0};

    rng.bytes(pk1, sizeof(pk1));

    pk_copy(pk2, pk1);

    EXPECT_TRUE(pk_equal(pk1, pk2));
}

TEST(CryptoCore, EncryptLargeData)
{
    SimulatedEnvironment env;
    auto c_mem = env.fake_memory().get_c_memory();
    auto c_rng = env.fake_random().get_c_random();

    Nonce nonce{};
    PublicKey pk;
    SecretKey sk;
    crypto_new_keypair(&c_rng, pk.data(), sk.data());

    // 100 MiB of data (all zeroes, doesn't matter what's inside).
    std::vector<uint8_t> plain(100 * 1024 * 1024);
    std::vector<uint8_t> encrypted(plain.size() + CRYPTO_MAC_SIZE);

    encrypt_data(
        &c_mem, pk.data(), sk.data(), nonce.data(), plain.data(), plain.size(), encrypted.data());
}

TEST(CryptoCore, IncrementNonce)
{
    Nonce nonce{};
    increment_nonce(nonce.data());
    EXPECT_EQ(
        nonce, (Nonce{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}}));

    for (int i = 0; i < 0x1F4; ++i) {
        increment_nonce(nonce.data());
    }

    EXPECT_EQ(nonce,
        (Nonce{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0xF5}}));
}

TEST(CryptoCore, IncrementNonceNumber)
{
    Nonce nonce{};

    increment_nonce_number(nonce.data(), 0x1F5);
    EXPECT_EQ(nonce,
        (Nonce{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0xF5}}));

    increment_nonce_number(nonce.data(), 0x1F5);
    EXPECT_EQ(nonce,
        (Nonce{{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x03, 0xEA}}));

    increment_nonce_number(nonce.data(), 0x12345678);
    EXPECT_EQ(nonce,
        (Nonce{
            {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x12, 0x34, 0x5A, 0x62}}));
}

TEST(CryptoCore, Signatures)
{
    SimulatedEnvironment env;
    auto c_rng = env.fake_random().get_c_random();

    Extended_Public_Key pk;
    Extended_Secret_Key sk;

    EXPECT_TRUE(create_extended_keypair(&pk, &sk, &c_rng));

    std::vector<uint8_t> message{0};
    message.clear();

    // Try a few different sizes, including empty 0 length message.
    for (uint8_t i = 0; i < 100; ++i) {
        Signature signature;
        EXPECT_TRUE(crypto_signature_create(
            signature.data(), message.data(), message.size(), get_sig_sk(&sk)));
        EXPECT_TRUE(crypto_signature_verify(
            signature.data(), message.data(), message.size(), get_sig_pk(&pk)));

        message.push_back(random_u08(&c_rng));
    }
}

TEST(CryptoCore, Hmac)
{
    SimulatedEnvironment env;
    auto c_rng = env.fake_random().get_c_random();

    HmacKey sk;
    new_hmac_key(&c_rng, sk.data());

    std::vector<uint8_t> message{0};
    message.clear();

    // Try a few different sizes, including empty 0 length message.
    for (uint8_t i = 0; i < 100; ++i) {
        Hmac auth;
        crypto_hmac(auth.data(), sk.data(), message.data(), message.size());
        EXPECT_TRUE(crypto_hmac_verify(auth.data(), sk.data(), message.data(), message.size()));

        message.push_back(random_u08(&c_rng));
    }
}

TEST(CryptoCore, ExtendedKeyAccessors)
{
    SimulatedEnvironment env;
    auto c_rng = env.fake_random().get_c_random();
    Extended_Public_Key pk;
    Extended_Secret_Key sk;
    ASSERT_TRUE(create_extended_keypair(&pk, &sk, &c_rng));

    EXPECT_EQ(memcmp(get_enc_key(&pk), pk.enc, CRYPTO_PUBLIC_KEY_SIZE), 0);
    EXPECT_EQ(memcmp(get_sig_pk(&pk), pk.sig, CRYPTO_SIGN_PUBLIC_KEY_SIZE), 0);
    EXPECT_EQ(memcmp(get_sig_sk(&sk), sk.sig, CRYPTO_SIGN_SECRET_KEY_SIZE), 0);
    EXPECT_EQ(memcmp(get_chat_id(&pk), pk.sig, CRYPTO_SIGN_PUBLIC_KEY_SIZE), 0);

    uint8_t new_sig[CRYPTO_SIGN_PUBLIC_KEY_SIZE];
    random_bytes(&c_rng, new_sig, sizeof(new_sig));
    set_sig_pk(&pk, new_sig);
    EXPECT_EQ(memcmp(pk.sig, new_sig, CRYPTO_SIGN_PUBLIC_KEY_SIZE), 0);
}

TEST(CryptoCore, PublicKeyValid)
{
    uint8_t pk[CRYPTO_PUBLIC_KEY_SIZE];
    memset(pk, 0, sizeof(pk));
    pk[31] = 127;
    EXPECT_TRUE(public_key_valid(pk));

    pk[31] = 128;
    EXPECT_FALSE(public_key_valid(pk));
    pk[31] = 255;
    EXPECT_FALSE(public_key_valid(pk));
}

TEST(CryptoCore, CryptoMemzero)
{
    uint8_t data[100];
    memset(data, 0xAA, sizeof(data));
    crypto_memzero(data, sizeof(data));
    for (size_t i = 0; i < sizeof(data); ++i) {
        EXPECT_EQ(data[i], 0);
    }
}

TEST(CryptoCore, ChecksumEq)
{
    SimulatedEnvironment env;
    auto c_rng = env.fake_random().get_c_random();
    uint8_t h1[CRYPTO_SHA512_SIZE], h2[CRYPTO_SHA512_SIZE];
    random_bytes(&c_rng, h1, sizeof(h1));
    memcpy(h2, h1, sizeof(h1));
    EXPECT_TRUE(crypto_sha512_eq(h1, h2));
    h2[0] ^= 1;
    EXPECT_FALSE(crypto_sha512_eq(h1, h2));

    uint8_t s1[CRYPTO_SHA256_SIZE], s2[CRYPTO_SHA256_SIZE];
    random_bytes(&c_rng, s1, sizeof(s1));
    memcpy(s2, s1, sizeof(s1));
    EXPECT_TRUE(crypto_sha256_eq(s1, s2));
    s2[0] ^= 1;
    EXPECT_FALSE(crypto_sha256_eq(s1, s2));
}

TEST(CryptoCore, RandomFunctions)
{
    SimulatedEnvironment env;
    auto c_rng = env.fake_random().get_c_random();
    
    // Just verify they run and return values in range (where applicable)
    // Detailed statistical testing is out of scope.
    EXPECT_LE(random_u08(&c_rng), 255);
    
    uint16_t r16 = random_u16(&c_rng);
    (void)r16;

    uint32_t r32 = random_u32(&c_rng);
    (void)r32;

    uint64_t r64 = random_u64(&c_rng);
    (void)r64;

    for (int i = 0; i < 100; ++i) {
        uint32_t bound = 10;
        EXPECT_LT(random_range_u32(&c_rng, bound), bound);
    }
}

TEST(CryptoCore, RandomNonce)
{
    SimulatedEnvironment env;
    auto c_rng = env.fake_random().get_c_random();
    uint8_t n1[CRYPTO_NONCE_SIZE];
    uint8_t n2[CRYPTO_NONCE_SIZE];
    random_nonce(&c_rng, n1);
    random_nonce(&c_rng, n2);
    EXPECT_NE(memcmp(n1, n2, sizeof(n1)), 0);
}

TEST(CryptoCore, RandomBytes)
{
    SimulatedEnvironment env;
    auto c_rng = env.fake_random().get_c_random();
    uint8_t b1[32];
    uint8_t b2[32];
    random_bytes(&c_rng, b1, sizeof(b1));
    random_bytes(&c_rng, b2, sizeof(b2));
    EXPECT_NE(memcmp(b1, b2, sizeof(b1)), 0);
}

TEST(CryptoCore, SymmetricEncryption)
{
    SimulatedEnvironment env;
    auto c_mem = env.fake_memory().get_c_memory();
    auto c_rng = env.fake_random().get_c_random();

    uint8_t shared_key[CRYPTO_SHARED_KEY_SIZE];
    new_symmetric_key(&c_rng, shared_key);

    uint8_t nonce[CRYPTO_NONCE_SIZE];
    random_nonce(&c_rng, nonce);

    const std::string plaintext = "Hello, Tox!";
    std::vector<uint8_t> encrypted(plaintext.size() + CRYPTO_MAC_SIZE);
    std::vector<uint8_t> decrypted(plaintext.size());

    int len = encrypt_data_symmetric(&c_mem, shared_key, nonce,
                                     reinterpret_cast<const uint8_t*>(plaintext.data()), plaintext.size(),
                                     encrypted.data());
    EXPECT_EQ(len, plaintext.size() + CRYPTO_MAC_SIZE);

    len = decrypt_data_symmetric(&c_mem, shared_key, nonce,
                                 encrypted.data(), encrypted.size(),
                                 decrypted.data());
    EXPECT_EQ(len, plaintext.size());
    EXPECT_EQ(memcmp(plaintext.data(), decrypted.data(), plaintext.size()), 0);

    // Test decryption failure with wrong key
    uint8_t wrong_key[CRYPTO_SHARED_KEY_SIZE];
    new_symmetric_key(&c_rng, wrong_key);
    len = decrypt_data_symmetric(&c_mem, wrong_key, nonce,
                                 encrypted.data(), encrypted.size(),
                                 decrypted.data());
    EXPECT_EQ(len, -1);
}

TEST(CryptoCore, EncryptPrecompute)
{
    SimulatedEnvironment env;
    auto c_mem = env.fake_memory().get_c_memory();
    auto c_rng = env.fake_random().get_c_random();

    PublicKey pk;
    SecretKey sk;
    crypto_new_keypair(&c_rng, pk.data(), sk.data());

    uint8_t shared_key[CRYPTO_SHARED_KEY_SIZE];
    encrypt_precompute(pk.data(), sk.data(), shared_key);

    uint8_t nonce[CRYPTO_NONCE_SIZE];
    random_nonce(&c_rng, nonce);

    const std::string plaintext = "Precompute Test";
    std::vector<uint8_t> encrypted(plaintext.size() + CRYPTO_MAC_SIZE);
    std::vector<uint8_t> decrypted(plaintext.size());

    encrypt_data_symmetric(&c_mem, shared_key, nonce,
                           reinterpret_cast<const uint8_t*>(plaintext.data()), plaintext.size(),
                           encrypted.data());
    
    decrypt_data_symmetric(&c_mem, shared_key, nonce,
                           encrypted.data(), encrypted.size(),
                           decrypted.data());
    
    EXPECT_EQ(memcmp(plaintext.data(), decrypted.data(), plaintext.size()), 0);
}

TEST(CryptoCore, Hashing)
{
    const std::string data = "Hash me!";
    uint8_t hash256[CRYPTO_SHA256_SIZE];
    uint8_t hash512[CRYPTO_SHA512_SIZE];

    crypto_sha256(hash256, reinterpret_cast<const uint8_t*>(data.data()), data.size());
    crypto_sha512(hash512, reinterpret_cast<const uint8_t*>(data.data()), data.size());

    // Basic check: hashes should not be all zeros
    uint8_t zeros[CRYPTO_SHA512_SIZE] = {0};
    EXPECT_NE(memcmp(hash256, zeros, CRYPTO_SHA256_SIZE), 0);
    EXPECT_NE(memcmp(hash512, zeros, CRYPTO_SHA512_SIZE), 0);

    // Deterministic check
    uint8_t hash256_2[CRYPTO_SHA256_SIZE];
    crypto_sha256(hash256_2, reinterpret_cast<const uint8_t*>(data.data()), data.size());
    EXPECT_EQ(memcmp(hash256, hash256_2, CRYPTO_SHA256_SIZE), 0);
}

TEST(CryptoCore, AsymmetricEncryption)
{
    SimulatedEnvironment env;
    auto c_mem = env.fake_memory().get_c_memory();
    auto c_rng = env.fake_random().get_c_random();

    PublicKey pk;
    SecretKey sk;
    crypto_new_keypair(&c_rng, pk.data(), sk.data());

    // Verify key derivation
    PublicKey derived_pk;
    crypto_derive_public_key(derived_pk.data(), sk.data());
    EXPECT_EQ(pk, derived_pk);

    uint8_t nonce[CRYPTO_NONCE_SIZE];
    random_nonce(&c_rng, nonce);

    const std::string plaintext = "Asymmetric Test";
    std::vector<uint8_t> encrypted(plaintext.size() + CRYPTO_MAC_SIZE);
    std::vector<uint8_t> decrypted(plaintext.size());

    int len = encrypt_data(&c_mem, pk.data(), sk.data(), nonce,
                           reinterpret_cast<const uint8_t*>(plaintext.data()), plaintext.size(),
                           encrypted.data());
    EXPECT_EQ(len, plaintext.size() + CRYPTO_MAC_SIZE);

    // For decrypting, we use sender's public key (pk) and receiver's secret key (sk).
    // In this self-send test, they are the same pair, but usually:
    // Sender: encrypt(receiver_pk, sender_sk, ...)
    // Receiver: decrypt(sender_pk, receiver_sk, ...)
    // Wait, encrypt_data(public_key, secret_key, ...)
    // Documentation: "Encrypt plain text ... using the public key of the receiver and the secret key of the sender"
    // decrypt_data: "Decrypt ... using the public key of the sender, the secret key of the receiver"
    
    // So if I am sending to myself:
    // encrypt: receiver_pk = my_pk, sender_sk = my_sk
    // decrypt: sender_pk = my_pk, receiver_sk = my_sk
    
    len = decrypt_data(&c_mem, pk.data(), sk.data(), nonce,
                       encrypted.data(), encrypted.size(),
                       decrypted.data());
    EXPECT_EQ(len, plaintext.size());
    EXPECT_EQ(memcmp(plaintext.data(), decrypted.data(), plaintext.size()), 0);
}

TEST(CryptoCore, AEAD_ChaCha20Poly1305)
{
    SimulatedEnvironment env;
    auto c_rng = env.fake_random().get_c_random();

    uint8_t shared_key[CRYPTO_SHARED_KEY_SIZE];
    new_symmetric_key(&c_rng, shared_key);

    uint8_t nonce[CRYPTO_NOISE_NONCE_SIZE]; // 12 bytes
    random_bytes(&c_rng, nonce, sizeof(nonce));

    const std::string plaintext = "AEAD Test Data";
    const std::string ad = "Associated Data";
    std::vector<uint8_t> encrypted(plaintext.size() + CRYPTO_MAC_SIZE);
    std::vector<uint8_t> decrypted(plaintext.size());

    int len = encrypt_data_symmetric_aead(shared_key, nonce,
                                          reinterpret_cast<const uint8_t*>(plaintext.data()), plaintext.size(),
                                          encrypted.data(),
                                          reinterpret_cast<const uint8_t*>(ad.data()), ad.size());
    EXPECT_EQ(len, plaintext.size() + CRYPTO_MAC_SIZE);

    len = decrypt_data_symmetric_aead(shared_key, nonce,
                                      encrypted.data(), encrypted.size(),
                                      decrypted.data(),
                                      reinterpret_cast<const uint8_t*>(ad.data()), ad.size());
    EXPECT_EQ(len, plaintext.size());
    EXPECT_EQ(memcmp(plaintext.data(), decrypted.data(), plaintext.size()), 0);

    // Fail with wrong AD
    const std::string wrong_ad = "Wrong Data";
    len = decrypt_data_symmetric_aead(shared_key, nonce,
                                      encrypted.data(), encrypted.size(),
                                      decrypted.data(),
                                      reinterpret_cast<const uint8_t*>(wrong_ad.data()), wrong_ad.size());
    EXPECT_EQ(len, -1);
}

TEST(CryptoCore, AEAD_XChaCha20Poly1305)
{
    SimulatedEnvironment env;
    auto c_rng = env.fake_random().get_c_random();

    uint8_t shared_key[CRYPTO_SHARED_KEY_SIZE];
    new_symmetric_key(&c_rng, shared_key);

    uint8_t nonce[CRYPTO_NONCE_SIZE]; // 24 bytes
    random_nonce(&c_rng, nonce);

    const std::string plaintext = "XAEAD Test Data";
    const std::string ad = "X Associated Data";
    std::vector<uint8_t> encrypted(plaintext.size() + CRYPTO_MAC_SIZE);
    std::vector<uint8_t> decrypted(plaintext.size());

    int len = encrypt_data_symmetric_xaead(shared_key, nonce,
                                           reinterpret_cast<const uint8_t*>(plaintext.data()), plaintext.size(),
                                           encrypted.data(),
                                           reinterpret_cast<const uint8_t*>(ad.data()), ad.size());
    EXPECT_EQ(len, plaintext.size() + CRYPTO_MAC_SIZE);

    len = decrypt_data_symmetric_xaead(shared_key, nonce,
                                       encrypted.data(), encrypted.size(),
                                       decrypted.data(),
                                       reinterpret_cast<const uint8_t*>(ad.data()), ad.size());
    EXPECT_EQ(len, plaintext.size());
    EXPECT_EQ(memcmp(plaintext.data(), decrypted.data(), plaintext.size()), 0);
}

TEST(CryptoCore, HKDF)
{
    SimulatedEnvironment env;
    auto c_rng = env.fake_random().get_c_random();
    uint8_t chaining_key[CRYPTO_NOISE_BLAKE2B_HASH_SIZE];
    random_bytes(&c_rng, chaining_key, sizeof(chaining_key));

    uint8_t data[32];
    random_bytes(&c_rng, data, sizeof(data));

    uint8_t out1[32], out2[32];
    crypto_hkdf(out1, sizeof(out1), out2, sizeof(out2), data, sizeof(data), chaining_key);

    uint8_t zeros[32] = {0};
    EXPECT_NE(memcmp(out1, zeros, sizeof(out1)), 0);
    EXPECT_NE(memcmp(out2, zeros, sizeof(out2)), 0);
    // Outputs should be different (usually)
    EXPECT_NE(memcmp(out1, out2, sizeof(out1)), 0);
}

TEST(CryptoCore, NoiseMixKey)
{
    SimulatedEnvironment env;
    auto c_rng = env.fake_random().get_c_random();
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

TEST(CryptoCore, NoiseMixHash)
{
    SimulatedEnvironment env;
    auto c_rng = env.fake_random().get_c_random();
    uint8_t hash[CRYPTO_NOISE_BLAKE2B_HASH_SIZE];
    random_bytes(&c_rng, hash, sizeof(hash));
    
    uint8_t data[10] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
    uint8_t original_hash[CRYPTO_NOISE_BLAKE2B_HASH_SIZE];
    memcpy(original_hash, hash, sizeof(hash));
    
    noise_mix_hash(hash, data, sizeof(data));
    
    EXPECT_NE(memcmp(hash, original_hash, sizeof(hash)), 0);
}

TEST(CryptoCore, NoiseEncryptDecryptHash)
{
    SimulatedEnvironment env;
    auto c_rng = env.fake_random().get_c_random();
    uint8_t shared_key[CRYPTO_SHARED_KEY_SIZE];
    new_symmetric_key(&c_rng, shared_key);
    
    uint8_t hash[CRYPTO_NOISE_BLAKE2B_HASH_SIZE];
    random_bytes(&c_rng, hash, sizeof(hash));
    uint8_t decrypt_hash[CRYPTO_NOISE_BLAKE2B_HASH_SIZE];
    memcpy(decrypt_hash, hash, sizeof(hash));

    const std::string plaintext = "Noise Message";
    std::vector<uint8_t> ciphertext(plaintext.size() + CRYPTO_MAC_SIZE);
    std::vector<uint8_t> decrypted(plaintext.size());

    noise_encrypt_and_hash(ciphertext.data(), reinterpret_cast<const uint8_t*>(plaintext.data()), plaintext.size(), shared_key, hash);
    
    int len = noise_decrypt_and_hash(decrypted.data(), ciphertext.data(), ciphertext.size(), shared_key, decrypt_hash);
    
    EXPECT_EQ(len, plaintext.size());
    EXPECT_EQ(memcmp(plaintext.data(), decrypted.data(), plaintext.size()), 0);
    // Hashes should be updated identically
    EXPECT_EQ(memcmp(hash, decrypt_hash, sizeof(hash)), 0);
}

TEST(CryptoCore, NoiseHandshakeInit)
{
    SimulatedEnvironment env;
    auto c_rng = env.fake_random().get_c_random();
    Noise_Handshake handshake;
    
    PublicKey self_pk, peer_pk;
    SecretKey self_sk, peer_sk;
    crypto_new_keypair(&c_rng, self_pk.data(), self_sk.data());
    crypto_new_keypair(&c_rng, peer_pk.data(), peer_sk.data());
    
    const uint8_t prologue[] = "Prologue";
    
    // Initiator
    EXPECT_EQ(noise_handshake_init(&handshake, self_sk.data(), peer_pk.data(), true, prologue, sizeof(prologue)), 0);
    EXPECT_TRUE(handshake.initiator);
    EXPECT_EQ(memcmp(handshake.static_public, self_pk.data(), CRYPTO_PUBLIC_KEY_SIZE), 0);
    EXPECT_EQ(memcmp(handshake.remote_static, peer_pk.data(), CRYPTO_PUBLIC_KEY_SIZE), 0);

    // Responder
    EXPECT_EQ(noise_handshake_init(&handshake, peer_sk.data(), nullptr, false, prologue, sizeof(prologue)), 0);
    EXPECT_FALSE(handshake.initiator);
    EXPECT_EQ(memcmp(handshake.static_public, peer_pk.data(), CRYPTO_PUBLIC_KEY_SIZE), 0);
}

}  // namespace
