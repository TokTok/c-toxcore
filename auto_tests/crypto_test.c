#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "../testing/misc_tools.h"
#include "../toxcore/crypto_core.h"
#include "../toxcore/net_crypto.h"
#include "check_compat.h"
// TODO(goldroom): necessary to print bytes
// #include "../other/fun/create_common.h"

static void rand_bytes(const Random *rng, uint8_t *b, size_t blen)
{
    for (size_t i = 0; i < blen; i++) {
        b[i] = random_u08(rng);
    }
}

// These test vectors are from libsodium's test suite

static const uint8_t alicesk[32] = {
    0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d,
    0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66, 0x45,
    0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a,
    0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a
};

static const uint8_t bobpk[32] = {
    0xde, 0x9e, 0xdb, 0x7d, 0x7b, 0x7d, 0xc1, 0xb4,
    0xd3, 0x5b, 0x61, 0xc2, 0xec, 0xe4, 0x35, 0x37,
    0x3f, 0x83, 0x43, 0xc8, 0x5b, 0x78, 0x67, 0x4d,
    0xad, 0xfc, 0x7e, 0x14, 0x6f, 0x88, 0x2b, 0x4f
};

static const uint8_t test_nonce[24] = {
    0x69, 0x69, 0x6e, 0xe9, 0x55, 0xb6, 0x2b, 0x73,
    0xcd, 0x62, 0xbd, 0xa8, 0x75, 0xfc, 0x73, 0xd6,
    0x82, 0x19, 0xe0, 0x03, 0x6b, 0x7a, 0x0b, 0x37
};

static const uint8_t test_m[131] = {
    0xbe, 0x07, 0x5f, 0xc5, 0x3c, 0x81, 0xf2, 0xd5,
    0xcf, 0x14, 0x13, 0x16, 0xeb, 0xeb, 0x0c, 0x7b,
    0x52, 0x28, 0xc5, 0x2a, 0x4c, 0x62, 0xcb, 0xd4,
    0x4b, 0x66, 0x84, 0x9b, 0x64, 0x24, 0x4f, 0xfc,
    0xe5, 0xec, 0xba, 0xaf, 0x33, 0xbd, 0x75, 0x1a,
    0x1a, 0xc7, 0x28, 0xd4, 0x5e, 0x6c, 0x61, 0x29,
    0x6c, 0xdc, 0x3c, 0x01, 0x23, 0x35, 0x61, 0xf4,
    0x1d, 0xb6, 0x6c, 0xce, 0x31, 0x4a, 0xdb, 0x31,
    0x0e, 0x3b, 0xe8, 0x25, 0x0c, 0x46, 0xf0, 0x6d,
    0xce, 0xea, 0x3a, 0x7f, 0xa1, 0x34, 0x80, 0x57,
    0xe2, 0xf6, 0x55, 0x6a, 0xd6, 0xb1, 0x31, 0x8a,
    0x02, 0x4a, 0x83, 0x8f, 0x21, 0xaf, 0x1f, 0xde,
    0x04, 0x89, 0x77, 0xeb, 0x48, 0xf5, 0x9f, 0xfd,
    0x49, 0x24, 0xca, 0x1c, 0x60, 0x90, 0x2e, 0x52,
    0xf0, 0xa0, 0x89, 0xbc, 0x76, 0x89, 0x70, 0x40,
    0xe0, 0x82, 0xf9, 0x37, 0x76, 0x38, 0x48, 0x64,
    0x5e, 0x07, 0x05
};

static const uint8_t test_c[147] = {
    0xf3, 0xff, 0xc7, 0x70, 0x3f, 0x94, 0x00, 0xe5,
    0x2a, 0x7d, 0xfb, 0x4b, 0x3d, 0x33, 0x05, 0xd9,
    0x8e, 0x99, 0x3b, 0x9f, 0x48, 0x68, 0x12, 0x73,
    0xc2, 0x96, 0x50, 0xba, 0x32, 0xfc, 0x76, 0xce,
    0x48, 0x33, 0x2e, 0xa7, 0x16, 0x4d, 0x96, 0xa4,
    0x47, 0x6f, 0xb8, 0xc5, 0x31, 0xa1, 0x18, 0x6a,
    0xc0, 0xdf, 0xc1, 0x7c, 0x98, 0xdc, 0xe8, 0x7b,
    0x4d, 0xa7, 0xf0, 0x11, 0xec, 0x48, 0xc9, 0x72,
    0x71, 0xd2, 0xc2, 0x0f, 0x9b, 0x92, 0x8f, 0xe2,
    0x27, 0x0d, 0x6f, 0xb8, 0x63, 0xd5, 0x17, 0x38,
    0xb4, 0x8e, 0xee, 0xe3, 0x14, 0xa7, 0xcc, 0x8a,
    0xb9, 0x32, 0x16, 0x45, 0x48, 0xe5, 0x26, 0xae,
    0x90, 0x22, 0x43, 0x68, 0x51, 0x7a, 0xcf, 0xea,
    0xbd, 0x6b, 0xb3, 0x73, 0x2b, 0xc0, 0xe9, 0xda,
    0x99, 0x83, 0x2b, 0x61, 0xca, 0x01, 0xb6, 0xde,
    0x56, 0x24, 0x4a, 0x9e, 0x88, 0xd5, 0xf9, 0xb3,
    0x79, 0x73, 0xf6, 0x22, 0xa4, 0x3d, 0x14, 0xa6,
    0x59, 0x9b, 0x1f, 0x65, 0x4c, 0xb4, 0x5a, 0x74,
    0xe3, 0x55, 0xa5
};

static void test_known(void)
{
    const Memory *mem = os_memory();
    ck_assert(mem != nullptr);

    uint8_t c[147];
    uint8_t m[131];

    ck_assert_msg(sizeof(c) == sizeof(m) + CRYPTO_MAC_SIZE * sizeof(uint8_t),
                  "cyphertext should be CRYPTO_MAC_SIZE bytes longer than plaintext");
    ck_assert_msg(sizeof(test_c) == sizeof(c), "sanity check failed");
    ck_assert_msg(sizeof(test_m) == sizeof(m), "sanity check failed");

    const uint16_t clen = encrypt_data(mem, bobpk, alicesk, test_nonce, test_m, sizeof(test_m) / sizeof(uint8_t), c);

    ck_assert_msg(memcmp(test_c, c, sizeof(c)) == 0, "cyphertext doesn't match test vector");
    ck_assert_msg(clen == sizeof(c) / sizeof(uint8_t), "wrong ciphertext length");

    const uint16_t mlen = decrypt_data(mem, bobpk, alicesk, test_nonce, test_c, sizeof(test_c) / sizeof(uint8_t), m);

    ck_assert_msg(memcmp(test_m, m, sizeof(m)) == 0, "decrypted text doesn't match test vector");
    ck_assert_msg(mlen == sizeof(m) / sizeof(uint8_t), "wrong plaintext length");
}

static void test_fast_known(void)
{
    const Memory *mem = os_memory();
    ck_assert(mem != nullptr);

    uint8_t k[CRYPTO_SHARED_KEY_SIZE];
    uint8_t c[147];
    uint8_t m[131];

    encrypt_precompute(bobpk, alicesk, k);

    ck_assert_msg(sizeof(c) == sizeof(m) + CRYPTO_MAC_SIZE * sizeof(uint8_t),
                  "cyphertext should be CRYPTO_MAC_SIZE bytes longer than plaintext");
    ck_assert_msg(sizeof(test_c) == sizeof(c), "sanity check failed");
    ck_assert_msg(sizeof(test_m) == sizeof(m), "sanity check failed");

    const uint16_t clen = encrypt_data_symmetric(mem, k, test_nonce, test_m, sizeof(test_m) / sizeof(uint8_t), c);

    ck_assert_msg(memcmp(test_c, c, sizeof(c)) == 0, "cyphertext doesn't match test vector");
    ck_assert_msg(clen == sizeof(c) / sizeof(uint8_t), "wrong ciphertext length");

    const uint16_t mlen = decrypt_data_symmetric(mem, k, test_nonce, test_c, sizeof(test_c) / sizeof(uint8_t), m);

    ck_assert_msg(memcmp(test_m, m, sizeof(m)) == 0, "decrypted text doesn't match test vector");
    ck_assert_msg(mlen == sizeof(m) / sizeof(uint8_t), "wrong plaintext length");
}

static void test_endtoend(void)
{
    const Memory *mem = os_memory();
    ck_assert(mem != nullptr);
    const Random *rng = os_random();
    ck_assert(rng != nullptr);

    // Test 100 random messages and keypairs
    for (uint8_t testno = 0; testno < 100; testno++) {
        uint8_t pk1[CRYPTO_PUBLIC_KEY_SIZE];
        uint8_t sk1[CRYPTO_SECRET_KEY_SIZE];
        uint8_t pk2[CRYPTO_PUBLIC_KEY_SIZE];
        uint8_t sk2[CRYPTO_SECRET_KEY_SIZE];
        uint8_t k1[CRYPTO_SHARED_KEY_SIZE];
        uint8_t k2[CRYPTO_SHARED_KEY_SIZE];

        uint8_t n[CRYPTO_NONCE_SIZE];

        enum { M_SIZE = 50 };
        uint8_t m[M_SIZE];
        uint8_t c1[sizeof(m) + CRYPTO_MAC_SIZE];
        uint8_t c2[sizeof(m) + CRYPTO_MAC_SIZE];
        uint8_t c3[sizeof(m) + CRYPTO_MAC_SIZE];
        uint8_t c4[sizeof(m) + CRYPTO_MAC_SIZE];
        uint8_t m1[sizeof(m)];
        uint8_t m2[sizeof(m)];
        uint8_t m3[sizeof(m)];
        uint8_t m4[sizeof(m)];

        //Generate random message (random length from 10 to 50)
        const uint16_t mlen = (random_u32(rng) % (M_SIZE - 10)) + 10;
        rand_bytes(rng, m, mlen);
        rand_bytes(rng, n, CRYPTO_NONCE_SIZE);

        //Generate keypairs
        crypto_new_keypair(rng, pk1, sk1);
        crypto_new_keypair(rng, pk2, sk2);

        //Precompute shared keys
        encrypt_precompute(pk2, sk1, k1);
        encrypt_precompute(pk1, sk2, k2);

        ck_assert_msg(memcmp(k1, k2, CRYPTO_SHARED_KEY_SIZE) == 0, "encrypt_precompute: bad");

        //Encrypt all four ways
        const uint16_t c1len = encrypt_data(mem, pk2, sk1, n, m, mlen, c1);
        const uint16_t c2len = encrypt_data(mem, pk1, sk2, n, m, mlen, c2);
        const uint16_t c3len = encrypt_data_symmetric(mem, k1, n, m, mlen, c3);
        const uint16_t c4len = encrypt_data_symmetric(mem, k2, n, m, mlen, c4);

        ck_assert_msg(c1len == c2len && c1len == c3len && c1len == c4len, "cyphertext lengths differ");
        ck_assert_msg(c1len == mlen + (uint16_t)CRYPTO_MAC_SIZE, "wrong cyphertext length");
        ck_assert_msg(memcmp(c1, c2, c1len) == 0 && memcmp(c1, c3, c1len) == 0
                      && memcmp(c1, c4, c1len) == 0, "crypertexts differ");

        //Decrypt all four ways
        const uint16_t m1len = decrypt_data(mem, pk2, sk1, n, c1, c1len, m1);
        const uint16_t m2len = decrypt_data(mem, pk1, sk2, n, c1, c1len, m2);
        const uint16_t m3len = decrypt_data_symmetric(mem, k1, n, c1, c1len, m3);
        const uint16_t m4len = decrypt_data_symmetric(mem, k2, n, c1, c1len, m4);

        ck_assert_msg(m1len == m2len && m1len == m3len && m1len == m4len, "decrypted text lengths differ");
        ck_assert_msg(m1len == mlen, "wrong decrypted text length");
        ck_assert_msg(memcmp(m1, m2, mlen) == 0 && memcmp(m1, m3, mlen) == 0
                      && memcmp(m1, m4, mlen) == 0, "decrypted texts differ");
        ck_assert_msg(memcmp(m1, m, mlen) == 0, "wrong decrypted text");
    }
}

static void test_large_data(void)
{
    const Memory *mem = os_memory();
    ck_assert(mem != nullptr);
    const Random *rng = os_random();
    ck_assert(rng != nullptr);
    uint8_t k[CRYPTO_SHARED_KEY_SIZE];
    uint8_t n[CRYPTO_NONCE_SIZE];

    const size_t m1_size = MAX_CRYPTO_PACKET_SIZE - CRYPTO_MAC_SIZE;
    uint8_t *m1 = (uint8_t *)malloc(m1_size);
    uint8_t *c1 = (uint8_t *)malloc(m1_size + CRYPTO_MAC_SIZE);
    uint8_t *m1prime = (uint8_t *)malloc(m1_size);

    const size_t m2_size = MAX_CRYPTO_PACKET_SIZE - CRYPTO_MAC_SIZE;
    uint8_t *m2 = (uint8_t *)malloc(m2_size);
    uint8_t *c2 = (uint8_t *)malloc(m2_size + CRYPTO_MAC_SIZE);

    ck_assert(m1 != nullptr && c1 != nullptr && m1prime != nullptr && m2 != nullptr && c2 != nullptr);

    //Generate random messages
    rand_bytes(rng, m1, m1_size);
    rand_bytes(rng, m2, m2_size);
    rand_bytes(rng, n, CRYPTO_NONCE_SIZE);

    //Generate key
    rand_bytes(rng, k, CRYPTO_SHARED_KEY_SIZE);

    const uint16_t c1len = encrypt_data_symmetric(mem, k, n, m1, m1_size, c1);
    const uint16_t c2len = encrypt_data_symmetric(mem, k, n, m2, m2_size, c2);

    ck_assert_msg(c1len == m1_size + CRYPTO_MAC_SIZE, "could not encrypt");
    ck_assert_msg(c2len == m2_size + CRYPTO_MAC_SIZE, "could not encrypt");

    const uint16_t m1plen = decrypt_data_symmetric(mem, k, n, c1, c1len, m1prime);

    ck_assert_msg(m1plen == m1_size, "decrypted text lengths differ");
    ck_assert_msg(memcmp(m1prime, m1, m1_size) == 0, "decrypted texts differ");

    free(c2);
    free(m2);
    free(m1prime);
    free(c1);
    free(m1);
}

static void test_large_data_symmetric(void)
{
    const Memory *mem = os_memory();
    ck_assert(mem != nullptr);
    const Random *rng = os_random();
    ck_assert(rng != nullptr);
    uint8_t k[CRYPTO_SYMMETRIC_KEY_SIZE];

    uint8_t n[CRYPTO_NONCE_SIZE];

    const size_t m1_size = 16 * 16 * 16;
    uint8_t *m1 = (uint8_t *)malloc(m1_size);
    uint8_t *c1 = (uint8_t *)malloc(m1_size + CRYPTO_MAC_SIZE);
    uint8_t *m1prime = (uint8_t *)malloc(m1_size);

    ck_assert(m1 != nullptr && c1 != nullptr && m1prime != nullptr);

    //Generate random messages
    rand_bytes(rng, m1, m1_size);
    rand_bytes(rng, n, CRYPTO_NONCE_SIZE);

    //Generate key
    new_symmetric_key(rng, k);

    const uint16_t c1len = encrypt_data_symmetric(mem, k, n, m1, m1_size, c1);
    ck_assert_msg(c1len == m1_size + CRYPTO_MAC_SIZE, "could not encrypt data");

    const uint16_t m1plen = decrypt_data_symmetric(mem, k, n, c1, c1len, m1prime);

    ck_assert_msg(m1plen == m1_size, "decrypted text lengths differ");
    ck_assert_msg(memcmp(m1prime, m1, m1_size) == 0, "decrypted texts differ");

    free(m1prime);
    free(c1);
    free(m1);
}

static void test_very_large_data(void)
{
    const Memory *mem = os_memory();
    ck_assert(mem != nullptr);
    const Random *rng = os_random();
    ck_assert(rng != nullptr);

    const uint8_t nonce[CRYPTO_NONCE_SIZE] = {0};
    uint8_t pk[CRYPTO_PUBLIC_KEY_SIZE];
    uint8_t sk[CRYPTO_SECRET_KEY_SIZE];
    crypto_new_keypair(rng, pk, sk);

    // 100 MiB of data (all zeroes, doesn't matter what's inside).
    const uint32_t plain_size = 100 * 1024 * 1024;
    uint8_t *plain = (uint8_t *)malloc(plain_size);
    uint8_t *encrypted = (uint8_t *)malloc(plain_size + CRYPTO_MAC_SIZE);

    ck_assert(plain != nullptr);
    ck_assert(encrypted != nullptr);

    memset(plain, 0, plain_size);

    encrypt_data(mem, pk, sk, nonce, plain, plain_size, encrypted);

    free(encrypted);
    free(plain);
}

static void increment_nonce_number_cmp(uint8_t *nonce, uint32_t num)
{
    uint32_t num1 = 0;
    memcpy(&num1, nonce + (CRYPTO_NONCE_SIZE - sizeof(num1)), sizeof(num1));
    num1 = net_ntohl(num1);
    uint32_t num2 = num + num1;

    if (num2 < num1) {
        for (uint16_t i = CRYPTO_NONCE_SIZE - sizeof(num1); i != 0; --i) {
            ++nonce[i - 1];

            if (nonce[i - 1] != 0) {
                break;
            }
        }
    }

    num2 = net_htonl(num2);
    memcpy(nonce + (CRYPTO_NONCE_SIZE - sizeof(num2)), &num2, sizeof(num2));
}

static void test_increment_nonce(void)
{
    const Random *rng = os_random();
    ck_assert(rng != nullptr);

    uint8_t n[CRYPTO_NONCE_SIZE];

    for (uint32_t i = 0; i < CRYPTO_NONCE_SIZE; ++i) {
        n[i] = random_u08(rng);
    }

    uint8_t n1[CRYPTO_NONCE_SIZE];

    memcpy(n1, n, CRYPTO_NONCE_SIZE);

    for (uint32_t i = 0; i < (1 << 18); ++i) {
        increment_nonce_number_cmp(n, 1);
        increment_nonce(n1);
        ck_assert_msg(memcmp(n, n1, CRYPTO_NONCE_SIZE) == 0, "Bad increment_nonce function");
    }

    for (uint32_t i = 0; i < (1 << 18); ++i) {
        const uint32_t r = random_u32(rng);
        increment_nonce_number_cmp(n, r);
        increment_nonce_number(n1, r);
        ck_assert_msg(memcmp(n, n1, CRYPTO_NONCE_SIZE) == 0, "Bad increment_nonce_number function");
    }
}

static void test_memzero(void)
{
    uint8_t src[sizeof(test_c)];
    memcpy(src, test_c, sizeof(test_c));

    crypto_memzero(src, sizeof(src));

    for (size_t i = 0; i < sizeof(src); i++) {
        ck_assert_msg(src[i] == 0, "Memory is not zeroed");
    }
}

/* Noise_IK_25519_ChaChaPoly_BLAKE2b test vectors from here: https://github.com/rweather/noise-c/blob/cfe25410979a87391bb9ac8d4d4bef64e9f268c6/tests/vector/noise-c-basic.txt */
/* "init_prologue": "50726f6c6f677565313233" (same as `resp_prologue`) */
static const uint8_t prologue[11] = {
    0x50, 0x72, 0x6f, 0x6c, 0x6f, 0x67, 0x75, 0x65, 
    0x31, 0x32, 0x33
};

/* Initiator static private key 
 "init_static": "e61ef9919cde45dd5f82166404bd08e38bceb5dfdfded0a34c8df7ed542214d1" */
static const uint8_t init_static[CRYPTO_SECRET_KEY_SIZE] = {
    0xe6, 0x1e, 0xf9, 0x91, 0x9c, 0xde, 0x45, 0xdd, 
    0x5f, 0x82, 0x16, 0x64, 0x04, 0xbd, 0x08, 0xe3, 
    0x8b, 0xce, 0xb5, 0xdf, 0xdf, 0xde, 0xd0, 0xa3, 
    0x4c, 0x8d, 0xf7, 0xed, 0x54, 0x22, 0x14, 0xd1
};

/* Initiator ephemeral private key 
 "init_ephemeral": "893e28b9dc6ca8d611ab664754b8ceb7bac5117349a4439a6b0569da977c464a" */
static const uint8_t init_ephemeral[CRYPTO_SECRET_KEY_SIZE] = {
    0x89, 0x3e, 0x28, 0xb9, 0xdc, 0x6c, 0xa8, 0xd6, 
    0x11, 0xab, 0x66, 0x47, 0x54, 0xb8, 0xce, 0xb7, 
    0xba, 0xc5, 0x11, 0x73, 0x49, 0xa4, 0x43, 0x9a, 
    0x6b, 0x05, 0x69, 0xda, 0x97, 0x7c, 0x46, 0x4a
};

/* Responder static public key
 "init_remote_static": "31e0303fd6418d2f8c0e78b91f22e8caed0fbe48656dcf4767e4834f701b8f62" */
static const uint8_t init_remote_static[CRYPTO_PUBLIC_KEY_SIZE] = {
    0x31, 0xe0, 0x30, 0x3f, 0xd6, 0x41, 0x8d, 0x2f, 
    0x8c, 0x0e, 0x78, 0xb9, 0x1f, 0x22, 0xe8, 0xca, 
    0xed, 0x0f, 0xbe, 0x48, 0x65, 0x6d, 0xcf, 0x47, 
    0x67, 0xe4, 0x83, 0x4f, 0x70, 0x1b, 0x8f, 0x62
};

/* Responder static private key
 "resp_static": "4a3acbfdb163dec651dfa3194dece676d437029c62a408b4c5ea9114246e4893" */
static const uint8_t resp_static[CRYPTO_SECRET_KEY_SIZE] = {
    0x4a, 0x3a, 0xcb, 0xfd, 0xb1, 0x63, 0xde, 0xc6,
    0x51, 0xdf, 0xa3, 0x19, 0x4d, 0xec, 0xe6, 0x76,
    0xd4, 0x37, 0x02, 0x9c, 0x62, 0xa4, 0x08, 0xb4,
    0xc5, 0xea, 0x91, 0x14, 0x24, 0x6e, 0x48, 0x93
};

/* Responder ephermal private key
 "resp_ephemeral": "bbdb4cdbd309f1a1f2e1456967fe288cadd6f712d65dc7b7793d5e63da6b375b" */
static const uint8_t resp_ephemeral[CRYPTO_SECRET_KEY_SIZE] = {
    0xbb, 0xdb, 0x4c, 0xdb, 0xd3, 0x09, 0xf1, 0xa1,
    0xf2, 0xe1, 0x45, 0x69, 0x67, 0xfe, 0x28, 0x8c,
    0xad, 0xd6, 0xf7, 0x12, 0xd6, 0x5d, 0xc7, 0xb7,
    0x79, 0x3d, 0x5e, 0x63, 0xda, 0x6b, 0x37, 0x5b
};

/* Payload for initiator handshake message 
  "payload": "4c756477696720766f6e204d69736573" */
static const uint8_t init_payload_hs[16] = {
    0x4c, 0x75, 0x64, 0x77, 0x69, 0x67, 0x20, 0x76, 
    0x6f,0x6e, 0x20, 0x4d, 0x69, 0x73, 0x65, 0x73
};
/* "ciphertext": is actually three values for initiator handshake message:  
 Initiator ephemeral public key in plaintext: ca35def5ae56cec33dc2036731ab14896bc4c75dbb07a61f879f8e3afa4c7944 
 Encrypted static public key (of initiator): ba83a447b38c83e327ad936929812f624884847b7831e95e197b2f797088efdd232fe541af156ec6d0657602902a8c3e 
 Encrypted payload: e64e470f4b6fcd9298ce0b56fe20f86e60d9d933ec6e103ffb09e6001d6abb64*/
static const uint8_t init_ephemeral_public[CRYPTO_PUBLIC_KEY_SIZE] = {
    0xca, 0x35, 0xde, 0xf5, 0xae, 0x56, 0xce, 0xc3, 
    0x3d, 0xc2, 0x03, 0x67, 0x31, 0xab, 0x14, 0x89, 
    0x6b, 0xc4, 0xc7, 0x5d, 0xbb, 0x07, 0xa6, 0x1f, 
    0x87, 0x9f, 0x8e, 0x3a, 0xfa, 0x4c, 0x79, 0x44
};
static const uint8_t init_encrypted_static_public[CRYPTO_PUBLIC_KEY_SIZE+CRYPTO_MAC_SIZE] = {
    0xba, 0x83, 0xa4, 0x47, 0xb3, 0x8c, 0x83, 0xe3, 
    0x27, 0xad, 0x93, 0x69, 0x29, 0x81, 0x2f, 0x62, 
    0x48, 0x84, 0x84, 0x7b, 0x78, 0x31, 0xe9, 0x5e, 
    0x19, 0x7b, 0x2f, 0x79, 0x70, 0x88, 0xef, 0xdd, 
    0x23, 0x2f, 0xe5, 0x41, 0xaf, 0x15, 0x6e, 0xc6, 
    0xd0, 0x65, 0x76, 0x02, 0x90, 0x2a, 0x8c, 0x3e
};
static const uint8_t init_payload_hs_encrypted[sizeof(init_payload_hs)+CRYPTO_MAC_SIZE] = {
    0xe6, 0x4e, 0x47, 0x0f, 0x4b, 0x6f, 0xcd, 0x92, 
    0x98, 0xce, 0x0b, 0x56, 0xfe, 0x20, 0xf8, 0x6e, 
    0x60, 0xd9, 0xd9, 0x33, 0xec, 0x6e, 0x10, 0x3f, 
    0xfb, 0x09, 0xe6, 0x00, 0x1d, 0x6a, 0xbb, 0x64
};

/* Payload for responder handshake message 
 "payload": "4d757272617920526f746862617264", */
static const uint8_t resp_payload_hs[15] = {
    0x4d, 0x75, 0x72, 0x72, 0x61, 0x79, 0x20, 0x52, 
    0x6f, 0x74, 0x68, 0x62, 0x61, 0x72, 0x64
};
/* "ciphertext": is actually two values for responder handshake message: 
 Responder ephemeral public key in plaintext:
 95ebc60d2b1fa672c1f46a8aa265ef51bfe38e7ccb39ec5be34069f144808843 
 Encrypted payload: 
 9f069b267a06b3de3ecb1043bcb09807c6cd101f3826192a65f11ef3fe4317 */
static const uint8_t resp_ephemeral_public[CRYPTO_PUBLIC_KEY_SIZE] = {
    0x95, 0xeb, 0xc6, 0x0d, 0x2b, 0x1f, 0xa6, 0x72, 
    0xc1, 0xf4, 0x6a, 0x8a, 0xa2, 0x65, 0xef, 0x51, 
    0xbf, 0xe3, 0x8e, 0x7c, 0xcb, 0x39, 0xec, 0x5b, 
    0xe3, 0x40, 0x69, 0xf1, 0x44, 0x80, 0x88, 0x43
};
static const uint8_t resp_payload_hs_encrypted[sizeof(resp_payload_hs)+CRYPTO_MAC_SIZE] = {
    0x9f, 0x06, 0x9b, 0x26, 0x7a, 0x06, 0xb3, 0xde, 
    0x3e, 0xcb, 0x10, 0x43, 0xbc, 0xb0, 0x98, 0x07, 
    0xc6, 0xcd, 0x10, 0x1f, 0x38, 0x26, 0x19, 0x2a, 
    0x65, 0xf1, 0x1e, 0xf3, 0xfe, 0x43, 0x17
};

/* Payload for initiator transport message 1 
 "payload": "462e20412e20486179656b" */
static const uint8_t init_payload_transport1[11] = {
    0x46, 0x2e, 0x20, 0x41, 0x2e, 0x20, 0x48, 0x61, 
    0x79, 0x65, 0x6b
};
/* Payload ciphertext for initiator transport message 1 
 "ciphertext": "cd54383060e7a28434cca27fb1cc524cfbabeb18181589df219d07" */
static const uint8_t init_payload_transport1_encrypted[sizeof(init_payload_transport1)+CRYPTO_MAC_SIZE] = {
    0xcd, 0x54, 0x38, 0x30, 0x60, 0xe7, 0xa2, 0x84,
    0x34, 0xcc, 0xa2, 0x7f, 0xb1, 0xcc, 0x52, 0x4c, 
    0xfb, 0xab, 0xeb, 0x18, 0x18, 0x15, 0x89, 0xdf, 
    0x21, 0x9d, 0x07
};

/* Payload for responder transport message 1 
 "payload": "4361726c204d656e676572" */
static const uint8_t resp_payload_transport1[11] = {
    0x43, 0x61, 0x72, 0x6c, 0x20, 0x4d, 0x65, 0x6e, 
    0x67, 0x65, 0x72
};
/* Payload ciphertext for responder transport message 1 
 "ciphertext": "a856d3bf0246bfc476c655009cd1ed677b8dcc5b349ae8ef2a05f2" */
static const uint8_t resp_payload_transport1_encrypted[sizeof(resp_payload_transport1)+CRYPTO_MAC_SIZE] = {
    0xa8, 0x56, 0xd3, 0xbf, 0x02, 0x46, 0xbf, 0xc4, 
    0x76, 0xc6, 0x55, 0x00, 0x9c, 0xd1, 0xed, 0x67, 
    0x7b, 0x8d, 0xcc, 0x5b, 0x34, 0x9a, 0xe8, 0xef, 
    0x2a, 0x05, 0xf2
};

/* Final handshake hash value (MUST be the same for both initiator and responder)
 "handshake_hash": "00e51d2aac81a9b8ebe441d6af3e1c8efc0f030cc608332edcb42588ff6a0ce26415ddc106e95277a5e6d54132f1e5245976b89caf96d262f1fe5a7f0c55c078" */
static const uint8_t handshake_hash[CRYPTO_SHA512_SIZE] = {
    0x00, 0xe5, 0x1d, 0x2a, 0xac, 0x81, 0xa9, 0xb8, 
    0xeb, 0xe4, 0x41, 0xd6, 0xaf, 0x3e, 0x1c, 0x8e, 
    0xfc, 0x0f, 0x03, 0x0c, 0xc6, 0x08, 0x33, 0x2e, 
    0xdc, 0xb4, 0x25, 0x88, 0xff, 0x6a, 0x0c, 0xe2, 
    0x64, 0x15, 0xdd, 0xc1, 0x06, 0xe9, 0x52, 0x77, 
    0xa5, 0xe6, 0xd5, 0x41, 0x32, 0xf1, 0xe5, 0x24, 
    0x59, 0x76, 0xb8, 0x9c, 0xaf, 0x96, 0xd2, 0x62, 
    0xf1, 0xfe, 0x5a, 0x7f, 0x0c, 0x55, 0xc0, 0x78
};

/* TODO(goldroom): Currently unused */
// TODO(goldroom): "payload": "4a65616e2d426170746973746520536179",
// TODO(goldroom): "ciphertext": "49063084b2c51f098337cb8a13739ac848f907e67cfb2cc8a8b60586467aa02fc7"

// TODO(goldroom): "payload": "457567656e2042f6686d20766f6e2042617765726b",
// TODO(goldroom): "ciphertext": "8b9709d23b47e4639df7678d7a21741eba4ef1e9c60383001c7435549c20f9d56f30e935d3"

static void test_noiseik(void) 
{ 
    /* INITIATOR: Create handshake packet for responder */
    Noise_Handshake *noise_handshake_initiator = (Noise_Handshake *) calloc(1, sizeof(Noise_Handshake));

    noise_handshake_init(noise_handshake_initiator, init_static, init_remote_static, true, prologue, sizeof(prologue));

    memcpy(noise_handshake_initiator->ephemeral_private, init_ephemeral, CRYPTO_SECRET_KEY_SIZE);
    crypto_derive_public_key(noise_handshake_initiator->ephemeral_public, init_ephemeral);

    ck_assert_msg(memcmp(noise_handshake_initiator->ephemeral_public, init_ephemeral_public, CRYPTO_PUBLIC_KEY_SIZE) == 0, "initiator ephemeral public keys differ");

    uint8_t resp_static_pub[CRYPTO_PUBLIC_KEY_SIZE];
    crypto_derive_public_key(resp_static_pub, resp_static);
    ck_assert_msg(memcmp(resp_static_pub, init_remote_static, CRYPTO_PUBLIC_KEY_SIZE) == 0, "responder static public keys differ");

    /* e */
    noise_mix_hash(noise_handshake_initiator->hash, noise_handshake_initiator->ephemeral_public, CRYPTO_PUBLIC_KEY_SIZE);

    /* es */
    uint8_t noise_handshake_temp_key[CRYPTO_SHARED_KEY_SIZE];
    noise_mix_key(noise_handshake_initiator->chaining_key, noise_handshake_temp_key, noise_handshake_initiator->ephemeral_private, noise_handshake_initiator->remote_static);

    /* s */

    /* Nonce for static pub key encryption is _always_ 0 in case of ChaCha20-Poly1305 */
    uint8_t ciphertext1[CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_MAC_SIZE];
    noise_encrypt_and_hash(ciphertext1, noise_handshake_initiator->static_public, CRYPTO_PUBLIC_KEY_SIZE, noise_handshake_temp_key,
                            noise_handshake_initiator->hash);

    ck_assert_msg(memcmp(ciphertext1, init_encrypted_static_public, CRYPTO_PUBLIC_KEY_SIZE+CRYPTO_MAC_SIZE) == 0, "initiator encrypted static public keys differ");

    /* ss */
    noise_mix_key(noise_handshake_initiator->chaining_key, noise_handshake_temp_key, 
        noise_handshake_initiator->static_private, noise_handshake_initiator->remote_static);

    /* Noise Handshake Payload */
    uint8_t ciphertext2[sizeof(init_payload_hs) + CRYPTO_MAC_SIZE];

    /* Nonce for payload encryption is _always_ 0 in case of ChaCha20-Poly1305 */
    noise_encrypt_and_hash(ciphertext2,
                            init_payload_hs, sizeof(init_payload_hs), noise_handshake_temp_key,
                            noise_handshake_initiator->hash);

    ck_assert_msg(memcmp(ciphertext2, init_payload_hs_encrypted, sizeof(init_payload_hs_encrypted)) == 0, "initiator encrypted handshake payloads differ");

    // INITIATOR: END Create handshake packet for responder

    /* RESPONDER: Consume handshake packet from initiator */
    Noise_Handshake *noise_handshake_responder = (Noise_Handshake *) calloc(1, sizeof(Noise_Handshake));
    
    uint8_t init_static_pub[CRYPTO_PUBLIC_KEY_SIZE];
    crypto_derive_public_key(init_static_pub, init_static);

    noise_handshake_init(noise_handshake_responder, resp_static, nullptr, false, prologue, sizeof(prologue));

    /* e */
    memcpy(noise_handshake_responder->remote_ephemeral, noise_handshake_initiator->ephemeral_public, CRYPTO_PUBLIC_KEY_SIZE);
    noise_mix_hash(noise_handshake_responder->hash, noise_handshake_initiator->ephemeral_public, CRYPTO_PUBLIC_KEY_SIZE);

    /* es */
    uint8_t noise_handshake_temp_key_resp[CRYPTO_SHARED_KEY_SIZE];
    noise_mix_key(noise_handshake_responder->chaining_key, noise_handshake_temp_key_resp, 
        noise_handshake_responder->static_private, noise_handshake_responder->remote_ephemeral);

    /* s */ 
    noise_decrypt_and_hash(noise_handshake_responder->remote_static, ciphertext1, CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_MAC_SIZE,
                                       noise_handshake_temp_key_resp, noise_handshake_responder->hash);

    /* ss */
    noise_mix_key(noise_handshake_responder->chaining_key, noise_handshake_temp_key_resp, noise_handshake_responder->static_private, 
        noise_handshake_responder->remote_static);

    /* Payload decryption */
    uint8_t handshake_payload_plain_initiator[sizeof(init_payload_hs)];
    noise_decrypt_and_hash(handshake_payload_plain_initiator, ciphertext2,
                                       sizeof(ciphertext2), noise_handshake_temp_key_resp,
                                       noise_handshake_responder->hash);

    /* RESPONDER: Create handshake packet for initiator */

    /* set ephemeral private+public */
    memcpy(noise_handshake_responder->ephemeral_private, resp_ephemeral, CRYPTO_SECRET_KEY_SIZE);
    crypto_derive_public_key(noise_handshake_responder->ephemeral_public, resp_ephemeral);

    ck_assert_msg(memcmp(noise_handshake_responder->ephemeral_public, resp_ephemeral_public, CRYPTO_PUBLIC_KEY_SIZE) == 0, "responder ephemeral public keys differ");

    /* e */
    noise_mix_hash(noise_handshake_responder->hash, noise_handshake_responder->ephemeral_public, CRYPTO_PUBLIC_KEY_SIZE);

    /* ee */
    uint8_t noise_handshake_temp_key_resp2[CRYPTO_SHARED_KEY_SIZE];
    noise_mix_key(noise_handshake_responder->chaining_key, noise_handshake_temp_key_resp2, noise_handshake_responder->ephemeral_private, 
        noise_handshake_responder->remote_ephemeral);

    /* se */
    noise_mix_key(noise_handshake_responder->chaining_key, noise_handshake_temp_key_resp2, noise_handshake_responder->ephemeral_private, 
        noise_handshake_responder->remote_static);

    
    /* Nonce for payload encryption is _always_ 0 in case of ChaCha20-Poly1305 */
    uint8_t ciphertext3_hs_responder[sizeof(resp_payload_hs) + CRYPTO_MAC_SIZE];
    noise_encrypt_and_hash(ciphertext3_hs_responder,
                            resp_payload_hs, sizeof(resp_payload_hs), noise_handshake_temp_key_resp2,
                            noise_handshake_responder->hash);

    ck_assert_msg(memcmp(ciphertext3_hs_responder, resp_payload_hs_encrypted, sizeof(resp_payload_hs_encrypted)) == 0, "responder encrypted handshake payloads differ");

    /* RESPONDER: END create handshake packet for initiator */

    /* INITIATOR: Consume handshake packet from responder */
    memcpy(noise_handshake_initiator->remote_ephemeral, noise_handshake_responder->ephemeral_public, CRYPTO_PUBLIC_KEY_SIZE);
    noise_mix_hash(noise_handshake_initiator->hash, noise_handshake_initiator->remote_ephemeral, CRYPTO_PUBLIC_KEY_SIZE);

    /* ee */
    uint8_t noise_handshake_temp_key_init[CRYPTO_SHARED_KEY_SIZE];
    noise_mix_key(noise_handshake_initiator->chaining_key, noise_handshake_temp_key_init, noise_handshake_initiator->ephemeral_private, 
        noise_handshake_initiator->remote_ephemeral);

    /* se */
    noise_mix_key(noise_handshake_initiator->chaining_key, noise_handshake_temp_key_init, noise_handshake_initiator->static_private, 
        noise_handshake_initiator->remote_ephemeral);

    uint8_t handshake_payload_plain_responder[sizeof(resp_payload_hs)];
    if(noise_decrypt_and_hash(handshake_payload_plain_responder, ciphertext3_hs_responder,
                                    sizeof(ciphertext3_hs_responder), noise_handshake_temp_key_init,
                                    noise_handshake_initiator->hash) != sizeof(resp_payload_hs)) {
                                    printf("Initiator: HS decryption failed\n");
    }

    /* INITIATOR Noise Split(), nonces already set in crypto connection */
    uint8_t initiator_send_key[CRYPTO_SHARED_KEY_SIZE];
    uint8_t initiator_recv_key[CRYPTO_SHARED_KEY_SIZE];
    crypto_hkdf(initiator_send_key, CRYPTO_SHARED_KEY_SIZE, initiator_recv_key, CRYPTO_SHARED_KEY_SIZE, nullptr, 0, 
        noise_handshake_initiator->chaining_key);

    ck_assert_msg(memcmp(noise_handshake_initiator->hash, handshake_hash, CRYPTO_SHA512_SIZE) == 0, "initiator handshake hash differ");

    uint8_t ciphertext4_transport1_initiator[sizeof(init_payload_transport1) + CRYPTO_MAC_SIZE];
    uint8_t nonce_chacha20_ietf[CRYPTO_NOISE_NONCE_SIZE] = {0};
    encrypt_data_symmetric_aead(initiator_send_key, nonce_chacha20_ietf, init_payload_transport1, sizeof(init_payload_transport1), ciphertext4_transport1_initiator, nullptr, 0);
    
    ck_assert_msg(memcmp(ciphertext4_transport1_initiator, init_payload_transport1_encrypted, sizeof(init_payload_transport1_encrypted)) == 0, "initiator transport1 ciphertext differ");

    /* RESPONDER Noise Split(): vice-verse keys in comparison to initiator */
    uint8_t responder_send_key[CRYPTO_SHARED_KEY_SIZE];
    uint8_t responder_recv_key[CRYPTO_SHARED_KEY_SIZE];
    crypto_hkdf(responder_recv_key, CRYPTO_SYMMETRIC_KEY_SIZE, responder_send_key, CRYPTO_SYMMETRIC_KEY_SIZE, nullptr, 0, noise_handshake_responder->chaining_key);

    ck_assert_msg(memcmp(noise_handshake_responder->hash, handshake_hash, CRYPTO_SHA512_SIZE) == 0, "responder handshake hash differ");

    uint8_t ciphertext5_transport1_responder[sizeof(resp_payload_transport1) + CRYPTO_MAC_SIZE];
    encrypt_data_symmetric_aead(responder_send_key, nonce_chacha20_ietf, 
        resp_payload_transport1, sizeof(resp_payload_transport1), ciphertext5_transport1_responder, nullptr, 0);

    ck_assert_msg(memcmp(ciphertext5_transport1_responder, resp_payload_transport1_encrypted, sizeof(resp_payload_transport1_encrypted)) == 0, "responder transport1 ciphertext differ");

    free(noise_handshake_initiator);
    free(noise_handshake_responder);
}

int main(void)
{
    setvbuf(stdout, nullptr, _IONBF, 0);

    test_known();
    test_fast_known();
    test_endtoend(); /* waiting up to 15 seconds */
    test_large_data();
    test_large_data_symmetric();
    test_very_large_data();
    test_increment_nonce();
    test_memzero();
    test_noiseik();

    return 0;
}
