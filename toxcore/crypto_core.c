/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2024 The TokTok team.
 * Copyright © 2013 Tox project.
 */

#include "crypto_core.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include <sodium.h>

#include "attributes.h"
#include "ccompat.h"
#include "mem.h"
#include "util.h"

static_assert(CRYPTO_PUBLIC_KEY_SIZE == crypto_box_PUBLICKEYBYTES,
              "CRYPTO_PUBLIC_KEY_SIZE should be equal to crypto_box_PUBLICKEYBYTES");
static_assert(CRYPTO_SECRET_KEY_SIZE == crypto_box_SECRETKEYBYTES,
              "CRYPTO_SECRET_KEY_SIZE should be equal to crypto_box_SECRETKEYBYTES");
static_assert(CRYPTO_SHARED_KEY_SIZE == crypto_box_BEFORENMBYTES,
              "CRYPTO_SHARED_KEY_SIZE should be equal to crypto_box_BEFORENMBYTES");
static_assert(CRYPTO_SYMMETRIC_KEY_SIZE == crypto_box_BEFORENMBYTES,
              "CRYPTO_SYMMETRIC_KEY_SIZE should be equal to crypto_box_BEFORENMBYTES");
static_assert(CRYPTO_MAC_SIZE == crypto_box_MACBYTES,
              "CRYPTO_MAC_SIZE should be equal to crypto_box_MACBYTES");
static_assert(CRYPTO_NONCE_SIZE == crypto_box_NONCEBYTES,
              "CRYPTO_NONCE_SIZE should be equal to crypto_box_NONCEBYTES");
static_assert(CRYPTO_HMAC_SIZE == crypto_auth_BYTES,
              "CRYPTO_HMAC_SIZE should be equal to crypto_auth_BYTES");
static_assert(CRYPTO_HMAC_KEY_SIZE == crypto_auth_KEYBYTES,
              "CRYPTO_HMAC_KEY_SIZE should be equal to crypto_auth_KEYBYTES");
static_assert(CRYPTO_SHA256_SIZE == crypto_hash_sha256_BYTES,
              "CRYPTO_SHA256_SIZE should be equal to crypto_hash_sha256_BYTES");
static_assert(CRYPTO_SHA512_SIZE == crypto_hash_sha512_BYTES,
              "CRYPTO_SHA512_SIZE should be equal to crypto_hash_sha512_BYTES");
static_assert(CRYPTO_PUBLIC_KEY_SIZE == 32,
              "CRYPTO_PUBLIC_KEY_SIZE is required to be 32 bytes for pk_equal to work");

static_assert(CRYPTO_SIGNATURE_SIZE == crypto_sign_BYTES,
              "CRYPTO_SIGNATURE_SIZE should be equal to crypto_sign_BYTES");
static_assert(CRYPTO_SIGN_PUBLIC_KEY_SIZE == crypto_sign_PUBLICKEYBYTES,
              "CRYPTO_SIGN_PUBLIC_KEY_SIZE should be equal to crypto_sign_PUBLICKEYBYTES");
static_assert(CRYPTO_SIGN_SECRET_KEY_SIZE == crypto_sign_SECRETKEYBYTES,
              "CRYPTO_SIGN_SECRET_KEY_SIZE should be equal to crypto_sign_SECRETKEYBYTES");

bool create_extended_keypair(Extended_Public_Key *pk, Extended_Secret_Key *sk, const Random *rng)
{
    /* create signature key pair */
    uint8_t seed[crypto_sign_SEEDBYTES];
    random_bytes(rng, seed, crypto_sign_SEEDBYTES);
    crypto_sign_seed_keypair(pk->sig, sk->sig, seed);
    crypto_memzero(seed, crypto_sign_SEEDBYTES);

    /* convert public signature key to public encryption key */
    const int res1 = crypto_sign_ed25519_pk_to_curve25519(pk->enc, pk->sig);

    /* convert secret signature key to secret encryption key */
    const int res2 = crypto_sign_ed25519_sk_to_curve25519(sk->enc, sk->sig);

    return res1 == 0 && res2 == 0;
}

const uint8_t *get_enc_key(const Extended_Public_Key *key)
{
    return key->enc;
}

const uint8_t *get_sig_pk(const Extended_Public_Key *key)
{
    return key->sig;
}

void set_sig_pk(Extended_Public_Key *key, const uint8_t *sig_pk)
{
    memcpy(key->sig, sig_pk, SIG_PUBLIC_KEY_SIZE);
}

const uint8_t *get_sig_sk(const Extended_Secret_Key *key)
{
    return key->sig;
}

const uint8_t *get_chat_id(const Extended_Public_Key *key)
{
    return key->sig;
}

#if !defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
non_null()
static uint8_t *crypto_malloc(const Memory *mem, size_t bytes)
{
    uint8_t *ptr = (uint8_t *)mem_balloc(mem, bytes);

    if (ptr != nullptr) {
        crypto_memlock(ptr, bytes);
    }

    return ptr;
}

non_null(1) nullable(2)
static void crypto_free(const Memory *mem, uint8_t *ptr, size_t bytes)
{
    if (ptr != nullptr) {
        crypto_memzero(ptr, bytes);
        crypto_memunlock(ptr, bytes);
    }

    mem_delete(mem, ptr);
}
#endif /* !defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) */

void crypto_memzero(void *data, size_t length)
{
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
    memzero((uint8_t *)data, length);
#else
    sodium_memzero(data, length);
#endif /* FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION */
}

bool crypto_memlock(void *data, size_t length)
{
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
    return false;
#else

    return sodium_mlock(data, length) == 0;
#endif /* FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION */
}

bool crypto_memunlock(void *data, size_t length)
{
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
    return false;
#else

    return sodium_munlock(data, length) == 0;
#endif /* FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION */
}

bool pk_equal(const uint8_t pk1[CRYPTO_PUBLIC_KEY_SIZE], const uint8_t pk2[CRYPTO_PUBLIC_KEY_SIZE])
{
#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
    // Hope that this is better for the fuzzer
    return memcmp(pk1, pk2, CRYPTO_PUBLIC_KEY_SIZE) == 0;
#else
    return crypto_verify_32(pk1, pk2) == 0;
#endif /* FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION */
}

void pk_copy(uint8_t dest[CRYPTO_PUBLIC_KEY_SIZE], const uint8_t src[CRYPTO_PUBLIC_KEY_SIZE])
{
    memcpy(dest, src, CRYPTO_PUBLIC_KEY_SIZE);
}

bool crypto_sha512_eq(const uint8_t cksum1[CRYPTO_SHA512_SIZE], const uint8_t cksum2[CRYPTO_SHA512_SIZE])
{
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
    // Hope that this is better for the fuzzer
    return memcmp(cksum1, cksum2, CRYPTO_SHA512_SIZE) == 0;
#else
    return crypto_verify_64(cksum1, cksum2) == 0;
#endif /* FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION */
}

bool crypto_sha256_eq(const uint8_t cksum1[CRYPTO_SHA256_SIZE], const uint8_t cksum2[CRYPTO_SHA256_SIZE])
{
#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
    // Hope that this is better for the fuzzer
    return memcmp(cksum1, cksum2, CRYPTO_SHA256_SIZE) == 0;
#else
    return crypto_verify_32(cksum1, cksum2) == 0;
#endif /* FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION */
}

uint8_t random_u08(const Random *rng)
{
    uint8_t randnum;
    random_bytes(rng, &randnum, 1);
    return randnum;
}

uint16_t random_u16(const Random *rng)
{
    uint16_t randnum;
    random_bytes(rng, (uint8_t *)&randnum, sizeof(randnum));
    return randnum;
}

uint32_t random_u32(const Random *rng)
{
    uint32_t randnum;
    random_bytes(rng, (uint8_t *)&randnum, sizeof(randnum));
    return randnum;
}

uint64_t random_u64(const Random *rng)
{
    uint64_t randnum;
    random_bytes(rng, (uint8_t *)&randnum, sizeof(randnum));
    return randnum;
}

uint32_t random_range_u32(const Random *rng, uint32_t upper_bound)
{
    return rng->funcs->random_uniform(rng->obj, upper_bound);
}

bool crypto_signature_create(uint8_t signature[CRYPTO_SIGNATURE_SIZE],
                             const uint8_t *message, uint64_t message_length,
                             const uint8_t secret_key[SIG_SECRET_KEY_SIZE])
{
    return crypto_sign_detached(signature, nullptr, message, message_length, secret_key) == 0;
}

bool crypto_signature_verify(const uint8_t signature[CRYPTO_SIGNATURE_SIZE],
                             const uint8_t *message, uint64_t message_length,
                             const uint8_t public_key[SIG_PUBLIC_KEY_SIZE])
{
    return crypto_sign_verify_detached(signature, message, message_length, public_key) == 0;
}

bool public_key_valid(const uint8_t public_key[CRYPTO_PUBLIC_KEY_SIZE])
{
    /* Last bit of key is always zero. */
    return public_key[31] < 128;
}

int32_t encrypt_precompute(const uint8_t public_key[CRYPTO_PUBLIC_KEY_SIZE],
                           const uint8_t secret_key[CRYPTO_SECRET_KEY_SIZE],
                           uint8_t shared_key[CRYPTO_SHARED_KEY_SIZE])
{
#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
    memcpy(shared_key, public_key, CRYPTO_SHARED_KEY_SIZE);
    return 0;
#else
    return crypto_box_beforenm(shared_key, public_key, secret_key);
#endif /* FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION */
}

int32_t encrypt_data_symmetric(const Memory *mem,
                               const uint8_t shared_key[CRYPTO_SHARED_KEY_SIZE],
                               const uint8_t nonce[CRYPTO_NONCE_SIZE],
                               const uint8_t *plain, size_t length, uint8_t *encrypted)
{
    if (length == 0 || shared_key == nullptr || nonce == nullptr || plain == nullptr || encrypted == nullptr) {
        return -1;
    }

#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
    // Don't encrypt anything.
    memcpy(encrypted, plain, length);
    // Zero MAC to avoid uninitialized memory reads.
    memzero(encrypted + length, crypto_box_MACBYTES);
#else

    const size_t size_temp_plain = length + crypto_box_ZEROBYTES;
    const size_t size_temp_encrypted = length + crypto_box_MACBYTES + crypto_box_BOXZEROBYTES;

    uint8_t *temp_plain = crypto_malloc(mem, size_temp_plain);
    uint8_t *temp_encrypted = crypto_malloc(mem, size_temp_encrypted);

    if (temp_plain == nullptr || temp_encrypted == nullptr) {
        crypto_free(mem, temp_plain, size_temp_plain);
        crypto_free(mem, temp_encrypted, size_temp_encrypted);
        return -1;
    }

    // crypto_box_afternm requires the entire range of the output array be
    // initialised with something. It doesn't matter what it's initialised with,
    // so we'll pick 0x00.
    memzero(temp_encrypted, size_temp_encrypted);

    memzero(temp_plain, crypto_box_ZEROBYTES);
    // Pad the message with 32 0 bytes.
    memcpy(temp_plain + crypto_box_ZEROBYTES, plain, length);

    if (crypto_box_afternm(temp_encrypted, temp_plain, length + crypto_box_ZEROBYTES, nonce,
                           shared_key) != 0) {
        crypto_free(mem, temp_plain, size_temp_plain);
        crypto_free(mem, temp_encrypted, size_temp_encrypted);
        return -1;
    }

    // Unpad the encrypted message.
    memcpy(encrypted, temp_encrypted + crypto_box_BOXZEROBYTES, length + crypto_box_MACBYTES);

    crypto_free(mem, temp_plain, size_temp_plain);
    crypto_free(mem, temp_encrypted, size_temp_encrypted);
#endif /* FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION */
    assert(length < INT32_MAX - crypto_box_MACBYTES);
    return (int32_t)(length + crypto_box_MACBYTES);
}

int32_t decrypt_data_symmetric(const Memory *mem,
                               const uint8_t shared_key[CRYPTO_SHARED_KEY_SIZE],
                               const uint8_t nonce[CRYPTO_NONCE_SIZE],
                               const uint8_t *encrypted, size_t length, uint8_t *plain)
{
    if (length <= crypto_box_BOXZEROBYTES || shared_key == nullptr || nonce == nullptr || encrypted == nullptr
            || plain == nullptr) {
        return -1;
    }

#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
    assert(length >= crypto_box_MACBYTES);
    memcpy(plain, encrypted, length - crypto_box_MACBYTES);  // Don't encrypt anything
#else

    const size_t size_temp_plain = length + crypto_box_ZEROBYTES;
    const size_t size_temp_encrypted = length + crypto_box_BOXZEROBYTES;

    uint8_t *temp_plain = crypto_malloc(mem, size_temp_plain);
    uint8_t *temp_encrypted = crypto_malloc(mem, size_temp_encrypted);

    if (temp_plain == nullptr || temp_encrypted == nullptr) {
        crypto_free(mem, temp_plain, size_temp_plain);
        crypto_free(mem, temp_encrypted, size_temp_encrypted);
        return -1;
    }

    // crypto_box_open_afternm requires the entire range of the output array be
    // initialised with something. It doesn't matter what it's initialised with,
    // so we'll pick 0x00.
    memzero(temp_plain, size_temp_plain);

    memzero(temp_encrypted, crypto_box_BOXZEROBYTES);
    // Pad the message with 16 0 bytes.
    memcpy(temp_encrypted + crypto_box_BOXZEROBYTES, encrypted, length);

    if (crypto_box_open_afternm(temp_plain, temp_encrypted, length + crypto_box_BOXZEROBYTES, nonce,
                                shared_key) != 0) {
        crypto_free(mem, temp_plain, size_temp_plain);
        crypto_free(mem, temp_encrypted, size_temp_encrypted);
        return -1;
    }

    memcpy(plain, temp_plain + crypto_box_ZEROBYTES, length - crypto_box_MACBYTES);

    crypto_free(mem, temp_plain, size_temp_plain);
    crypto_free(mem, temp_encrypted, size_temp_encrypted);
#endif /* FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION */
    assert(length > crypto_box_MACBYTES);
    assert(length < INT32_MAX);
    return (int32_t)(length - crypto_box_MACBYTES);
}

int32_t encrypt_data(const Memory *mem,
                     const uint8_t public_key[CRYPTO_PUBLIC_KEY_SIZE],
                     const uint8_t secret_key[CRYPTO_SECRET_KEY_SIZE],
                     const uint8_t nonce[CRYPTO_NONCE_SIZE],
                     const uint8_t *plain, size_t length, uint8_t *encrypted)
{
    if (public_key == nullptr || secret_key == nullptr) {
        return -1;
    }

    uint8_t k[crypto_box_BEFORENMBYTES];
    encrypt_precompute(public_key, secret_key, k);
    const int ret = encrypt_data_symmetric(mem, k, nonce, plain, length, encrypted);
    crypto_memzero(k, sizeof(k));
    return ret;
}

int32_t decrypt_data(const Memory *mem,
                     const uint8_t public_key[CRYPTO_PUBLIC_KEY_SIZE],
                     const uint8_t secret_key[CRYPTO_SECRET_KEY_SIZE],
                     const uint8_t nonce[CRYPTO_NONCE_SIZE],
                     const uint8_t *encrypted, size_t length, uint8_t *plain)
{
    if (public_key == nullptr || secret_key == nullptr) {
        return -1;
    }

    uint8_t k[crypto_box_BEFORENMBYTES];
    encrypt_precompute(public_key, secret_key, k);
    const int ret = decrypt_data_symmetric(mem, k, nonce, encrypted, length, plain);
    crypto_memzero(k, sizeof(k));
    return ret;
}

void increment_nonce(uint8_t nonce[CRYPTO_NONCE_SIZE])
{
    /* TODO(irungentoo): use `increment_nonce_number(nonce, 1)` or
     * sodium_increment (change to little endian).
     *
     * NOTE don't use breaks inside this loop.
     * In particular, make sure, as far as possible,
     * that loop bounds and their potential underflow or overflow
     * are independent of user-controlled input (you may have heard of the Heartbleed bug).
     */
    uint_fast16_t carry = 1U;

    for (uint32_t i = crypto_box_NONCEBYTES; i != 0; --i) {
        carry += (uint_fast16_t)nonce[i - 1];
        nonce[i - 1] = (uint8_t)carry;
        carry >>= 8;
    }
}

void increment_nonce_number(uint8_t nonce[CRYPTO_NONCE_SIZE], uint32_t increment)
{
    /* NOTE don't use breaks inside this loop
     * In particular, make sure, as far as possible,
     * that loop bounds and their potential underflow or overflow
     * are independent of user-controlled input (you may have heard of the Heartbleed bug).
     */
    uint8_t num_as_nonce[crypto_box_NONCEBYTES] = {0};
    num_as_nonce[crypto_box_NONCEBYTES - 4] = increment >> 24;
    num_as_nonce[crypto_box_NONCEBYTES - 3] = increment >> 16;
    num_as_nonce[crypto_box_NONCEBYTES - 2] = increment >> 8;
    num_as_nonce[crypto_box_NONCEBYTES - 1] = increment;

    uint_fast16_t carry = 0U;

    for (uint32_t i = crypto_box_NONCEBYTES; i != 0; --i) {
        carry += (uint_fast16_t)nonce[i - 1] + (uint_fast16_t)num_as_nonce[i - 1];
        nonce[i - 1] = (uint8_t)carry;
        carry >>= 8;
    }
}

void random_nonce(const Random *rng, uint8_t nonce[CRYPTO_NONCE_SIZE])
{
    random_bytes(rng, nonce, crypto_box_NONCEBYTES);
}

void new_symmetric_key(const Random *rng, uint8_t key[CRYPTO_SYMMETRIC_KEY_SIZE])
{
    random_bytes(rng, key, CRYPTO_SYMMETRIC_KEY_SIZE);
}

int32_t crypto_new_keypair(const Random *rng,
                           uint8_t public_key[CRYPTO_PUBLIC_KEY_SIZE],
                           uint8_t secret_key[CRYPTO_SECRET_KEY_SIZE])
{
    random_bytes(rng, secret_key, CRYPTO_SECRET_KEY_SIZE);
    memzero(public_key, CRYPTO_PUBLIC_KEY_SIZE);  // Make MSAN happy
    crypto_derive_public_key(public_key, secret_key);
    return 0;
}

void crypto_derive_public_key(uint8_t public_key[CRYPTO_PUBLIC_KEY_SIZE],
                              const uint8_t secret_key[CRYPTO_SECRET_KEY_SIZE])
{
    crypto_scalarmult_curve25519_base(public_key, secret_key);
}

void new_hmac_key(const Random *rng, uint8_t key[CRYPTO_HMAC_KEY_SIZE])
{
    random_bytes(rng, key, CRYPTO_HMAC_KEY_SIZE);
}

void crypto_hmac(uint8_t auth[CRYPTO_HMAC_SIZE], const uint8_t key[CRYPTO_HMAC_KEY_SIZE],
                 const uint8_t *data, size_t length)
{
#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
    memcpy(auth, key, 16);
    memcpy(auth + 16, data, length < 16 ? length : 16);
#else
    crypto_auth(auth, data, length, key);
#endif /* FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION */
}

bool crypto_hmac_verify(const uint8_t auth[CRYPTO_HMAC_SIZE], const uint8_t key[CRYPTO_HMAC_KEY_SIZE],
                        const uint8_t *data, size_t length)
{
#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
    return memcmp(auth, key, 16) == 0 && memcmp(auth + 16, data, length < 16 ? length : 16) == 0;
#else
    return crypto_auth_verify(auth, data, length, key) == 0;
#endif /* FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION */
}

void crypto_sha256(uint8_t hash[CRYPTO_SHA256_SIZE], const uint8_t *data, size_t length)
{
#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
    memzero(hash, CRYPTO_SHA256_SIZE);
    memcpy(hash, data, length < CRYPTO_SHA256_SIZE ? length : CRYPTO_SHA256_SIZE);
#else
    crypto_hash_sha256(hash, data, length);
#endif /* FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION */
}

void crypto_sha512(uint8_t hash[CRYPTO_SHA512_SIZE], const uint8_t *data, size_t length)
{
#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
    memzero(hash, CRYPTO_SHA512_SIZE);
    memcpy(hash, data, length < CRYPTO_SHA512_SIZE ? length : CRYPTO_SHA512_SIZE);
#else
    crypto_hash_sha512(hash, data, length);
#endif /* FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION */
}

non_null()
static void sys_random_bytes(void *obj, uint8_t *bytes, size_t length)
{
    randombytes(bytes, length);
}

non_null()
static uint32_t sys_random_uniform(void *obj, uint32_t upper_bound)
{
    return randombytes_uniform(upper_bound);
}

static const Random_Funcs os_random_funcs = {
    sys_random_bytes,
    sys_random_uniform,
};

static const Random os_random_obj = {&os_random_funcs};

const Random *os_random(void)
{
#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
    if ((true)) {
        return nullptr;
    }
#endif /* FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION */
    // It is safe to call this function more than once and from different
    // threads -- subsequent calls won't have any effects.
    if (sodium_init() == -1) {
        return nullptr;
    }
    return &os_random_obj;
}

void random_bytes(const Random *rng, uint8_t *bytes, size_t length)
{
    rng->funcs->random_bytes(rng->obj, bytes, length);
}

/* Necessary functions for Noise, cf. https://noiseprotocol.org/noise.html (Revision 34) */

int32_t encrypt_data_symmetric_aead(const uint8_t shared_key[CRYPTO_SHARED_KEY_SIZE], const uint8_t nonce[CRYPTO_NOISEIK_NONCE_SIZE],
                                    const uint8_t *plain, size_t plain_length, uint8_t *encrypted,
                                    const uint8_t *ad, size_t ad_length)
{
    /* Additional data ad can be a NULL pointer with ad_length equal to 0; encrypted_length is calculated by libsodium */
    if (plain_length == 0 || shared_key == nullptr || nonce == nullptr || plain == nullptr || encrypted == nullptr) {
        return -1;
    }

    /* Passing NULL instead, encrypted length is clear anwyay (plain_length + crypto_aead_chacha20poly1305_IETF_ABYTES)  */
    // unsigned long long encrypted_length = 0;

    /* nsec is not used by this particular construction and should always be NULL. */ 
    if (crypto_aead_chacha20poly1305_ietf_encrypt(encrypted, NULL, plain, plain_length,
            ad, ad_length, nullptr, nonce, shared_key) != 0) {
        return -1;
    }

    assert(plain_length < INT32_MAX - crypto_aead_chacha20poly1305_IETF_ABYTES);
    return (int32_t)(plain_length + crypto_aead_chacha20poly1305_IETF_ABYTES);
}

int32_t decrypt_data_symmetric_aead(const uint8_t shared_key[CRYPTO_SHARED_KEY_SIZE], const uint8_t nonce[CRYPTO_NOISEIK_NONCE_SIZE],
                                    const uint8_t *encrypted, size_t encrypted_length, uint8_t *plain,
                                    const uint8_t *ad, size_t ad_length)
{
    /* Additional data ad can be a NULL pointer with ad_length equal to 0;  plain_length is calculated by libsodium */ 
    if (encrypted_length <= CRYPTO_MAC_SIZE || shared_key == nullptr || nonce == nullptr || encrypted == nullptr
            || plain == nullptr) {
        return -1;
    }

    /* Passing NULL instead, encrypted length is clear anwyay (plain_length + crypto_aead_chacha20poly1305_IETF_ABYTES)  */
    // unsigned long long plain_length = 0;

    if (crypto_aead_chacha20poly1305_ietf_decrypt(plain, NULL, nullptr, encrypted,
            encrypted_length, ad, ad_length, nonce, shared_key) != 0) {
        return -1;
    }

    assert(encrypted_length > crypto_aead_chacha20poly1305_IETF_ABYTES);
    assert(encrypted_length < INT32_MAX);
    return (int32_t)(encrypted_length - crypto_aead_chacha20poly1305_IETF_ABYTES);
}

int32_t encrypt_data_symmetric_xaead(const uint8_t shared_key[CRYPTO_SHARED_KEY_SIZE], const uint8_t nonce[CRYPTO_NONCE_SIZE],
                                    const uint8_t *plain, size_t plain_length, uint8_t *encrypted,
                                    const uint8_t *ad, size_t ad_length)
{
    /* Additional data ad can be a NULL pointer with ad_length equal to 0; encrypted_length is calculated by libsodium */
    if (plain_length == 0 || shared_key == nullptr || nonce == nullptr || plain == nullptr || encrypted == nullptr) {
        return -1;
    }

    /* Passing NULL instead, encrypted length is clear anwyay (plain_length + crypto_aead_xchacha20poly1305_ietf_ABYTES)  */
    // unsigned long long encrypted_length = 0;

    /* nsec is not used by this particular construction and should always be NULL. */
    if (crypto_aead_xchacha20poly1305_ietf_encrypt(encrypted, NULL, plain, plain_length,
            ad, ad_length, nullptr, nonce, shared_key) != 0) {
        return -1;
    }

    assert(plain_length < INT32_MAX - crypto_aead_xchacha20poly1305_ietf_ABYTES);
    return (int32_t)(plain_length + crypto_aead_xchacha20poly1305_ietf_ABYTES);
}

int32_t decrypt_data_symmetric_xaead(const uint8_t shared_key[CRYPTO_SHARED_KEY_SIZE], const uint8_t nonce[CRYPTO_NONCE_SIZE],
                                    const uint8_t *encrypted, size_t encrypted_length, uint8_t *plain,
                                    const uint8_t *ad, size_t ad_length)
{
    /* Additional data ad can be a NULL pointer with ad_length equal to 0;  plain_length is calculated by libsodium */
    if (encrypted_length <= CRYPTO_MAC_SIZE || shared_key == nullptr || nonce == nullptr || encrypted == nullptr
            || plain == nullptr) {
        return -1;
    }

    /* Passing NULL instead, encrypted length is clear anwyay (plain_length + crypto_aead_xchacha20poly1305_ietf_ABYTES)  */
    // unsigned long long plain_length = 0;

    if (crypto_aead_xchacha20poly1305_ietf_decrypt(plain, NULL, nullptr, encrypted,
            encrypted_length, ad, ad_length, nonce, shared_key) != 0) {
        return -1;
    }

    assert(encrypted_length > crypto_aead_xchacha20poly1305_ietf_ABYTES);
    assert(encrypted_length < INT32_MAX);
    return (int32_t)(encrypted_length - crypto_aead_xchacha20poly1305_ietf_ABYTES);
}

/*
* TODO: Helper function to print hashes, keys, packets, etc.
* TODO: remove from production code or make dependent on MIN_LOGGER_LEVEL=DEBUG?
* bytes_to_string() from util.h
*/
// static void bytes2string(char *string, size_t string_length, const uint8_t *bytes, size_t bytes_length)
// {   
//     bytes_to_string(bytes, bytes_length, string, string_length);
// }

// #define NOISE_PROTOCOL_NAME "Noise_IK_25519_ChaChaPoly_SHA512"
/* Actually only 32 bytes necessary (but terminator necessary for CI), but test vectors still verify with 33 bytes */
//TODO: Remove if Blake2b
// static const uint8_t noise_protocol[33] = "Noise_IK_25519_ChaChaPoly_SHA512";
static const uint8_t noise_protocol[34] = "Noise_IK_25519_ChaChaPoly_BLAKE2b";

//TODO: remove, unused function
/**
 * cf. Noise sections 4.3 and 5.1
 * Applies HMAC from RFC2104 (https://www.ietf.org/rfc/rfc2104.txt) using the HASH() (=SHA512) function.
 * This function is only called via `crypto_hkdf()`.
 * HMAC-SHA-512 instead of HMAC-SHA512-256 as used by `crypto_auth_*()` (libsodium) which is underlying function of
 * `crypto_hmac*()` in crypto_core. Necessary for Noise (cf. section 4.3) to return 64 bytes (SHA512 HASHLEN) instead of
 * of 32 bytes (SHA512-256 HASHLEN). Cf. https://doc.libsodium.org/advanced/hmac-sha2#hmac-sha-512
 * key is CRYPTO_SHA512_SIZE bytes because this function is only called via crypto_hkdf() where the key (ck, temp_key)
 * is always HASHLEN bytes.
 */
void crypto_hmac512(uint8_t *auth, const uint8_t key[CRYPTO_SHA512_SIZE], const uint8_t *data,
                    size_t data_length)
{
    crypto_auth_hmacsha512(auth, data, data_length, key);
}

/**
 * cf. Noise sections 4.3 and 5.1
 * Applies HMAC from RFC2104 (https://www.ietf.org/rfc/rfc2104.txt) using the HASH() (=BLAKE2b) function.
 * This function is only called via `crypto_hkdf()`.
 * Necessary for Noise (cf. sections 4.3 and 12.8) to return 64 bytes (BLAKE2b HASHLEN). 
 * Cf. https://doc.libsodium.org/hashing/generic_hashing
 * TODO: Still true?
 * key is CRYPTO_BLAKE2b_HASH_SIZE bytes because this function is only called via crypto_hkdf() where the key (ck, temp_key)
 * is always HASHLEN bytes.
 */
static void crypto_hmac_blake2b512(uint8_t *out, const uint8_t *in, size_t in_length, const uint8_t *key,
                    size_t key_length)
{
    crypto_generichash_blake2b_state state;

    /*
    * (1) append zeros to the end of K to create a B byte string (e.g., if K is of length 20 bytes and B=64, 
    * then K will be appended with 44 zero bytes 0x00) 
    * B = Blake2b block length = 128
    * L the byte-length of Blake2b hash output = 64 
    */
	uint8_t x_key[CRYPTO_BLAKE2b_BLOCK_SIZE] = { 0 };
	uint8_t i_hash[CRYPTO_BLAKE2b_HASH_SIZE];
	int i;

    /* 
    * The authentication key K can be of any length up to B, the
    * block length of the hash function.  Applications that use keys longer
    * than B bytes will first hash the key using H and then use the
    * resultant L byte string as the actual key to HMAC.
    * In any case the minimal recommended length for K is L bytes (as the hash output
    * length).
    */ 
	if (key_length > CRYPTO_BLAKE2b_BLOCK_SIZE) {
		crypto_generichash_blake2b_init(&state, NULL, 0, CRYPTO_BLAKE2b_HASH_SIZE);
		crypto_generichash_blake2b_update(&state, key, key_length);
		crypto_generichash_blake2b_final(&state, x_key, CRYPTO_BLAKE2b_BLOCK_SIZE);
	} else {
		memcpy(x_key, key, key_length);
    }

    /*
    * K XOR ipad, ipad = the byte 0x36 repeated B times
    * (2) XOR (bitwise exclusive-OR) the B byte string computed in step
    * (1) with ipad 
    */
	for (i = 0; i < CRYPTO_BLAKE2b_BLOCK_SIZE; ++i) {
		x_key[i] ^= 0x36;
    }

    /* 
    * H(K XOR ipad, text)
    * (3) append the stream of data 'text' to the B byte string resulting
        from step (2)
        (4) apply H to the stream generated in step (3)
    */
	crypto_generichash_blake2b_init(&state, NULL, 0, CRYPTO_BLAKE2b_HASH_SIZE);
	crypto_generichash_blake2b_update(&state, x_key, CRYPTO_BLAKE2b_BLOCK_SIZE);
	crypto_generichash_blake2b_update(&state, in, in_length);
	crypto_generichash_blake2b_final(&state, i_hash, CRYPTO_BLAKE2b_HASH_SIZE);

    /* 
    * K XOR opad, opad = the byte 0x5C repeated B times
    * (5) XOR (bitwise exclusive-OR) the B byte string computed in
        step (1) with opad
    */
	for (i = 0; i < CRYPTO_BLAKE2b_BLOCK_SIZE; ++i) {
        x_key[i] ^= 0x5c ^ 0x36;
    }

    /*
    * H(K XOR opad, H(K XOR ipad, text))
    * (6) append the H result from step (4) to the B byte string
        resulting from step (5)
        (7) apply H to the stream generated in step (6) and output
        the result
    */
	crypto_generichash_blake2b_init(&state, NULL, 0, CRYPTO_BLAKE2b_HASH_SIZE);
	crypto_generichash_blake2b_update(&state, x_key, CRYPTO_BLAKE2b_BLOCK_SIZE);
	crypto_generichash_blake2b_update(&state, i_hash, CRYPTO_BLAKE2b_HASH_SIZE);
	crypto_generichash_blake2b_final(&state, i_hash, CRYPTO_BLAKE2b_HASH_SIZE);

	memcpy(out, i_hash, CRYPTO_BLAKE2b_HASH_SIZE);

    /* Clear sensitive data from stack */
    crypto_memzero(x_key, CRYPTO_BLAKE2b_BLOCK_SIZE);
    crypto_memzero(i_hash, CRYPTO_BLAKE2b_HASH_SIZE);
}

/* This is Hugo Krawczyk's HKDF (i.e. HKDF-SHA512):
 * - https://eprint.iacr.org/2010/264.pdf
 * - https://tools.ietf.org/html/rfc5869
 * HKDF(chaining_key, input_key_material, num_outputs): Takes a
 * chaining_key byte sequence of length HASHLEN, and an input_key_material
 * byte sequence with length either zero bytes, 32 bytes, or DHLEN bytes.
 * Returns a pair or triple of byte sequences each of length HASHLEN,
 * depending on whether num_outputs is two or three:
 * – Sets temp_key = HMAC-HASH(chaining_key, input_key_material).
 * – Sets output1 = HMAC-HASH(temp_key, byte(0x01)).
 * – Sets output2 = HMAC-HASH(temp_key, output1 || byte(0x02)).
 * – If num_outputs == 2 then returns the pair (output1, output2).
 * – Sets output3 = HMAC-HASH(temp_key, output2 || byte(0x03)).
 * – Returns the triple (output1, output2, output3).
 * Note that temp_key, output1, output2, and output3 are all HASHLEN bytes in
 * length. Also note that the HKDF() function is simply HKDF with the
 * chaining_key as HKDF salt, and zero-length HKDF info.
 */
// void crypto_hkdf(uint8_t *output1, size_t first_len, uint8_t *output2, 
//                  size_t second_len, const uint8_t *data,
//                  size_t data_len, const uint8_t chaining_key[CRYPTO_SHA512_SIZE])
// {
//     /* Implementing HKDF-SHA512 based on libsodium `crypto_auth_hmacsha512()` and WireGuard leads to wrong results. 
//      Verified using Noise_IK_25519_ChaChaPoly_SHA512 test vectors. Keeping for documentation purposes. */
//     // uint8_t output[CRYPTO_SHA512_SIZE + 1];
//     // temp_key = secret in WG
//     uint8_t temp_key[CRYPTO_SHA512_SIZE];

//     /* Extract entropy from data into temp_key */
//     /* HKDF-Extract(salt, IKM) -> PRK, where chaining_key is HKDF salt, DH result (data) is input keying material (IKM) (and zero-length HKDF info in expand). 
//      Result is a pseudo random key (PRK) = temp_key */
//     /* data => input_key_material => X25519-DH result in Noise */ 
//     /* TODO: This is correct, same result as libsodium `crypto_kdf_hkdf_sha512_extract()` */
//     // crypto_hmac512(temp_key, chaining_key, data, data_len);
//     /* Noise spec: Note that temp_key, output1, output2, and output3 are all HASHLEN bytes in length. 
//      Also note that the HKDF() function is simply HKDF from [4] with the chaining_key as HKDF salt, and zero-length HKDF info. */
//     crypto_kdf_hkdf_sha512_extract(temp_key, chaining_key, CRYPTO_SHA512_SIZE, data, data_len);

//     /* Expand first key: key = temp_key, data = 0x1 */
//     /* TODO: Result not correct, unsure why */
//     // output[0] = 1;
//     // crypto_hmac512(output, temp_key, output, 1);
//     // memcpy(output1, output, first_len);

//     /* Expand both keys in one operation (verified): */ 
//     /* HKDF-Expand(PRK, info, L) -> OKM, where PRK = temp_key, zero-length HKDF info (ctx)
//      and L (length of output keying material in octets) = 2*64 byte (i.e. 2x HashLen) */
//     /* OKM = HKDF -> T(0) + T(1); cf. RFC5869: https://datatracker.ietf.org/doc/html/rfc5869#section-2.3 */
//     /* ctx parameter = RFC5869 info -> i.e. optional context and application specific information (can be a zero-length string) */
//     uint8_t output_temp[CRYPTO_SHA512_SIZE*2];
//     crypto_kdf_hkdf_sha512_expand(output_temp, CRYPTO_SHA512_SIZE*2, nullptr, 0, temp_key);
//     memcpy(output1, output_temp, first_len);
//     memcpy(output2, output_temp + CRYPTO_SHA512_SIZE, second_len);

//     /* Expand second key: key = secret, data = first-key || 0x2 */
//     /* TODO: Not correct, unsure why */
//     // output[CRYPTO_SHA512_SIZE] = 2;
//     // crypto_hmac512(output, temp_key, output, CRYPTO_SHA512_SIZE + 1);
//     // memcpy(output2, output, second_len);

//     /* Expand third key: key = temp_key, data = second-key || 0x3 */
//     /* Currently output3 is not used in Tox, maybe necessary in future for pre-shared symmetric keys (cf. Noise spec )*/
//     // output[CRYPTO_SHA512_SIZE] = 3;
//     // crypto_hmac512(output, temp_key, output, CRYPTO_SHA512_SIZE + 1);
//     // memcpy(output3, output, third_len);

//     /* Clear sensitive data from stack */
//     crypto_memzero(temp_key, CRYPTO_SHA512_SIZE);
//     // crypto_memzero(output, CRYPTO_SHA512_SIZE + 1);
//     crypto_memzero(output_temp, CRYPTO_SHA512_SIZE*2);
// }

/* This is Hugo Krawczyk's HKDF (i.e. HKDF-BLAKE2b):
 * - https://eprint.iacr.org/2010/264.pdf
 * - https://tools.ietf.org/html/rfc5869
 * HKDF(chaining_key, input_key_material, num_outputs): Takes a
 * chaining_key byte sequence of length HASHLEN, and an input_key_material
 * byte sequence with length either zero bytes, 32 bytes, or DHLEN bytes.
 * Returns a pair or triple of byte sequences each of length HASHLEN,
 * depending on whether num_outputs is two or three:
 * – Sets temp_key = HMAC-HASH(chaining_key, input_key_material).
 * – Sets output1 = HMAC-HASH(temp_key, byte(0x01)).
 * – Sets output2 = HMAC-HASH(temp_key, output1 || byte(0x02)).
 * – If num_outputs == 2 then returns the pair (output1, output2).
 * – Sets output3 = HMAC-HASH(temp_key, output2 || byte(0x03)).
 * – Returns the triple (output1, output2, output3).
 * Note that temp_key, output1, output2, and output3 are all HASHLEN bytes in
 * length. Also note that the HKDF() function is simply HKDF with the
 * chaining_key as HKDF salt, and zero-length HKDF info.
 * 
 * Verified using Noise_IK_25519_ChaChaPoly_BLAKE2b test vectors.
 */
void crypto_hkdf(uint8_t *output1, size_t first_len, uint8_t *output2, 
                 size_t second_len, const uint8_t *data,
                 size_t data_len, const uint8_t chaining_key[CRYPTO_BLAKE2b_HASH_SIZE])
{
    uint8_t output[CRYPTO_BLAKE2b_HASH_SIZE + 1];
    // temp_key = secret in WG
    uint8_t temp_key[CRYPTO_BLAKE2b_HASH_SIZE];

    /* Extract entropy from data into temp_key */
    /* HKDF-Extract(salt, IKM) -> PRK, where chaining_key is HKDF salt, DH result (data) is input keying material (IKM) (and zero-length HKDF info in expand). 
     Result is a pseudo random key (PRK) = temp_key */
    /* data => input_key_material => X25519-DH result in Noise */ 
    crypto_hmac_blake2b512(temp_key, data, data_len, chaining_key, CRYPTO_BLAKE2b_HASH_SIZE);
    /* Noise spec: Note that temp_key, output1, output2, and output3 are all HASHLEN bytes in length. 
     Also note that the HKDF() function is simply HKDF from [4] with the chaining_key as HKDF salt, and zero-length HKDF info. */

    /* Expand first key: key = temp_key, data = 0x1 */
    output[0] = 1;
    crypto_hmac_blake2b512(output, output, 1, temp_key, CRYPTO_BLAKE2b_HASH_SIZE);
    memcpy(output1, output, first_len);

    /* Expand both keys in one operation (verified): */ 
    /* HKDF-Expand(PRK, info, L) -> OKM, where PRK = temp_key, zero-length HKDF info (ctx)
     and L (length of output keying material in octets) = 2*64 byte (i.e. 2x HashLen) */
    /* OKM = HKDF -> T(0) + T(1); cf. RFC5869: https://datatracker.ietf.org/doc/html/rfc5869#section-2.3 */
    /* ctx parameter = RFC5869 info -> i.e. optional context and application specific information (can be a zero-length string) */

    /* Expand second key: key = secret, data = first-key || 0x2 */
    output[CRYPTO_SHA512_SIZE] = 2;
    crypto_hmac_blake2b512(output, output, CRYPTO_BLAKE2b_HASH_SIZE +1, temp_key, CRYPTO_BLAKE2b_HASH_SIZE);
    memcpy(output2, output, second_len);

    /* Expand third key: key = temp_key, data = second-key || 0x3 */
    /* Currently output3 is not used in Tox, maybe necessary in future for pre-shared symmetric keys (cf. Noise spec )*/
    // output[CRYPTO_SHA512_SIZE] = 3;
    // crypto_hmac512(output, temp_key, output, CRYPTO_SHA512_SIZE + 1);
    // memcpy(output3, output, third_len);

    /* Clear sensitive data from stack */
    crypto_memzero(temp_key, CRYPTO_SHA512_SIZE);
    crypto_memzero(output, CRYPTO_SHA512_SIZE + 1);
}

/*
 * cf. Noise section 5.2
 * Executes the following steps:
 * - Sets ck, temp_k = HKDF(ck, input_key_material, 2).
 * - If HASHLEN is 64, then truncates temp_k to 32 bytes
 * - Calls InitializeKey(temp_k).
 * input_key_material = DH_X25519(private, public)
 * 
 * based on HKDF-SHA512
 */
// int32_t noise_mix_key(uint8_t chaining_key[CRYPTO_SHA512_SIZE],
//                       uint8_t shared_key[CRYPTO_SHARED_KEY_SIZE],
//                       const uint8_t private_key[CRYPTO_SECRET_KEY_SIZE],
//                       const uint8_t public_key[CRYPTO_PUBLIC_KEY_SIZE])
// {
//     uint8_t dh_calculation[CRYPTO_SHARED_KEY_SIZE];
//     memset(dh_calculation, 0, CRYPTO_SHARED_KEY_SIZE);

//     /* X25519: returns plain DH result, afterwards hashed with HKDF (necessary for NoiseIK) */ 
//     if (crypto_scalarmult_curve25519(dh_calculation, private_key, public_key) != 0) {
//         return -1;
//     }

//     /* chaining_key is HKDF output1 and shared_key is HKDF output2 => different values/results! */
//     /* If HASHLEN is 64, then truncates temp_k (= shared_key) to 32 bytes. => done via call to crypto_hkdf() */ 
//     crypto_hkdf(chaining_key, CRYPTO_SHA512_SIZE, shared_key, CRYPTO_SHARED_KEY_SIZE, dh_calculation,
//                 CRYPTO_SHARED_KEY_SIZE, chaining_key);

//     crypto_memzero(dh_calculation, CRYPTO_SHARED_KEY_SIZE);

//     return 0;
// }

/*
 * cf. Noise section 5.2
 * Executes the following steps:
 * - Sets ck, temp_k = HKDF(ck, input_key_material, 2).
 * - If HASHLEN is 64, then truncates temp_k to 32 bytes
 * - Calls InitializeKey(temp_k).
 * input_key_material = DH_X25519(private, public)
 * 
 * based on HKDF-BLAKE2b
 */
int32_t noise_mix_key(uint8_t chaining_key[CRYPTO_BLAKE2b_HASH_SIZE],
                      uint8_t shared_key[CRYPTO_SHARED_KEY_SIZE],
                      const uint8_t private_key[CRYPTO_SECRET_KEY_SIZE],
                      const uint8_t public_key[CRYPTO_PUBLIC_KEY_SIZE])
{
    uint8_t dh_calculation[CRYPTO_SHARED_KEY_SIZE];
    memset(dh_calculation, 0, CRYPTO_SHARED_KEY_SIZE);

    /* X25519: returns plain DH result, afterwards hashed with HKDF (necessary for NoiseIK) */ 
    if (crypto_scalarmult_curve25519(dh_calculation, private_key, public_key) != 0) {
        return -1;
    }

    /* chaining_key is HKDF output1 and shared_key is HKDF output2 => different values/results! */
    /* If HASHLEN is 64, then truncates temp_k (= shared_key) to 32 bytes. => done via call to crypto_hkdf() */ 
    crypto_hkdf(chaining_key, CRYPTO_BLAKE2b_HASH_SIZE, shared_key, CRYPTO_SHARED_KEY_SIZE, dh_calculation,
                CRYPTO_SHARED_KEY_SIZE, chaining_key);

    crypto_memzero(dh_calculation, CRYPTO_SHARED_KEY_SIZE);

    return 0;
}

/*
 * Noise MixHash(data): Sets h = HASH(h || data).
 * SHA512
 *
 * cf. Noise section 5.2
 */
// void noise_mix_hash(uint8_t hash[CRYPTO_SHA512_SIZE], const uint8_t *data, size_t data_len)
// {
//     //TODO: not necessary with Blake2b
//     VLA(uint8_t, to_hash, CRYPTO_SHA512_SIZE + data_len);
//     memcpy(to_hash, hash, CRYPTO_SHA512_SIZE);
//     if (data != nullptr) {
//         memcpy(to_hash + CRYPTO_SHA512_SIZE, data, data_len);
//     }
//     // crypto_sha512(hash, to_hash, CRYPTO_SHA512_SIZE + data_len);

//     crypto_generichash_blake2b_state state;
//     crypto_generichash_blake2b_init(&state, NULL, 0, CRYPTO_BLAKE2b_HASH_SIZE);
//     crypto_generichash_blake2b_update(&state, hash, CRYPTO_BLAKE2b_HASH_SIZE);
// 	crypto_generichash_blake2b_update(&state, data, data_len);
// 	crypto_generichash_blake2b_final(&state, hash, CRYPTO_BLAKE2b_HASH_SIZE);
// }

/*
 * Noise MixHash(data): Sets h = HASH(h || data).
 * Blake2b
 *
 * cf. Noise section 5.2
 */
void noise_mix_hash(uint8_t hash[CRYPTO_BLAKE2b_HASH_SIZE], const uint8_t *data, size_t data_len)
{
    crypto_generichash_blake2b_state state;
    crypto_generichash_blake2b_init(&state, NULL, 0, CRYPTO_BLAKE2b_HASH_SIZE);
    crypto_generichash_blake2b_update(&state, hash, CRYPTO_BLAKE2b_HASH_SIZE);
	crypto_generichash_blake2b_update(&state, data, data_len);
	crypto_generichash_blake2b_final(&state, hash, CRYPTO_BLAKE2b_HASH_SIZE);
}

/*
 * cf. Noise section 5.2
 * "Noise spec: Note that if k is empty, the EncryptWithAd() call will set ciphertext equal to plaintext."
 * This is not the case in Tox.
 */
void noise_encrypt_and_hash(uint8_t *ciphertext, const uint8_t *plaintext,
                            size_t plain_length, uint8_t shared_key[CRYPTO_SHARED_KEY_SIZE],
                            uint8_t hash[CRYPTO_SHA512_SIZE])
{
    static uint8_t nonce_chacha20_ietf[CRYPTO_NOISEIK_NONCE_SIZE] = {0};
    memset(nonce_chacha20_ietf, 0, CRYPTO_NOISEIK_NONCE_SIZE);

    int32_t encrypted_length = encrypt_data_symmetric_aead(shared_key, nonce_chacha20_ietf,
                                          plaintext, plain_length, ciphertext,
                                          hash, CRYPTO_SHA512_SIZE);

    noise_mix_hash(hash, ciphertext, encrypted_length);
}

/*
 * cf. Noise section 5.2
 * "Note that if k is empty, the DecryptWithAd() call will set plaintext equal to ciphertext."
 * This is not the case in Tox.
 */
int noise_decrypt_and_hash(uint8_t *plaintext, const uint8_t *ciphertext,
                           size_t encrypted_length, uint8_t shared_key[CRYPTO_SHARED_KEY_SIZE],
                           uint8_t hash[CRYPTO_SHA512_SIZE])
{
    static uint8_t nonce_chacha20_ietf[CRYPTO_NOISEIK_NONCE_SIZE] = {0};
    memset(nonce_chacha20_ietf, 0, CRYPTO_NOISEIK_NONCE_SIZE);

    int32_t plaintext_length = decrypt_data_symmetric_aead(shared_key, nonce_chacha20_ietf,
                                          ciphertext, encrypted_length, plaintext,
                                          hash, CRYPTO_SHA512_SIZE);

    noise_mix_hash(hash, ciphertext, encrypted_length);

    return plaintext_length;
}

/**
 * @brief Initializes a Noise Handshake State with provided static X25519 ID key pair, X25519 static ID public key from peer
 * and sets if initiator or not.
 *
 * cf. Noise section 5.3
 * Calls InitializeSymmetric(protocol_name).
 * Calls MixHash(prologue).
 * Sets the initiator, s, e, rs, and re variables to the corresponding arguments.
 * Calls MixHash() once for each public key listed in the pre-messages.
 *
 * //TODO: remove Logger Param
 * @param noise_handshake handshake struct to save the necessary values to
 * @param self_secret_key static private ID X25519 key of this Tox instance
 * @param peer_public_key X25519 static ID public key from peer to connect to
 * @param initiator specifies if this Tox instance is the initiator of this crypto connection
 * @param prologue specifies the prologue, used in call to MixHash(prologue) which maybe zero-length
 * @param prologue_length length of prologue in bytes
 *
 * @return -1 on failure
 * @return 0 on success
 */
int noise_handshake_init
(Noise_Handshake *noise_handshake, const uint8_t *self_secret_key, const uint8_t *peer_public_key, bool initiator, const uint8_t *prologue, size_t prologue_length)
{
    //TODO: remove
    // if (log != nullptr) {
    //     LOGGER_DEBUG(log, "ENTERING");
    // }

    //TODO: move to handle_packet_crypto_hs()?
    crypto_memzero(noise_handshake, sizeof(Noise_Handshake));

    /* IntializeSymmetric(protocol_name) => set h to NOISE_PROTOCOL_NAME and append zero bytes to make 64 bytes, sets ck = h
     Nothing gets hashed in Tox case because NOISE_PROTOCOL_NAME < CRYPTO_SHA512_SIZE */
    uint8_t temp_hash[CRYPTO_SHA512_SIZE];
    memset(temp_hash, 0, CRYPTO_SHA512_SIZE);
    memcpy(temp_hash, noise_protocol, sizeof(noise_protocol));
    memcpy(noise_handshake->hash, temp_hash, CRYPTO_SHA512_SIZE);
    memcpy(noise_handshake->chaining_key, temp_hash, CRYPTO_SHA512_SIZE);

    /* IMPORTANT needs to be called with (empty/zero-length) prologue! */ 
    noise_mix_hash(noise_handshake->hash, prologue, prologue_length);

    //TODO: remove
    // char log_ck[CRYPTO_SHA512_SIZE*2+1];
    // if (log != nullptr) {
    //     bytes2string(log_ck, sizeof(log_ck), noise_handshake->chaining_key, CRYPTO_SHA512_SIZE, log);
    //     LOGGER_DEBUG(log, "ck: %s", log_ck);
    // }

    /* Sets the initiator, s => ephemeral keys are set afterwards */
    noise_handshake->initiator = initiator;
    if (self_secret_key != nullptr) {
        memcpy(noise_handshake->static_private, self_secret_key, CRYPTO_SECRET_KEY_SIZE);
        crypto_derive_public_key(noise_handshake->static_public, self_secret_key);

        //TODO: remove
        // if (log != nullptr) {
        //     char log_spub[CRYPTO_PUBLIC_KEY_SIZE * 2 + 1];
        //     bytes2string(log_spub, sizeof(log_spub), noise_handshake->static_public, CRYPTO_PUBLIC_KEY_SIZE, log);
        //     LOGGER_DEBUG(log, "static pub: %s", log_spub);
        // }

    } else {
        // fprintf(stderr, "Local static private key required, but not provided.\n");
        // LOGGER_DEBUG(log, "Local static private key required, but not provided.");
        return -1;
    }
    /* <- s: pre-message from responder to initiator => sets rs (only initiator) */
    if (initiator) {
        if (peer_public_key != nullptr) {
            memcpy(noise_handshake->remote_static, peer_public_key, CRYPTO_PUBLIC_KEY_SIZE);

            //TODO: Remove
            // if (log != nullptr) {
            //     char log_spub[CRYPTO_PUBLIC_KEY_SIZE * 2 + 1];
            //     bytes2string(log_spub, sizeof(log_spub), noise_handshake->remote_static, CRYPTO_PUBLIC_KEY_SIZE, log);
            //     LOGGER_DEBUG(log, "INITIATOR remote static: %s", log_spub);
            // }

            /* Calls MixHash() once for each public key listed in the pre-messages from Noise IK */
            noise_mix_hash(noise_handshake->hash, peer_public_key, CRYPTO_PUBLIC_KEY_SIZE);

            //TODO: remove
            // if (log != nullptr) {
            //     bytes2string(log_hash, sizeof(log_hash), noise_handshake->hash, CRYPTO_SHA512_SIZE, log);
            //     LOGGER_DEBUG(log, "INITIATOR hash: %s", log_hash);
            // }
        } else {
            // fprintf(stderr, "Remote peer static public key required, but not provided.\n");
            // LOGGER_DEBUG(log, "Remote peer static public key required, but not provided.");
            return -1;
        }
    }
    /* Noise RESPONDER */
    else {
        /* Calls MixHash() once for each public key listed in the pre-messages from Noise IK */
        noise_mix_hash(noise_handshake->hash, noise_handshake->static_public, CRYPTO_PUBLIC_KEY_SIZE);

        //TODO(goldroom): precompute static static here (ss)? cf. WireGuard wg_noise_handshake_init()

        //TODO: remove
        // if (log != nullptr) {
        //     bytes2string(log_hash, sizeof(log_hash), noise_handshake->hash, CRYPTO_SHA512_SIZE, log);
        //     LOGGER_DEBUG(log, "RESPONDER hash: %s", log_hash);
        // }
    }

    /* Ready to go */
    return 0;
}

//TODO(goldroom): abstract creation and handling of NoiseIK handshake packets from net_crypto (_after_ cookie adaption)
// /* Noise create INITIATOR: -> e, es, s, ss */
// int noise_handshake_create_initiator()
// /* Noise handle INITIATOR: -> e, es, s, ss */
// int noise_handshake_handle_initiator()
// /* Noise create RESPONDER: <- e, ee, se */
// int noise_handshake_create_responder()
// /* Noise handle RESPONDER: <- e, ee, se */
// int noise_handshake_handle_responder()
