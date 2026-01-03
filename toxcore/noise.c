/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2026 The TokTok team.
 */

#include "noise.h"

#include <string.h>

#include <sodium.h>

#include "attributes.h"
#include "ccompat.h"
#include "crypto_core.h"

/** BLAKE2b block size in bytes (128), used only by crypto_hmac_blake2b_512. */
#define NOISE_BLAKE2B_BLOCK_SIZE 128

static_assert(CRYPTO_NOISE_BLAKE2B_HASH_SIZE == crypto_generichash_blake2b_BYTES_MAX,
              "CRYPTO_NOISE_BLAKE2B_HASH_SIZE should be equal to crypto_generichash_blake2b_BYTES_MAX");

/**
 * HMAC (RFC 2104) with BLAKE2b-512, as Noise needs (sections 4.3 and 12.8).
 * libsodium has no HMAC for BLAKE2b, so we build it from the hash.
 */
static void crypto_hmac_blake2b_512(uint8_t *out_hmac, const uint8_t *in, size_t in_length, const uint8_t *key,
                                    size_t key_length)
{
    crypto_generichash_blake2b_state state;

    /* K padded with zeros to the block size, or its hash if it's longer. */
    uint8_t x_key[NOISE_BLAKE2B_BLOCK_SIZE] = { 0 };
    uint8_t i_hash[CRYPTO_NOISE_BLAKE2B_HASH_SIZE];

    if (key_length > NOISE_BLAKE2B_BLOCK_SIZE) {
        crypto_generichash_blake2b_init(&state, nullptr, 0, CRYPTO_NOISE_BLAKE2B_HASH_SIZE);
        crypto_generichash_blake2b_update(&state, key, key_length);
        crypto_generichash_blake2b_final(&state, x_key, CRYPTO_NOISE_BLAKE2B_HASH_SIZE);
    } else {
        memcpy(x_key, key, key_length);
    }

    /* `H((K ^ ipad) || text)` */
    for (int i = 0; i < NOISE_BLAKE2B_BLOCK_SIZE; ++i) {
        x_key[i] ^= 0x36;
    }

    crypto_generichash_blake2b_init(&state, nullptr, 0, CRYPTO_NOISE_BLAKE2B_HASH_SIZE);
    crypto_generichash_blake2b_update(&state, x_key, NOISE_BLAKE2B_BLOCK_SIZE);
    crypto_generichash_blake2b_update(&state, in, in_length);
    crypto_generichash_blake2b_final(&state, i_hash, CRYPTO_NOISE_BLAKE2B_HASH_SIZE);

    /* `H((K ^ opad) || inner_hash)`. x_key holds `K ^ ipad`, so undo that too. */
    for (int i = 0; i < NOISE_BLAKE2B_BLOCK_SIZE; ++i) {
        x_key[i] ^= 0x5c ^ 0x36;
    }

    crypto_generichash_blake2b_init(&state, nullptr, 0, CRYPTO_NOISE_BLAKE2B_HASH_SIZE);
    crypto_generichash_blake2b_update(&state, x_key, NOISE_BLAKE2B_BLOCK_SIZE);
    crypto_generichash_blake2b_update(&state, i_hash, CRYPTO_NOISE_BLAKE2B_HASH_SIZE);
    crypto_generichash_blake2b_final(&state, i_hash, CRYPTO_NOISE_BLAKE2B_HASH_SIZE);

    memcpy(out_hmac, i_hash, CRYPTO_NOISE_BLAKE2B_HASH_SIZE);

    crypto_memzero(x_key, NOISE_BLAKE2B_BLOCK_SIZE);
    crypto_memzero(i_hash, CRYPTO_NOISE_BLAKE2B_HASH_SIZE);
}

bool noise_hkdf(uint8_t *output1, size_t first_len, uint8_t *output2,
                size_t second_len, const uint8_t *data,
                size_t data_len, const uint8_t chaining_key[CRYPTO_NOISE_BLAKE2B_HASH_SIZE])
{
    if (output1 == nullptr || first_len == 0 || first_len > CRYPTO_NOISE_BLAKE2B_HASH_SIZE
            || output2 == nullptr || second_len == 0 || second_len > CRYPTO_NOISE_BLAKE2B_HASH_SIZE
            || (data_len > 0 && data == nullptr) || chaining_key == nullptr) {
        return false;
    }
    uint8_t output[CRYPTO_NOISE_BLAKE2B_HASH_SIZE + 1];
    uint8_t temp_key[CRYPTO_NOISE_BLAKE2B_HASH_SIZE];

    /* HKDF-Extract: temp_key = HMAC-HASH(chaining_key, data) cf. RFC5869 section 2.2 */
    crypto_hmac_blake2b_512(temp_key, data, data_len, chaining_key, CRYPTO_NOISE_BLAKE2B_HASH_SIZE);

    /* HKDF-Expand T(1): output1 = HMAC-HASH(temp_key, 0x01) cf. RFC5869 section 2.3 */
    output[0] = 1;
    crypto_hmac_blake2b_512(output, output, 1, temp_key, CRYPTO_NOISE_BLAKE2B_HASH_SIZE);
    memcpy(output1, output, first_len);

    /* HKDF-Expand T(2): output2 = HMAC-HASH(temp_key, T(1) || 0x02), cf. RFC5869 section 2.3 */
    output[CRYPTO_NOISE_BLAKE2B_HASH_SIZE] = 2;
    crypto_hmac_blake2b_512(output, output, CRYPTO_NOISE_BLAKE2B_HASH_SIZE + 1, temp_key, CRYPTO_NOISE_BLAKE2B_HASH_SIZE);
    memcpy(output2, output, second_len);

    /* No output3, as we don't use pre-shared keys. */

    crypto_memzero(temp_key, CRYPTO_NOISE_BLAKE2B_HASH_SIZE);
    crypto_memzero(output, CRYPTO_NOISE_BLAKE2B_HASH_SIZE + 1);
    return true;
}

/*
 * cf. Noise section 5.2: based on HKDF-BLAKE2b
 * Executes the following steps:
 * - Sets ck, temp_k = HKDF(ck, input_key_material, 2).
 * - If HASHLEN is 64, then truncates temp_k to 32 bytes
 * - Calls InitializeKey(temp_k).
 * input_key_material = DH_X25519(private, public)
 *
 */
int32_t noise_mix_key(uint8_t chaining_key[CRYPTO_NOISE_BLAKE2B_HASH_SIZE],
                      uint8_t shared_key[CRYPTO_SHARED_KEY_SIZE],
                      const uint8_t private_key[CRYPTO_SECRET_KEY_SIZE],
                      const uint8_t public_key[CRYPTO_PUBLIC_KEY_SIZE])
{
    uint8_t dh_calculation[CRYPTO_SHARED_KEY_SIZE];
    memset(dh_calculation, 0, CRYPTO_SHARED_KEY_SIZE);

    /* Reject an all-zero result (a low-order point), cf. Noise section 12.1. */
    if (crypto_scalarmult_curve25519(dh_calculation, private_key, public_key) != 0) {
        crypto_memzero(dh_calculation, CRYPTO_SHARED_KEY_SIZE);
        return -1;
    }

    if (sodium_is_zero(dh_calculation, CRYPTO_SHARED_KEY_SIZE) != 0) {
        crypto_memzero(dh_calculation, CRYPTO_SHARED_KEY_SIZE);
        return -1;
    }

    /* noise_hkdf truncates shared_key to 32 bytes. */
    noise_hkdf(chaining_key, CRYPTO_NOISE_BLAKE2B_HASH_SIZE, shared_key, CRYPTO_SHARED_KEY_SIZE, dh_calculation,
               CRYPTO_SHARED_KEY_SIZE, chaining_key);

    crypto_memzero(dh_calculation, CRYPTO_SHARED_KEY_SIZE);

    return 0;
}

void noise_mix_hash(uint8_t hash[CRYPTO_NOISE_BLAKE2B_HASH_SIZE], const uint8_t *data, size_t data_len)
{
    crypto_generichash_blake2b_state state;
    crypto_generichash_blake2b_init(&state, nullptr, 0, CRYPTO_NOISE_BLAKE2B_HASH_SIZE);
    crypto_generichash_blake2b_update(&state, hash, CRYPTO_NOISE_BLAKE2B_HASH_SIZE);
    crypto_generichash_blake2b_update(&state, data, data_len);
    crypto_generichash_blake2b_final(&state, hash, CRYPTO_NOISE_BLAKE2B_HASH_SIZE);
}

/*
 * cf. Noise section 5.2. Unlike the spec, k is never empty in Tox.
 */
int noise_encrypt_and_hash(uint8_t *ciphertext, const uint8_t *plaintext,
                           size_t plain_length, uint8_t shared_key[CRYPTO_SHARED_KEY_SIZE],
                           uint8_t hash[CRYPTO_NOISE_BLAKE2B_HASH_SIZE])
{
    uint8_t nonce_chacha20_ietf[CRYPTO_NOISE_NONCE_SIZE] = {0};

    const int32_t encrypted_length = encrypt_data_symmetric_aead(shared_key, nonce_chacha20_ietf,
                                     plaintext, plain_length, ciphertext,
                                     hash, CRYPTO_NOISE_BLAKE2B_HASH_SIZE);

    if (encrypted_length == -1) {
        return -1;
    }

    noise_mix_hash(hash, ciphertext, encrypted_length);
    return 0;
}

/*
 * cf. Noise section 5.2. Unlike the spec, k is never empty in Tox.
 */
int noise_decrypt_and_hash(uint8_t *plaintext, const uint8_t *ciphertext,
                           size_t encrypted_length, uint8_t shared_key[CRYPTO_SHARED_KEY_SIZE],
                           uint8_t hash[CRYPTO_NOISE_BLAKE2B_HASH_SIZE])
{
    uint8_t nonce_chacha20_ietf[CRYPTO_NOISE_NONCE_SIZE] = {0};

    const int32_t plaintext_length = decrypt_data_symmetric_aead(shared_key, nonce_chacha20_ietf,
                                     ciphertext, encrypted_length, plaintext,
                                     hash, CRYPTO_NOISE_BLAKE2B_HASH_SIZE);

    if (plaintext_length == -1) {
        return -1;
    }

    noise_mix_hash(hash, ciphertext, encrypted_length);

    return plaintext_length;
}

int noise_handshake_init(Noise_Handshake *noise_handshake, const uint8_t self_id_public_key[CRYPTO_PUBLIC_KEY_SIZE],
                         const uint8_t peer_id_public_key[CRYPTO_PUBLIC_KEY_SIZE], bool initiator,
                         const uint8_t *prologue, size_t prologue_length)
{
    crypto_memzero(noise_handshake, sizeof(Noise_Handshake));

    if (self_id_public_key == nullptr) {
        return -1;
    }

    /* 33 bytes and the NUL, which is just more zero padding in the 64-byte h. */
    const uint8_t noise_protocol[34] = "Noise_IK_25519_ChaChaPoly_BLAKE2b";

    /* InitializeSymmetric(protocol_name): the name is shorter than HASHLEN, so h
     * is the name padded with zeros, and ck = h. */
    uint8_t temp_hash[CRYPTO_NOISE_BLAKE2B_HASH_SIZE];
    memset(temp_hash, 0, CRYPTO_NOISE_BLAKE2B_HASH_SIZE);
    memcpy(temp_hash, noise_protocol, sizeof(noise_protocol));
    memcpy(noise_handshake->hash, temp_hash, CRYPTO_NOISE_BLAKE2B_HASH_SIZE);
    memcpy(noise_handshake->chaining_key, temp_hash, CRYPTO_NOISE_BLAKE2B_HASH_SIZE);

    noise_mix_hash(noise_handshake->hash, prologue, prologue_length);

    noise_handshake->initiator = initiator;

    /* Pre-message <- s: the responder's static key. */
    if (initiator) {
        if (peer_id_public_key != nullptr) {
            memcpy(noise_handshake->remote_static, peer_id_public_key, CRYPTO_PUBLIC_KEY_SIZE);

            noise_mix_hash(noise_handshake->hash, peer_id_public_key, CRYPTO_PUBLIC_KEY_SIZE);
        } else {
            return -1;
        }
    } else {
        noise_mix_hash(noise_handshake->hash, self_id_public_key, CRYPTO_PUBLIC_KEY_SIZE);
        // TODO(goldroom): precompute DH(s, rs) here? cf. WireGuard wg_noise_handshake_init()
    }

    return 0;
}
