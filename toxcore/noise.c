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
 * cf. Noise sections 4.3, 5.1 and 12.8: HMAC-BLAKE2b-512
 * HASH(input): BLAKE2b with digest length 64
 * HASHLEN = 64
 * BLOCKLEN = 128
 * Applies HMAC from RFC2104 (https://www.ietf.org/rfc/rfc2104.txt) using the HASH() (=BLAKE2b) function.
 * This function is only called via `noise_hkdf()`.
 * Necessary for Noise (cf. sections 4.3 and 12.8) to return 64 bytes (BLAKE2b HASHLEN).
 * Cf. https://doc.libsodium.org/hashing/generic_hashing
 * key is CRYPTO_NOISE_BLAKE2B_HASH_SIZE bytes because this function is only called via noise_hkdf() where the key (ck, temp_key)
 * is always HASHLEN bytes.
 */
static void crypto_hmac_blake2b_512(uint8_t *out_hmac, const uint8_t *in, size_t in_length, const uint8_t *key,
                                    size_t key_length)
{
    crypto_generichash_blake2b_state state;

    /*
     * (1) append zeros to the end of K to create a B byte string (e.g., if K is of length 20 bytes and B=64,
     * then K will be appended with 44 zero bytes 0x00)
     * B = Blake2b block length = 128
     * L the byte-length of Blake2b hash output = 64
     */
    uint8_t x_key[NOISE_BLAKE2B_BLOCK_SIZE] = { 0 };
    uint8_t i_hash[CRYPTO_NOISE_BLAKE2B_HASH_SIZE];

    /*
     * The authentication key K can be of any length up to B, the
     * block length of the hash function.  Applications that use keys longer
     * than B bytes will first hash the key using H and then use the
     * resultant L byte string as the actual key to HMAC.
     * In any case the minimal recommended length for K is L bytes (as the hash output
     * length).
     */
    if (key_length > NOISE_BLAKE2B_BLOCK_SIZE) {
        crypto_generichash_blake2b_init(&state, nullptr, 0, CRYPTO_NOISE_BLAKE2B_HASH_SIZE);
        crypto_generichash_blake2b_update(&state, key, key_length);
        crypto_generichash_blake2b_final(&state, x_key, CRYPTO_NOISE_BLAKE2B_HASH_SIZE);
    } else {
        memcpy(x_key, key, key_length);
    }

    /*
     * K XOR ipad, ipad = the byte 0x36 repeated B times
     * (2) XOR (bitwise exclusive-OR) the B byte string computed in step
     * (1) with ipad
     */
    for (int i = 0; i < NOISE_BLAKE2B_BLOCK_SIZE; ++i) {
        x_key[i] ^= 0x36;
    }

    /*
     * H(K XOR ipad, text)
     * (3) append the stream of data `text` to the B byte string resulting
     *   from step (2)
     *   (4) apply H to the stream generated in step (3)
     */
    crypto_generichash_blake2b_init(&state, nullptr, 0, CRYPTO_NOISE_BLAKE2B_HASH_SIZE);
    crypto_generichash_blake2b_update(&state, x_key, NOISE_BLAKE2B_BLOCK_SIZE);
    crypto_generichash_blake2b_update(&state, in, in_length);
    crypto_generichash_blake2b_final(&state, i_hash, CRYPTO_NOISE_BLAKE2B_HASH_SIZE);

    /*
     * K XOR opad, opad = the byte 0x5C repeated B times
     * (5) XOR (bitwise exclusive-OR) the B byte string computed in
     *   step (1) with opad
     */
    for (int i = 0; i < NOISE_BLAKE2B_BLOCK_SIZE; ++i) {
        x_key[i] ^= 0x5c ^ 0x36;
    }

    /*
     * H(K XOR opad, H(K XOR ipad, text))
     * (6) append the H result from step (4) to the B byte string
     *   resulting from step (5)
     *   (7) apply H to the stream generated in step (6) and output
     *   the result
     */
    crypto_generichash_blake2b_init(&state, nullptr, 0, CRYPTO_NOISE_BLAKE2B_HASH_SIZE);
    crypto_generichash_blake2b_update(&state, x_key, NOISE_BLAKE2B_BLOCK_SIZE);
    crypto_generichash_blake2b_update(&state, i_hash, CRYPTO_NOISE_BLAKE2B_HASH_SIZE);
    crypto_generichash_blake2b_final(&state, i_hash, CRYPTO_NOISE_BLAKE2B_HASH_SIZE);

    memcpy(out_hmac, i_hash, CRYPTO_NOISE_BLAKE2B_HASH_SIZE);

    /* Clear sensitive data from stack */
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

    /* HKDF-Expand T(2): output2 = HMAC-HASH(temp_key, T(1) || 0x02); OKM = T(1) || T(2) cf. RFC5869 section 2.3 */
    output[CRYPTO_NOISE_BLAKE2B_HASH_SIZE] = 2;
    crypto_hmac_blake2b_512(output, output, CRYPTO_NOISE_BLAKE2B_HASH_SIZE + 1, temp_key, CRYPTO_NOISE_BLAKE2B_HASH_SIZE);
    memcpy(output2, output, second_len);

    /* output3 (for pre-shared symmetric keys) is not needed and therefore not computed. */

    /* Clear sensitive data from stack */
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

    /* X25519: returns plain DH result, afterwards hashed with HKDF (necessary for NoiseIK).
     * Also reject all-zero DH output (low-order input point), cf. Noise spec section 12.1. */
    if (crypto_scalarmult_curve25519(dh_calculation, private_key, public_key) != 0) {
        crypto_memzero(dh_calculation, CRYPTO_SHARED_KEY_SIZE);
        return -1;
    }

    if (sodium_is_zero(dh_calculation, CRYPTO_SHARED_KEY_SIZE) != 0) {
        crypto_memzero(dh_calculation, CRYPTO_SHARED_KEY_SIZE);
        return -1;
    }

    /* chaining_key is HKDF output1 and shared_key is HKDF output2 => different values/results! */
    /* If HASHLEN is 64, then truncates temp_k (= shared_key) to 32 bytes. => done via call to noise_hkdf() */
    noise_hkdf(chaining_key, CRYPTO_NOISE_BLAKE2B_HASH_SIZE, shared_key, CRYPTO_SHARED_KEY_SIZE, dh_calculation,
               CRYPTO_SHARED_KEY_SIZE, chaining_key);

    crypto_memzero(dh_calculation, CRYPTO_SHARED_KEY_SIZE);

    return 0;
}

/*
 * Noise MixHash(data): Sets h = HASH(h || data).
 * Blake2b
 *
 * cf. Noise section 5.2
 */
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
    /* Zero the entire struct to prevent use of uninitialized key material
     * (ephemeral keys and remote_ephemeral are set later by callers). */
    crypto_memzero(noise_handshake, sizeof(Noise_Handshake));

    if (self_id_public_key == nullptr) {
        return -1;
    }

    /* The protocol name is exactly 33 ASCII bytes. The NUL terminator occupies byte 34,
     * which becomes a zero-pad byte when copied into the 64-byte hash/ck initial state.
     * This matches the noise-c test vectors. */
    const uint8_t noise_protocol[34] = "Noise_IK_25519_ChaChaPoly_BLAKE2b";

    /* IntializeSymmetric(protocol_name) => set h to NOISE_PROTOCOL_NAME and append zero bytes to make 64 bytes, sets ck = h
     * Nothing gets hashed in Tox case because NOISE_PROTOCOL_NAME < HASHLEN */
    uint8_t temp_hash[CRYPTO_NOISE_BLAKE2B_HASH_SIZE];
    memset(temp_hash, 0, CRYPTO_NOISE_BLAKE2B_HASH_SIZE);
    memcpy(temp_hash, noise_protocol, sizeof(noise_protocol));
    memcpy(noise_handshake->hash, temp_hash, CRYPTO_NOISE_BLAKE2B_HASH_SIZE);
    memcpy(noise_handshake->chaining_key, temp_hash, CRYPTO_NOISE_BLAKE2B_HASH_SIZE);

    /* IMPORTANT needs to be called with (empty/zero-length) prologue! */
    noise_mix_hash(noise_handshake->hash, prologue, prologue_length);

    noise_handshake->initiator = initiator;

    /* <- s: pre-message from responder to initiator => sets rs (only initiator) */
    if (initiator) {
        if (peer_id_public_key != nullptr) {
            memcpy(noise_handshake->remote_static, peer_id_public_key, CRYPTO_PUBLIC_KEY_SIZE);

            /* Calls MixHash() once for each public key listed in the pre-messages from Noise IK */
            noise_mix_hash(noise_handshake->hash, peer_id_public_key, CRYPTO_PUBLIC_KEY_SIZE);
        } else {
            return -1;
        }
    } else {
        /* Noise RESPONDER */
        /* Calls MixHash() once for each public key listed in the pre-messages from Noise IK */
        noise_mix_hash(noise_handshake->hash, self_id_public_key, CRYPTO_PUBLIC_KEY_SIZE);
        // TODO(goldroom): precompute DH(s, rs) here? cf. WireGuard wg_noise_handshake_init()
    }

    /* Ready to go */
    return 0;
}
