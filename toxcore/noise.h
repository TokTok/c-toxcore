/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2026 The TokTok team.
 */

/** @file
 * @brief Noise IK protocol primitives.
 *
 * Implements the symmetric-state and handshake-state operations from the
 * Noise protocol framework (https://noiseprotocol.org/noise.html, rev. 34),
 * instantiated as Noise_IK_25519_ChaChaPoly_BLAKE2b.
 */
#ifndef C_TOXCORE_TOXCORE_NOISE_H
#define C_TOXCORE_TOXCORE_NOISE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "attributes.h"
#include "crypto_core.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief The number of bytes in a BLAKE2b-512 hash (as defined for Noise in section 12.8).
 */
#define CRYPTO_NOISE_BLAKE2B_HASH_SIZE  64

/** @brief NoiseIK handshake state. */
typedef struct Noise_Handshake {
    uint8_t ephemeral_private[CRYPTO_SECRET_KEY_SIZE];
    uint8_t ephemeral_public[CRYPTO_PUBLIC_KEY_SIZE];
    uint8_t remote_static[CRYPTO_PUBLIC_KEY_SIZE];
    uint8_t remote_ephemeral[CRYPTO_PUBLIC_KEY_SIZE];
    // TODO(goldroom): precompute DH(s, rs) to avoid recomputing during handshake? cf. WireGuard

    uint8_t hash[CRYPTO_NOISE_BLAKE2B_HASH_SIZE];
    uint8_t chaining_key[CRYPTO_NOISE_BLAKE2B_HASH_SIZE];

    bool initiator;
} Noise_Handshake;

/**
 * @brief Computes two HKDF-BLAKE2b-512 outputs (chaining key and derived key).
 *
 * cf. Noise sections 4.3 and 5.1. This is Hugo Krawczyk's HKDF
 * (https://eprint.iacr.org/2010/264.pdf, https://tools.ietf.org/html/rfc5869)
 * with BLAKE2b as the hash function (HASHLEN=64, BLOCKLEN=128).
 *
 * Sets temp_key = HMAC-HASH(chaining_key, data), then:
 * – output1 = HMAC-HASH(temp_key, byte(0x01))  (truncated to first_len)
 * – output2 = HMAC-HASH(temp_key, output1 || byte(0x02))  (truncated to second_len)
 *
 * Verified using Noise_IK_25519_ChaChaPoly_BLAKE2b test vectors.
 *
 * @param output1 First key to compute; must be non-null and first_len <= CRYPTO_NOISE_BLAKE2B_HASH_SIZE.
 * @param first_len Length of output1 in bytes (must be > 0 and <= @ref CRYPTO_NOISE_BLAKE2B_HASH_SIZE).
 * @param output2 Second key to compute; must be non-null and second_len <= CRYPTO_NOISE_BLAKE2B_HASH_SIZE.
 * @param second_len Length of output2 in bytes (must be > 0 and <= @ref CRYPTO_NOISE_BLAKE2B_HASH_SIZE).
 * @param data HKDF input_key_material (may be null if data_len == 0).
 * @param data_len Length of data (zero, 32, or DHLEN bytes per Noise spec).
 * @param chaining_key 64-byte Noise chaining key used as HKDF salt.
 * @return false on invalid arguments, true on success.
 */
bool noise_hkdf(uint8_t *_Nonnull output1, size_t first_len, uint8_t *_Nonnull output2,
                size_t second_len, const uint8_t *_Nullable data,
                size_t data_len, const uint8_t chaining_key[_Nonnull CRYPTO_NOISE_BLAKE2B_HASH_SIZE]);

/**
 * @brief Noise MixKey(input_key_material)
 *
 * cf. Noise section 5.2
 * Executes the following steps:
 * - Sets ck, temp_k = HKDF(ck, input_key_material, 2).
 * - If HASHLEN is 64, then truncates temp_k to 32 bytes
 * - Calls InitializeKey(temp_k).
 * input_key_material = DH_X25519(private, public)
 *
 * @param chaining_key 64 byte Noise ck
 * @param shared_key 32 byte secret key to be calculated
 * @param private_key X25519 private key
 * @param public_key X25519 public key
 */
int32_t noise_mix_key(uint8_t chaining_key[_Nonnull CRYPTO_NOISE_BLAKE2B_HASH_SIZE], uint8_t shared_key[_Nonnull CRYPTO_SHARED_KEY_SIZE],
                      const uint8_t private_key[_Nonnull CRYPTO_SECRET_KEY_SIZE],
                      const uint8_t public_key[_Nonnull CRYPTO_PUBLIC_KEY_SIZE]);

/**
 * @brief Noise MixHash(data): Sets h = HASH(h || data).
 *
 * cf. Noise section 5.2
 *
 * @param hash Contains current hash, is updated with new hash
 * @param data to add to hash
 * @param data_len length of data to hash
 */
void noise_mix_hash(uint8_t hash[_Nonnull CRYPTO_NOISE_BLAKE2B_HASH_SIZE], const uint8_t *_Nullable data, size_t data_len);

/**
 * @brief Noise EncryptAndHash(plaintext): Sets ciphertext = EncryptWithAd(h,
 * plaintext), then calls MixHash(ciphertext).
 *
 * cf. Noise section 5.2. Unlike the spec, k is never empty in Tox.
 *
 * @param ciphertext stores encrypted plaintext
 * @param plaintext to be encrypted
 * @param plain_length length of plaintext
 * @param shared_key used for AEAD encryption
 * @param hash stores hash value, used as associated data in AEAD
 *
 * @retval -1 on encryption failure.
 * @retval 0 on success.
 */
int noise_encrypt_and_hash(uint8_t *_Nonnull ciphertext, const uint8_t *_Nonnull plaintext,
                           size_t plain_length, uint8_t shared_key[_Nonnull CRYPTO_SHARED_KEY_SIZE],
                           uint8_t hash[_Nonnull CRYPTO_NOISE_BLAKE2B_HASH_SIZE]);

/**
 * @brief DecryptAndHash(ciphertext): Sets plaintext = DecryptWithAd(h,
 * ciphertext), then calls MixHash(ciphertext).
 *
 * cf. Noise section 5.2. Unlike the spec, k is never empty in Tox.
 *
 * @param ciphertext contains ciphertext to decrypt
 * @param plaintext stores decrypted ciphertext
 * @param encrypted_length length of ciphertext+MAC
 * @param shared_key used for AEAD decryption
 * @param hash stores hash value, used as associated data in AEAD
 */
int noise_decrypt_and_hash(uint8_t *_Nonnull plaintext, const uint8_t *_Nonnull ciphertext,
                           size_t encrypted_length, uint8_t shared_key[_Nonnull CRYPTO_SHARED_KEY_SIZE],
                           uint8_t hash[_Nonnull CRYPTO_NOISE_BLAKE2B_HASH_SIZE]);

/**
 * @brief Initializes a Noise Handshake State.
 *
 * The long-term identity keys are NOT stored in the handshake struct; they are
 * only used here for the pre-message MixHash and must be passed separately to
 * create_crypto_handshake / handle_crypto_handshake.
 *
 * cf. Noise section 5.3
 * Calls InitializeSymmetric(protocol_name).
 * Calls MixHash(prologue).
 * Sets the initiator, e, rs, and re variables to the corresponding arguments.
 * Calls MixHash() once for each public key listed in the pre-messages.
 *
 * @param noise_handshake Noise handshake struct to save the necessary values to
 * @param self_id_public_key static public ID X25519 key of this Tox instance
 * @param peer_id_public_key static public ID X25519 key from the peer to connect to (initiator only)
 * @param initiator specifies if this Tox instance is the initiator of this crypto connection
 * @param prologue specifies the Noise prologue, used in call to MixHash(prologue) which maybe zero-length
 * @param prologue_length length of Noise prologue in bytes
 *
 * @return -1 on failure
 * @return 0 on success
 */
int noise_handshake_init(Noise_Handshake *_Nonnull noise_handshake,
                         const uint8_t self_id_public_key[_Nonnull CRYPTO_PUBLIC_KEY_SIZE],
                         const uint8_t peer_id_public_key[_Nullable CRYPTO_PUBLIC_KEY_SIZE], bool initiator,
                         const uint8_t *_Nullable prologue, size_t prologue_length);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* C_TOXCORE_TOXCORE_NOISE_H */
