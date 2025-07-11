/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2025 The TokTok team.
 * Copyright © 2013 Tox project.
 */

/** @file
 * @brief Functions for the core crypto.
 *
 * @note This code has to be perfect. We don't mess around with encryption.
 */
#ifndef C_TOXCORE_TOXCORE_CRYPTO_CORE_H
#define C_TOXCORE_TOXCORE_CRYPTO_CORE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "attributes.h"
#include "mem.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief The number of bytes in a signature.
 */
#define CRYPTO_SIGNATURE_SIZE          64

/**
 * @brief The number of bytes in a Tox public key used for signatures.
 */
#define CRYPTO_SIGN_PUBLIC_KEY_SIZE    32

/**
 * @brief The number of bytes in a Tox secret key used for signatures.
 */
#define CRYPTO_SIGN_SECRET_KEY_SIZE    64

/**
 * @brief The number of bytes in a Tox public key used for encryption.
 */
#define CRYPTO_PUBLIC_KEY_SIZE         32

/**
 * @brief The number of bytes in a Tox secret key used for encryption.
 */
#define CRYPTO_SECRET_KEY_SIZE         32

/**
 * @brief The number of bytes in a shared key computed from public and secret keys.
 */
#define CRYPTO_SHARED_KEY_SIZE         32

/**
 * @brief The number of bytes in a symmetric key.
 */
#define CRYPTO_SYMMETRIC_KEY_SIZE      CRYPTO_SHARED_KEY_SIZE

/**
 * @brief The number of bytes needed for the MAC (message authentication code) in an
 *   encrypted message.
 */
#define CRYPTO_MAC_SIZE                16

/**
 * @brief The number of bytes in a nonce used for encryption/decryption.
 */
#define CRYPTO_NONCE_SIZE              24

/**
 * @brief The number of bytes in a SHA256 hash.
 */
#define CRYPTO_SHA256_SIZE             32

/**
 * @brief The number of bytes in a SHA512 hash.
 */
#define CRYPTO_SHA512_SIZE             64

/** @brief Fill a byte array with random bytes.
 *
 * This is the key generator callback and as such must be a cryptographically
 * secure pseudo-random number generator (CSPRNG). The security of Tox heavily
 * depends on the security of this RNG.
 */
typedef void crypto_random_bytes_cb(void *obj, uint8_t *bytes, size_t length);

/** @brief Generate a random integer between 0 and @p upper_bound.
 *
 * Should produce a uniform random distribution, but Tox security does not
 * depend on this being correct. In principle, it could even be a non-CSPRNG.
 */
typedef uint32_t crypto_random_uniform_cb(void *obj, uint32_t upper_bound);

/** @brief Virtual function table for Random. */
typedef struct Random_Funcs {
    crypto_random_bytes_cb *random_bytes;
    crypto_random_uniform_cb *random_uniform;
} Random_Funcs;

/** @brief Random number generator object.
 *
 * Can be used by test code and fuzzers to make toxcore behave in specific
 * well-defined (non-random) ways. Production code ought to use libsodium's
 * CSPRNG and use `os_random` below.
 */
typedef struct Random {
    const Random_Funcs *funcs;
    void *obj;
} Random;

/** @brief System random number generator.
 *
 * Uses libsodium's CSPRNG (on Linux, `/dev/urandom`).
 */
const Random *os_random(void);

/**
 * @brief The number of bytes in an encryption public key used by DHT group chats.
 */
#define ENC_PUBLIC_KEY_SIZE            CRYPTO_PUBLIC_KEY_SIZE

/**
 * @brief The number of bytes in an encryption secret key used by DHT group chats.
 */
#define ENC_SECRET_KEY_SIZE            CRYPTO_SECRET_KEY_SIZE

/**
 * @brief The number of bytes in a signature public key.
 */
#define SIG_PUBLIC_KEY_SIZE            CRYPTO_SIGN_PUBLIC_KEY_SIZE

/**
 * @brief The number of bytes in a signature secret key.
 */
#define SIG_SECRET_KEY_SIZE            CRYPTO_SIGN_SECRET_KEY_SIZE

/**
 * @brief The number of bytes in a DHT group chat public key identifier.
 */
#define CHAT_ID_SIZE                   SIG_PUBLIC_KEY_SIZE

/**
 * @brief The number of bytes in an extended public key used by DHT group chats.
 */
#define EXT_PUBLIC_KEY_SIZE            (ENC_PUBLIC_KEY_SIZE + SIG_PUBLIC_KEY_SIZE)

/**
 * @brief The number of bytes in an extended secret key used by DHT group chats.
 */
#define EXT_SECRET_KEY_SIZE            (ENC_SECRET_KEY_SIZE + SIG_SECRET_KEY_SIZE)

/**
 * @brief The number of bytes in an HMAC authenticator.
 */
#define CRYPTO_HMAC_SIZE               32

/**
 * @brief The number of bytes in an HMAC secret key.
 */
#define CRYPTO_HMAC_KEY_SIZE           32

/**
 * @brief A `bzero`-like function which won't be optimised away by the compiler.
 *
 * Some compilers will inline `bzero` or `memset` if they can prove that there
 * will be no reads to the written data. Use this function if you want to be
 * sure the memory is indeed zeroed.
 */
void crypto_memzero(non_null() void *data, size_t length);

/**
 * @brief Compute a SHA256 hash (32 bytes).
 *
 * @param[out] hash The SHA256 hash of @p data will be written to this byte array.
 */
void crypto_sha256(non_null() uint8_t hash[CRYPTO_SHA256_SIZE], non_null() const uint8_t *data, size_t length);

/**
 * @brief Compute a SHA512 hash (64 bytes).
 *
 * @param[out] hash The SHA512 hash of @p data will be written to this byte array.
 */
void crypto_sha512(non_null() uint8_t hash[CRYPTO_SHA512_SIZE], non_null() const uint8_t *data, size_t length);

/**
 * @brief Compute an HMAC authenticator (32 bytes).
 *
 * @param[out] auth Resulting authenticator.
 * @param key Secret key, as generated by `new_hmac_key()`.
 */
void crypto_hmac(non_null() uint8_t auth[CRYPTO_HMAC_SIZE], non_null() const uint8_t key[CRYPTO_HMAC_KEY_SIZE], non_null() const uint8_t *data, size_t length);

/**
 * @brief Verify an HMAC authenticator.
 */
bool crypto_hmac_verify(non_null() const uint8_t auth[CRYPTO_HMAC_SIZE], non_null() const uint8_t key[CRYPTO_HMAC_KEY_SIZE], non_null() const uint8_t *data, size_t length);

/**
 * @brief Compare 2 public keys of length @ref CRYPTO_PUBLIC_KEY_SIZE, not vulnerable to
 *   timing attacks.
 *
 * @retval true if both mem locations of length are equal
 * @retval false if they are not
 */
bool pk_equal(non_null() const uint8_t pk1[CRYPTO_PUBLIC_KEY_SIZE], non_null() const uint8_t pk2[CRYPTO_PUBLIC_KEY_SIZE]);

/**
 * @brief Copy a public key from `src` to `dest`.
 */
void pk_copy(non_null() uint8_t dest[CRYPTO_PUBLIC_KEY_SIZE], non_null() const uint8_t src[CRYPTO_PUBLIC_KEY_SIZE]);

/**
 * @brief Compare 2 SHA512 checksums of length CRYPTO_SHA512_SIZE, not vulnerable to
 *   timing attacks.
 *
 * @return true if both mem locations of length are equal, false if they are not.
 */
bool crypto_sha512_eq(non_null() const uint8_t cksum1[CRYPTO_SHA512_SIZE], non_null() const uint8_t cksum2[CRYPTO_SHA512_SIZE]);

/**
 * @brief Compare 2 SHA256 checksums of length CRYPTO_SHA256_SIZE, not vulnerable to
 *   timing attacks.
 *
 * @return true if both mem locations of length are equal, false if they are not.
 */
bool crypto_sha256_eq(non_null() const uint8_t cksum1[CRYPTO_SHA256_SIZE], non_null() const uint8_t cksum2[CRYPTO_SHA256_SIZE]);

/**
 * @brief Return a random 8 bit integer.
 */
uint8_t random_u08(non_null() const Random *rng);

/**
 * @brief Return a random 16 bit integer.
 */
uint16_t random_u16(non_null() const Random *rng);

/**
 * @brief Return a random 32 bit integer.
 */
uint32_t random_u32(non_null() const Random *rng);

/**
 * @brief Return a random 64 bit integer.
 */
uint64_t random_u64(non_null() const Random *rng);

/**
 * @brief Return a random 32 bit integer between 0 and upper_bound (excluded).
 *
 * This function guarantees a uniform distribution of possible outputs.
 */
uint32_t random_range_u32(non_null() const Random *rng, uint32_t upper_bound);

/**
 * @brief Cryptographically signs a message using the supplied secret key and puts the resulting signature
 *   in the supplied buffer.
 *
 * @param[out] signature The buffer for the resulting signature, which must have room for at
 *   least CRYPTO_SIGNATURE_SIZE bytes.
 * @param message The message being signed.
 * @param message_length The length in bytes of the message being signed.
 * @param secret_key The secret key used to create the signature. The key should be
 *   produced by either `create_extended_keypair` or the libsodium function `crypto_sign_keypair`.
 *
 * @retval true on success.
 */
bool crypto_signature_create(non_null() uint8_t signature[CRYPTO_SIGNATURE_SIZE], non_null() const uint8_t *message, uint64_t message_length, non_null() const uint8_t secret_key[SIG_SECRET_KEY_SIZE]);

/** @brief Verifies that the given signature was produced by a given message and public key.
 *
 * @param signature The signature we wish to verify.
 * @param message The message we wish to verify.
 * @param message_length The length of the message.
 * @param public_key The public key counterpart of the secret key that was used to
 *   create the signature.
 *
 * @retval true on success.
 */
bool crypto_signature_verify(non_null() const uint8_t signature[CRYPTO_SIGNATURE_SIZE], non_null() const uint8_t *message, uint64_t message_length,
                             non_null() const uint8_t public_key[SIG_PUBLIC_KEY_SIZE]);

/**
 * @brief Fill the given nonce with random bytes.
 */
void random_nonce(non_null() const Random *rng, non_null() uint8_t nonce[CRYPTO_NONCE_SIZE]);

/**
 * @brief Fill an array of bytes with random values.
 */
void random_bytes(non_null() const Random *rng, non_null() uint8_t *bytes, size_t length);

/**
 * @brief Check if a Tox public key CRYPTO_PUBLIC_KEY_SIZE is valid or not.
 *
 * This should only be used for input validation.
 *
 * @return false if it isn't, true if it is.
 */
bool public_key_valid(non_null() const uint8_t public_key[CRYPTO_PUBLIC_KEY_SIZE]);

typedef struct Extended_Public_Key {
    uint8_t enc[CRYPTO_PUBLIC_KEY_SIZE];
    uint8_t sig[CRYPTO_SIGN_PUBLIC_KEY_SIZE];
} Extended_Public_Key;

typedef struct Extended_Secret_Key {
    uint8_t enc[CRYPTO_SECRET_KEY_SIZE];
    uint8_t sig[CRYPTO_SIGN_SECRET_KEY_SIZE];
} Extended_Secret_Key;

/**
 * @brief Creates an extended keypair: curve25519 and ed25519 for encryption and signing
 *   respectively. The Encryption keys are derived from the signature keys.
 *
 * NOTE: This does *not* use Random, so any code using this will not be fuzzable.
 * TODO: Make it use Random.
 *
 * @param[out] pk The buffer where the public key will be stored. Must have room for EXT_PUBLIC_KEY_SIZE bytes.
 * @param[out] sk The buffer where the secret key will be stored. Must have room for EXT_SECRET_KEY_SIZE bytes.
 * @param rng The random number generator to use for the key generator seed.
 *
 * @retval true on success.
 */
bool create_extended_keypair(non_null() Extended_Public_Key *pk, non_null() Extended_Secret_Key *sk, non_null() const Random *rng);

/** Functions for groupchat extended keys */
const uint8_t *get_enc_key(non_null() const Extended_Public_Key *key);
const uint8_t *get_sig_pk(non_null() const Extended_Public_Key *key);
void set_sig_pk(non_null() Extended_Public_Key *key, non_null() const uint8_t *sig_pk);
const uint8_t *get_sig_sk(non_null() const Extended_Secret_Key *key);
const uint8_t *get_chat_id(non_null() const Extended_Public_Key *key);

/**
 * @brief Generate a new random keypair.
 *
 * Every call to this function is likely to generate a different keypair.
 */
int32_t crypto_new_keypair(non_null() const Random *rng, uint8_t public_key[CRYPTO_PUBLIC_KEY_SIZE], uint8_t secret_key[CRYPTO_SECRET_KEY_SIZE]);

/**
 * @brief Derive the public key from a given secret key.
 */
void crypto_derive_public_key(non_null() uint8_t public_key[CRYPTO_PUBLIC_KEY_SIZE], non_null() const uint8_t secret_key[CRYPTO_SECRET_KEY_SIZE]);

/**
 * @brief Encrypt message to send from secret key to public key.
 *
 * Encrypt plain text of the given length to encrypted of
 * `length + CRYPTO_MAC_SIZE` using the public key (@ref CRYPTO_PUBLIC_KEY_SIZE
 * bytes) of the receiver and the secret key of the sender and a
 * @ref CRYPTO_NONCE_SIZE byte nonce.
 *
 * @retval -1 if there was a problem.
 * @return length of encrypted data if everything was fine.
 */
int32_t encrypt_data(non_null() const Memory *mem, non_null() const uint8_t public_key[CRYPTO_PUBLIC_KEY_SIZE], non_null() const uint8_t secret_key[CRYPTO_SECRET_KEY_SIZE],
                     non_null() const uint8_t nonce[CRYPTO_NONCE_SIZE], non_null() const uint8_t *plain, size_t length, non_null() uint8_t *encrypted);

/**
 * @brief Decrypt message from public key to secret key.
 *
 * Decrypt encrypted text of the given @p length to plain text of the given
 * `length - CRYPTO_MAC_SIZE` using the public key (@ref CRYPTO_PUBLIC_KEY_SIZE
 * bytes) of the sender, the secret key of the receiver and a
 * @ref CRYPTO_NONCE_SIZE byte nonce.
 *
 * @retval -1 if there was a problem (decryption failed).
 * @return length of plain text data if everything was fine.
 */
int32_t decrypt_data(non_null() const Memory *mem, non_null() const uint8_t public_key[CRYPTO_PUBLIC_KEY_SIZE], non_null() const uint8_t secret_key[CRYPTO_SECRET_KEY_SIZE],
                     non_null() const uint8_t nonce[CRYPTO_NONCE_SIZE], non_null() const uint8_t *encrypted, size_t length, non_null() uint8_t *plain);

/**
 * @brief Fast encrypt/decrypt operations.
 *
 * Use if this is not a one-time communication. `encrypt_precompute` does the
 * shared-key generation once so it does not have to be performed on every
 * encrypt/decrypt.
 */
int32_t encrypt_precompute(non_null() const uint8_t public_key[CRYPTO_PUBLIC_KEY_SIZE], non_null() const uint8_t secret_key[CRYPTO_SECRET_KEY_SIZE],
                           non_null() uint8_t shared_key[CRYPTO_SHARED_KEY_SIZE]);

/**
 * @brief Encrypt message with precomputed shared key.
 *
 * Encrypts plain of length length to encrypted of length + @ref CRYPTO_MAC_SIZE
 * using a shared key @ref CRYPTO_SHARED_KEY_SIZE big and a @ref CRYPTO_NONCE_SIZE
 * byte nonce.
 *
 * @retval -1 if there was a problem.
 * @return length of encrypted data if everything was fine.
 */
int32_t encrypt_data_symmetric(non_null() const Memory *mem, non_null() const uint8_t shared_key[CRYPTO_SHARED_KEY_SIZE], non_null() const uint8_t nonce[CRYPTO_NONCE_SIZE],
                               non_null() const uint8_t *plain, size_t length, non_null() uint8_t *encrypted);

/**
 * @brief Decrypt message with precomputed shared key.
 *
 * Decrypts encrypted of length length to plain of length
 * `length - CRYPTO_MAC_SIZE` using a shared key @ref CRYPTO_SHARED_KEY_SIZE
 * big and a @ref CRYPTO_NONCE_SIZE byte nonce.
 *
 * @retval -1 if there was a problem (decryption failed).
 * @return length of plain data if everything was fine.
 */
int32_t decrypt_data_symmetric(non_null() const Memory *mem, non_null() const uint8_t shared_key[CRYPTO_SHARED_KEY_SIZE], non_null() const uint8_t nonce[CRYPTO_NONCE_SIZE],
                               non_null() const uint8_t *encrypted, size_t length, non_null() uint8_t *plain);

/**
 * @brief Increment the given nonce by 1 in big endian (rightmost byte incremented first).
 */
void increment_nonce(non_null() uint8_t nonce[CRYPTO_NONCE_SIZE]);

/**
 * @brief Increment the given nonce by a given number.
 *
 * The number should be in host byte order.
 */
void increment_nonce_number(non_null() uint8_t nonce[CRYPTO_NONCE_SIZE], uint32_t increment);

/**
 * @brief Fill a key @ref CRYPTO_SYMMETRIC_KEY_SIZE big with random bytes.
 */
void new_symmetric_key(non_null() const Random *rng, non_null() uint8_t key[CRYPTO_SYMMETRIC_KEY_SIZE]);

/**
 * @brief Locks `length` bytes of memory pointed to by `data`.
 *
 * This will attempt to prevent the specified memory region from being swapped
 * to disk.
 *
 * @return true on success.
 */
bool crypto_memlock(non_null() void *data, size_t length);

/**
 * @brief Unlocks `length` bytes of memory pointed to by `data`.
 *
 * This allows the specified memory region to be swapped to disk.
 *
 * This function call has the side effect of zeroing the specified memory region
 * whether or not it succeeds. Therefore it should only be used once the memory
 * is no longer in use.
 *
 * @return true on success.
 */
bool crypto_memunlock(non_null() void *data, size_t length);

/**
 * @brief Generate a random secret HMAC key.
 */
void new_hmac_key(non_null() const Random *rng, non_null() uint8_t key[CRYPTO_HMAC_KEY_SIZE]);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* C_TOXCORE_TOXCORE_CRYPTO_CORE_H */
