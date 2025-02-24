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
 * @brief NoiseIK: The number of bytes in a nonce used for encryption/decryption (ChaChaPoly1305-IETF).
 */
#define CRYPTO_NOISE_NONCE_SIZE              12

/**
 * @brief The number of bytes in a SHA256 hash.
 */
#define CRYPTO_SHA256_SIZE             32

/**
 * @brief The number of bytes in a SHA512 hash.
 */
#define CRYPTO_SHA512_SIZE             64

/**
 * @brief The number of bytes in a BLAKE2b-512 hash (as defined for Noise in section 12.8.).
 */
#define CRYPTO_NOISE_BLAKE2B_HASH_SIZE             64

/**
 * @brief The number of bytes in a BLAKE2b block.
 */
#define CRYPTO_BLAKE2B_BLOCK_SIZE             128

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

// TODO(goldroom): struct necessary?
/** @brief Necessary NoiseIK handshake state information/values.
 */
typedef struct Noise_Handshake {
    uint8_t static_private[CRYPTO_SECRET_KEY_SIZE];
    uint8_t static_public[CRYPTO_PUBLIC_KEY_SIZE];
    uint8_t ephemeral_private[CRYPTO_SECRET_KEY_SIZE];
    uint8_t ephemeral_public[CRYPTO_PUBLIC_KEY_SIZE];
    uint8_t remote_static[CRYPTO_PUBLIC_KEY_SIZE];
    uint8_t remote_ephemeral[CRYPTO_PUBLIC_KEY_SIZE];
    // TODO(goldroom): precompute static static? cf. WireGuard struct noise_handshake
    // uint8_t precomputed_static_static[CRYPTO_SHARED_KEY_SIZE];

    uint8_t hash[CRYPTO_SHA512_SIZE];
    uint8_t chaining_key[CRYPTO_SHA512_SIZE];

    bool initiator;
} Noise_Handshake;

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
non_null()
void crypto_memzero(void *data, size_t length);

/**
 * @brief Compute a SHA256 hash (32 bytes).
 *
 * @param[out] hash The SHA256 hash of @p data will be written to this byte array.
 */
non_null()
void crypto_sha256(uint8_t hash[CRYPTO_SHA256_SIZE], const uint8_t *data, size_t length);

/**
 * @brief Compute a SHA512 hash (64 bytes).
 *
 * @param[out] hash The SHA512 hash of @p data will be written to this byte array.
 */
non_null()
void crypto_sha512(uint8_t hash[CRYPTO_SHA512_SIZE], const uint8_t *data, size_t length);

/**
 * @brief Compute an HMAC authenticator (32 bytes).
 *
 * @param[out] auth Resulting authenticator.
 * @param key Secret key, as generated by `new_hmac_key()`.
 */
non_null()
void crypto_hmac(uint8_t auth[CRYPTO_HMAC_SIZE], const uint8_t key[CRYPTO_HMAC_KEY_SIZE],
                 const uint8_t *data, size_t length);

/**
 * @brief Verify an HMAC authenticator.
 */
non_null()
bool crypto_hmac_verify(const uint8_t auth[CRYPTO_HMAC_SIZE], const uint8_t key[CRYPTO_HMAC_KEY_SIZE],
                        const uint8_t *data, size_t length);

/**
 * @brief Compare 2 public keys of length @ref CRYPTO_PUBLIC_KEY_SIZE, not vulnerable to
 *   timing attacks.
 *
 * @retval true if both mem locations of length are equal
 * @retval false if they are not
 */
non_null()
bool pk_equal(const uint8_t pk1[CRYPTO_PUBLIC_KEY_SIZE], const uint8_t pk2[CRYPTO_PUBLIC_KEY_SIZE]);

/**
 * @brief Copy a public key from `src` to `dest`.
 */
non_null()
void pk_copy(uint8_t dest[CRYPTO_PUBLIC_KEY_SIZE], const uint8_t src[CRYPTO_PUBLIC_KEY_SIZE]);

/**
 * @brief Compare 2 SHA512 checksums of length CRYPTO_SHA512_SIZE, not vulnerable to
 *   timing attacks.
 *
 * @return true if both mem locations of length are equal, false if they are not.
 */
non_null()
bool crypto_sha512_eq(const uint8_t cksum1[CRYPTO_SHA512_SIZE], const uint8_t cksum2[CRYPTO_SHA512_SIZE]);

/**
 * @brief Compare 2 SHA256 checksums of length CRYPTO_SHA256_SIZE, not vulnerable to
 *   timing attacks.
 *
 * @return true if both mem locations of length are equal, false if they are not.
 */
non_null()
bool crypto_sha256_eq(const uint8_t cksum1[CRYPTO_SHA256_SIZE], const uint8_t cksum2[CRYPTO_SHA256_SIZE]);

/**
 * @brief Return a random 8 bit integer.
 */
non_null()
uint8_t random_u08(const Random *rng);

/**
 * @brief Return a random 16 bit integer.
 */
non_null()
uint16_t random_u16(const Random *rng);

/**
 * @brief Return a random 32 bit integer.
 */
non_null()
uint32_t random_u32(const Random *rng);

/**
 * @brief Return a random 64 bit integer.
 */
non_null()
uint64_t random_u64(const Random *rng);

/**
 * @brief Return a random 32 bit integer between 0 and upper_bound (excluded).
 *
 * This function guarantees a uniform distribution of possible outputs.
 */
non_null()
uint32_t random_range_u32(const Random *rng, uint32_t upper_bound);

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
non_null()
bool crypto_signature_create(uint8_t signature[CRYPTO_SIGNATURE_SIZE],
                             const uint8_t *message, uint64_t message_length,
                             const uint8_t secret_key[SIG_SECRET_KEY_SIZE]);

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
non_null()
bool crypto_signature_verify(const uint8_t signature[CRYPTO_SIGNATURE_SIZE],
                             const uint8_t *message, uint64_t message_length,
                             const uint8_t public_key[SIG_PUBLIC_KEY_SIZE]);

/**
 * @brief Fill the given nonce with random bytes.
 */
non_null()
void random_nonce(const Random *rng, uint8_t nonce[CRYPTO_NONCE_SIZE]);

/**
 * @brief Fill an array of bytes with random values.
 */
non_null()
void random_bytes(const Random *rng, uint8_t *bytes, size_t length);

/**
 * @brief Check if a Tox public key CRYPTO_PUBLIC_KEY_SIZE is valid or not.
 *
 * This should only be used for input validation.
 *
 * @return false if it isn't, true if it is.
 */
non_null()
bool public_key_valid(const uint8_t public_key[CRYPTO_PUBLIC_KEY_SIZE]);

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
non_null()
bool create_extended_keypair(Extended_Public_Key *pk, Extended_Secret_Key *sk, const Random *rng);

/** Functions for groupchat extended keys */
non_null() const uint8_t *get_enc_key(const Extended_Public_Key *key);
non_null() const uint8_t *get_sig_pk(const Extended_Public_Key *key);
non_null() void set_sig_pk(Extended_Public_Key *key, const uint8_t *sig_pk);
non_null() const uint8_t *get_sig_sk(const Extended_Secret_Key *key);
non_null() const uint8_t *get_chat_id(const Extended_Public_Key *key);

/**
 * @brief Generate a new random keypair.
 *
 * Every call to this function is likely to generate a different keypair.
 */
non_null()
int32_t crypto_new_keypair(const Random *rng,
                           uint8_t public_key[CRYPTO_PUBLIC_KEY_SIZE],
                           uint8_t secret_key[CRYPTO_SECRET_KEY_SIZE]);

/**
 * @brief Derive the public key from a given secret key.
 */
non_null()
void crypto_derive_public_key(uint8_t public_key[CRYPTO_PUBLIC_KEY_SIZE],
                              const uint8_t secret_key[CRYPTO_SECRET_KEY_SIZE]);

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
non_null()
int32_t encrypt_data(const Memory *mem,
                     const uint8_t public_key[CRYPTO_PUBLIC_KEY_SIZE],
                     const uint8_t secret_key[CRYPTO_SECRET_KEY_SIZE],
                     const uint8_t nonce[CRYPTO_NONCE_SIZE],
                     const uint8_t *plain, size_t length, uint8_t *encrypted);

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
non_null()
int32_t decrypt_data(const Memory *mem,
                     const uint8_t public_key[CRYPTO_PUBLIC_KEY_SIZE],
                     const uint8_t secret_key[CRYPTO_SECRET_KEY_SIZE],
                     const uint8_t nonce[CRYPTO_NONCE_SIZE],
                     const uint8_t *encrypted, size_t length, uint8_t *plain);

/**
 * @brief Fast encrypt/decrypt operations.
 *
 * Use if this is not a one-time communication. `encrypt_precompute` does the
 * shared-key generation once so it does not have to be performed on every
 * encrypt/decrypt.
 */
non_null()
int32_t encrypt_precompute(const uint8_t public_key[CRYPTO_PUBLIC_KEY_SIZE],
                           const uint8_t secret_key[CRYPTO_SECRET_KEY_SIZE],
                           uint8_t shared_key[CRYPTO_SHARED_KEY_SIZE]);

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
non_null()
int32_t encrypt_data_symmetric(const Memory *mem,
                               const uint8_t shared_key[CRYPTO_SHARED_KEY_SIZE],
                               const uint8_t nonce[CRYPTO_NONCE_SIZE],
                               const uint8_t *plain, size_t length, uint8_t *encrypted);

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
non_null()
int32_t decrypt_data_symmetric(const Memory *mem,
                               const uint8_t shared_key[CRYPTO_SHARED_KEY_SIZE],
                               const uint8_t nonce[CRYPTO_NONCE_SIZE],
                               const uint8_t *encrypted, size_t length, uint8_t *plain);

/**
 * @brief Increment the given nonce by 1 in big endian (rightmost byte incremented first).
 */
non_null()
void increment_nonce(uint8_t nonce[CRYPTO_NONCE_SIZE]);

/**
 * @brief Increment the given nonce by a given number.
 *
 * The number should be in host byte order.
 */
non_null()
void increment_nonce_number(uint8_t nonce[CRYPTO_NONCE_SIZE], uint32_t increment);

/**
 * @brief Fill a key @ref CRYPTO_SYMMETRIC_KEY_SIZE big with random bytes.
 */
non_null()
void new_symmetric_key(const Random *rng, uint8_t key[CRYPTO_SYMMETRIC_KEY_SIZE]);

/**
 * @brief Locks `length` bytes of memory pointed to by `data`.
 *
 * This will attempt to prevent the specified memory region from being swapped
 * to disk.
 *
 * @return true on success.
 */
non_null()
bool crypto_memlock(void *data, size_t length);

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
non_null()
bool crypto_memunlock(void *data, size_t length);

/**
 * @brief Generate a random secret HMAC key.
 */
non_null()
void new_hmac_key(const Random *rng, uint8_t key[CRYPTO_HMAC_KEY_SIZE]);

/* Necessary functions for Noise, cf. https://noiseprotocol.org/noise.html (Revision 34) */

/**
 * @brief Encrypt message with precomputed shared key using ChaCha20-Poly1305-IETF (RFC7539).
 *
 * Encrypts plain of plain_length to encrypted of plain_length + @ref CRYPTO_MAC_SIZE
 * using a shared key @ref CRYPTO_SYMMETRIC_KEY_SIZE big and a @ref CRYPTO_NOISE_NONCE_SIZE
 * byte nonce. The encrypted message, as well as a tag authenticating both the confidential
 * message m and adlen bytes of non-confidential data ad, are put into encrypted.
 *
 * @retval -1 if there was a problem.
 * @return length of encrypted data if everything was fine.
 */
non_null(1, 2, 3, 5) nullable(6)
int32_t encrypt_data_symmetric_aead(const uint8_t shared_key[CRYPTO_SHARED_KEY_SIZE], const uint8_t nonce[CRYPTO_NOISE_NONCE_SIZE], const uint8_t *plain, size_t plain_length,
                                    uint8_t *encrypted, const uint8_t *ad, size_t ad_length);

/**
 * @brief Decrypt message with precomputed shared key using ChaCha20-Poly1305-IETF (RFC7539).
 *
 * Decrypts encrypted of encrypted_length to plain of length
 * `length - CRYPTO_MAC_SIZE` using a shared key @ref CRYPTO_SHARED_KEY_SIZE
 * big and a @ref CRYPTO_NOISE_NONCE_SIZE byte nonce.
 *
 * @retval -1 if there was a problem (decryption failed).
 * @return length of plain data if everything was fine.
 */
non_null(1, 2, 3, 5) nullable(6)
int32_t decrypt_data_symmetric_aead(const uint8_t shared_key[CRYPTO_SHARED_KEY_SIZE], const uint8_t nonce[CRYPTO_NOISE_NONCE_SIZE], const uint8_t *encrypted, size_t encrypted_length,
                                    uint8_t *plain, const uint8_t *ad, size_t ad_length);

/**
 * @brief Encrypt message with precomputed shared key using XChaCha20-Poly1305.
 *
 * Encrypts plain of plain_length to encrypted of plain_length + @ref CRYPTO_MAC_SIZE
 * using a shared key @ref CRYPTO_SYMMETRIC_KEY_SIZE big and a @ref CRYPTO_NONCE_SIZE
 * byte nonce. The encrypted message, as well as a tag authenticating both the confidential
 * message m and adlen bytes of non-confidential data ad, are put into encrypted.
 *
 * @retval -1 if there was a problem.
 * @return length of encrypted data if everything was fine.
 */
non_null(1, 2, 3, 5) nullable(6)
int32_t encrypt_data_symmetric_xaead(const uint8_t shared_key[CRYPTO_SHARED_KEY_SIZE], const uint8_t nonce[CRYPTO_NONCE_SIZE], const uint8_t *plain, size_t plain_length,
                                    uint8_t *encrypted, const uint8_t *ad, size_t ad_length);

/**
 * @brief Decrypt message with precomputed shared key using XChaCha20-Poly1305.
 *
 * Decrypts encrypted of encrypted_length to plain of length
 * `length - CRYPTO_MAC_SIZE` using a shared key @ref CRYPTO_SHARED_KEY_SIZE
 * big and a @ref CRYPTO_NONCE_SIZE byte nonce.
 *
 * @retval -1 if there was a problem (decryption failed).
 * @return length of plain data if everything was fine.
 */
non_null(1, 2, 3, 5) nullable(6)
int32_t decrypt_data_symmetric_xaead(const uint8_t shared_key[CRYPTO_SHARED_KEY_SIZE], const uint8_t nonce[CRYPTO_NONCE_SIZE], const uint8_t *encrypted, size_t encrypted_length,
                                    uint8_t *plain, const uint8_t *ad, size_t ad_length);

/**
 * @brief Computes the number of provides outputs (=keys) with HKDF-SHA512.
 *
 * cf. Noise sections 4.3 and 5.1
 *
 * This is Hugo Krawczyk's HKDF:
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
 * @param output1 First key to compute
 * @param first_len Length of output1/key
 * @param output2 Second key to compute
 * @param second_len Length of output2/key
 * @param data HKDF input_key_material byte sequence with length either zero bytes, 32 bytes, or DHLEN bytes
 * @param data_len length of either zero bytes, 32 bytes, or DHLEN bytes
 * @param chaining_key Noise 64 byte chaining key as HKDF salt
 */
non_null(1, 3, 7) nullable(5)
void crypto_hkdf(uint8_t *output1, size_t first_len, uint8_t *output2,
                 size_t second_len, const uint8_t *data,
                 size_t data_len, const uint8_t chaining_key[CRYPTO_SHA512_SIZE]);

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
 * @param noise_handshake Noise handshake struct to save the necessary values to
 * @param self_id_secret_key static private ID X25519 key of this Tox instance
 * @param peer_id_public_key static public ID X25519 key from the peer to connect to
 * @param initiator specifies if this Tox instance is the initiator of this crypto connection
 * @param prologue specifies the Noise prologue, used in call to MixHash(prologue) which maybe zero-length
 * @param prologue_length length of Noise prologue in bytes
 *
 * @return -1 on failure
 * @return 0 on success
 */
non_null(1, 2) nullable(3, 5)
int noise_handshake_init
(Noise_Handshake *noise_handshake, const uint8_t self_id_secret_key[CRYPTO_SECRET_KEY_SIZE], const uint8_t peer_id_public_key[CRYPTO_PUBLIC_KEY_SIZE], bool initiator, const uint8_t *prologue, size_t prologue_length);

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
 non_null()
int32_t noise_mix_key(uint8_t chaining_key[CRYPTO_SHA512_SIZE], uint8_t shared_key[CRYPTO_SHARED_KEY_SIZE],
                      const uint8_t private_key[CRYPTO_SECRET_KEY_SIZE],
                      const uint8_t public_key[CRYPTO_PUBLIC_KEY_SIZE]);

/**
 * @brief Noise MixHash(data): Sets h = HASH(h || data).
 *
 * cf. Noise section 5.2
 *
 * @param hash Contains current hash, is updated with new hash
 * @param data to add to hash
 * @param data_len length of data to hash
 *
 */
non_null(1) nullable(2)
void noise_mix_hash(uint8_t hash[CRYPTO_SHA512_SIZE], const uint8_t *data, size_t data_len);

/**
 * @brief Noise EncryptAndHash(plaintext): Sets ciphertext = EncryptWithAd(h,
 * plaintext), calls MixHash(ciphertext), and returns ciphertext. Note
 * that if k is empty, the EncryptWithAd() call will set ciphertext equal
 * to plaintext.
 *
 * cf. Noise section 5.2
 * "Noise spec: Note that if k is empty, the EncryptWithAd() call will set ciphertext equal to plaintext."
 * This is not the case in Tox.
 *
 * @param ciphertext stores encrypted plaintext
 * @param plaintext to be encrypted
 * @param plain_length length of plaintext
 * @param shared_key used for XAEAD encryption
 * @param hash stores hash value, used as associated data in XAEAD
 */
non_null()
void noise_encrypt_and_hash(uint8_t *ciphertext, const uint8_t *plaintext,
                            size_t plain_length, uint8_t shared_key[CRYPTO_SHARED_KEY_SIZE],
                            uint8_t hash[CRYPTO_SHA512_SIZE]);

/**
 * @brief DecryptAndHash(ciphertext): Sets plaintext = DecryptWithAd(h,
 * ciphertext), calls MixHash(ciphertext), and returns plaintext. Note
 * that if k is empty, the DecryptWithAd() call will set plaintext equal to
 * ciphertext.
 *
 * cf. Noise section 5.2
 * "Note that if k is empty, the DecryptWithAd() call will set plaintext equal to ciphertext."
 * This is not the case in Tox.
 *
 * @param ciphertext contains ciphertext to decrypt
 * @param plaintext stores decrypted ciphertext
 * @param encrypted_length length of ciphertext+MAC
 * @param shared_key used for XAEAD decryption
 * @param hash stores hash value, used as associated data in XAEAD
 */
non_null()
int noise_decrypt_and_hash(uint8_t *plaintext, const uint8_t *ciphertext, 
                           size_t encrypted_length, uint8_t shared_key[CRYPTO_SHARED_KEY_SIZE],
                           uint8_t hash[CRYPTO_SHA512_SIZE]);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* C_TOXCORE_TOXCORE_CRYPTO_CORE_H */
