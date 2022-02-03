/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2020 The TokTok team.
 * Copyright © 2015 Tox project.
 */

/**
 * An implementation of massive text only group chats.
 */

#ifndef GROUP_MODERATION_H
#define GROUP_MODERATION_H

#include <stdbool.h>
#include <stdint.h>

#include "DHT.h"
#include "logger.h"

/* Maximum number of allowed sanctions. This value must take into account the maxmimum allowed group packet size. */
#define MOD_MAX_NUM_SANCTIONS 12

#define MOD_MODERATION_HASH_SIZE CRYPTO_SHA256_SIZE
#define MOD_LIST_ENTRY_SIZE SIG_PUBLIC_KEY_SIZE
#define MOD_SANCTION_HASH_SIZE CRYPTO_SHA256_SIZE
#define MOD_MAX_NUM_MODERATORS 30

/* Corresponds to Mod_Sanction_Creds in group_chats.h */
#define MOD_SANCTIONS_CREDS_SIZE (sizeof(uint32_t) + MOD_SANCTION_HASH_SIZE + sizeof(uint16_t) +\
                                       SIG_PUBLIC_KEY_SIZE + SIGNATURE_SIZE)

typedef enum Mod_Sanction_Type {
    SA_OBSERVER = 0x00,
    SA_INVALID  = 0x01,
} Mod_Sanction_Type;

typedef struct Mod_Sanction_Creds {
    uint32_t    version;
    uint8_t     hash[MOD_SANCTION_HASH_SIZE];    // hash of all sanctions list signatures + version
    uint16_t    checksum;  // a sum of the hash
    uint8_t     sig_pk[SIG_PUBLIC_KEY_SIZE];    // Last mod to have modified the sanctions list
    uint8_t     sig[SIGNATURE_SIZE];    // signature of hash, signed by sig_pk
} Mod_Sanction_Creds;

/** Holds data pertaining to a peer who has been sanctioned. */
typedef struct Mod_Sanction {
    uint8_t     setter_public_sig_key[SIG_PUBLIC_KEY_SIZE];
    uint64_t    time_set;

    uint8_t     type;
    uint8_t     target_public_enc_key[ENC_PUBLIC_KEY_SIZE];

    /* Signature of all above packed data signed by the owner of public_sig_key */
    uint8_t     signature[SIGNATURE_SIZE];
} Mod_Sanction;

typedef struct Moderation {
    const       Logger *log;

    Mod_Sanction *sanctions;
    uint16_t    num_sanctions;

    Mod_Sanction_Creds sanctions_creds;

    uint8_t     **mod_list;  // array of public signature keys of all the mods
    uint16_t    num_mods;

    const uint8_t     *founder_public_sig_key;  // points to shared state object
    const uint8_t     *self_public_sig_key;     // points to parent chat object
    const uint8_t     *self_secret_sig_key;     // points to parent chat object
    const uint32_t    *shared_state_version;    // points to shared state object
} Moderation;

/** Unpacks data into the moderator list.
 * data should contain num_mods entries of size MOD_LIST_ENTRY_SIZE.
 *
 * Returns length of unpacked data on success.
 * Returns -1 on failure.
 */
int mod_list_unpack(Moderation *moderation, const uint8_t *data, uint16_t length, uint16_t num_mods);

/** Packs moderator list into data.
 * data must have room for `num_mods * MOD_LIST_ENTRY_SIZE` bytes.
 */
void mod_list_pack(const Moderation *moderation, uint8_t *data);

/** Creates a new moderator list hash and puts it in `hash`.
 *
 * `hash` must have room for at least GC_MOD_LIST_HASH_SIZE bytes.
 *
 * If num_mods is 0 the hash is zeroed.
 *
 * Returns 0 on sucess.
 * Returns -1 on failure.
 */
int mod_list_make_hash(const Moderation *moderation, uint8_t *hash);

/** Puts a sha256 hash of `packed_mod_list` of `length` bytes in `hash`.
 *
 * `hash` must have room for at least GC_MOD_LIST_HASH_SIZE bytes.
 */
void mod_list_get_data_hash(uint8_t *hash, const uint8_t *packed_mod_list, size_t length);

/** Removes moderator at index-th position in the moderator list.
 *
 * Returns 0 on success.
 * Returns -1 on failure.
 */
int mod_list_remove_index(Moderation *moderation, size_t index);

/** Removes public_sig_key from the moderator list.
 *
 * Returns 0 on success.
 * Returns -1 on failure.
 */
int mod_list_remove_entry(Moderation *moderation, const uint8_t *public_sig_key);

/** Adds a mod to the moderator list. mod_data must be MOD_LIST_ENTRY_SIZE bytes.
 *
 * Returns 0 on success.
 * Returns -1 on failure.
 */
int mod_list_add_entry(Moderation *moderation, const uint8_t *mod_data);

/** Returns true if the public signature key belongs to a moderator or the founder */
bool mod_list_verify_sig_pk(const Moderation *moderation, const uint8_t *sig_pk);

/** Frees all memory associated with the moderator list and sets num_mods to 0. */
void mod_list_cleanup(Moderation *moderation);

/** Packs num_sanctions sanctions into data of maxlength length. Additionally packs the
 * sanctions list credentials into creds if creds is non-NULL.
 *
 * Returns length of packed data on success.
 * Returns -1 on failure.
 */
int sanctions_list_pack(uint8_t *data, uint16_t length, const Mod_Sanction *sanctions,
                        const Mod_Sanction_Creds *creds, uint16_t num_sanctions);

/** Unpack max_sanctions sanctions from data into sanctions, and unpacks credentials into creds.
 * Put the length of the data processed in processed_data_len.
 *
 * Returns number of unpacked entries on success.
 * Returns -1 on failure.
 */
int sanctions_list_unpack(Mod_Sanction *sanctions, Mod_Sanction_Creds *creds, uint16_t max_sanctions,
                          const uint8_t *data, uint16_t length, uint16_t *processed_data_len);

/** Packs sanction list credentials into data.
 * data must have room for MOD_SANCTIONS_CREDS_SIZE bytes.
 *
 * Returns length of packed data.
 */
uint16_t sanctions_creds_pack(const Mod_Sanction_Creds *creds, uint8_t *data, uint16_t length);

/** Unpacks sanctions credentials into creds from data.
 * data must have room for MOD_SANCTIONS_CREDS_SIZE bytes.
 *
 * Returns the length of the data processed.
 */
uint16_t sanctions_creds_unpack(Mod_Sanction_Creds *creds, const uint8_t *data, uint16_t length);

/** Updates sanction list credentials: increment version, replace sig_pk with your own,
 * update hash to reflect new sanction list, and sign new hash signature.
 *
 * Returns 0 on success.
 * Returns -1 on failure.
 */
int sanctions_list_make_creds(Moderation *moderation);

/** Validates all sanctions list entries as well as the list itself.
 *
 * Returns 0 if all entries are valid.
 * Returns -1 if one or more entries are invalid.
 */
int sanctions_list_check_integrity(const Moderation *moderation, const Mod_Sanction_Creds *creds,
                                   const Mod_Sanction *sanctions, uint16_t num_sanctions);

/** Adds an entry to the sanctions list. The entry is first validated and the resulting
 * new sanction list is compared against the new credentials.
 *
 * Entries must be unique.
 *
 * Returns 0 on success.
 * Returns -1 on failure.
 */
int sanctions_list_add_entry(Moderation *moderation, const Mod_Sanction *sanction, const Mod_Sanction_Creds *creds);

/** Creates a new sanction entry for `public_key` where type is one GROUP_SANCTION_TYPE.
 * New entry is signed and placed in the sanctions list.
 *
 * Returns 0 on success.
 * Returns -1 on failure.
 */
int sanctions_list_make_entry(Moderation *moderation, const uint8_t *public_key, Mod_Sanction *sanction,
                              uint8_t type);

/** Returns true if public key is in the observer list. */
bool sanctions_list_is_observer(const Moderation *moderation, const uint8_t *public_key);

/** Returns true if sanction already exists in the sanctions list. */
bool sanctions_list_entry_exists(const Moderation *moderation, const Mod_Sanction *sanction);

/** Removes observer entry for public key from sanction list.
 * If creds is NULL we make new credentials (this should only be done by a moderator or founder)
 *
 * Returns 0 on success.
 * Returns -1 on failure or if entry was not found.
 */
int sanctions_list_remove_observer(Moderation *moderation, const uint8_t *public_key,
                                   const Mod_Sanction_Creds *creds);

/** Replaces all sanctions list signatures made by public_sig_key with the caller's.
 * This is called whenever the founder demotes a moderator.
 *
 * Returns the number of entries re-signed.
 */
uint16_t sanctions_list_replace_sig(Moderation *moderation, const uint8_t *public_sig_key);

void sanctions_list_cleanup(Moderation *moderation);

#endif // GROUP_MODERATION_H
