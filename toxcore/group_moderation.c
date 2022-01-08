/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2020 The TokTok team.
 * Copyright © 2015 Tox project.
 */

/*
 * An implementation of massive text only group chats.
 */

#include "group_moderation.h"

#include <string.h>

#include "mono_time.h"
#include "network.h"
#include "util.h"

#ifndef VANILLA_NACL
#include <sodium.h>
#endif // VANILLA_NACL

#ifndef VANILLA_NACL

#define TIME_STAMP_SIZE sizeof(uint64_t)

int mod_list_unpack(Moderation *moderation, const uint8_t *data, uint32_t length, uint16_t num_mods)
{
    if (length != num_mods * MOD_LIST_ENTRY_SIZE) {
        return -1;
    }

    mod_list_cleanup(moderation);

    if (num_mods == 0) {
        return 0;
    }

    uint8_t **tmp_list = (uint8_t **)malloc(sizeof(uint8_t *) * num_mods);

    if (tmp_list == nullptr) {
        return -1;
    }

    uint32_t unpacked_len = 0;

    for (uint16_t i = 0; i < num_mods; ++i) {
        tmp_list[i] = (uint8_t *)malloc(sizeof(uint8_t) * MOD_LIST_ENTRY_SIZE);

        if (tmp_list[i] == nullptr) {
            free_uint8_t_pointer_array(tmp_list, i);
            return -1;
        }

        memcpy(tmp_list[i], &data[i * MOD_LIST_ENTRY_SIZE], MOD_LIST_ENTRY_SIZE);
        unpacked_len += MOD_LIST_ENTRY_SIZE;
    }

    moderation->mod_list = tmp_list;
    moderation->num_mods = num_mods;

    return unpacked_len;
}

void mod_list_pack(const Moderation *moderation, uint8_t *data)
{
    for (uint16_t i = 0; i < moderation->num_mods && i < MOD_MAX_NUM_MODERATORS; ++i) {
        memcpy(&data[i * MOD_LIST_ENTRY_SIZE], moderation->mod_list[i], MOD_LIST_ENTRY_SIZE);
    }
}

void mod_list_get_data_hash(uint8_t *hash, const uint8_t *packed_mod_list, size_t length)
{
    crypto_hash_sha256(hash, packed_mod_list, length);
}

int mod_list_make_hash(Moderation *moderation, uint8_t *hash)
{
    if (moderation->num_mods == 0) {
        memset(hash, 0, MOD_MODERATION_HASH_SIZE);
        return 0;
    }

    const size_t data_buf_size = moderation->num_mods * MOD_LIST_ENTRY_SIZE;
    uint8_t *data = (uint8_t *)malloc(data_buf_size);

    if (data == nullptr) {
        return -1;
    }

    mod_list_pack(moderation, data);

    mod_list_get_data_hash(hash, data, data_buf_size);

    free(data);

    return 0;
}

/* Returns moderator list index for public_sig_key.
 * Returns -1 if key is not in the list.
 */
static int mod_list_index_of_sig_pk(const Moderation *moderation, const uint8_t *public_sig_key)
{
    for (uint16_t i = 0; i < moderation->num_mods; ++i) {
        if (memcmp(moderation->mod_list[i], public_sig_key, SIG_PUBLIC_KEY_SIZE) == 0) {
            return i;
        }
    }

    return -1;
}

bool mod_list_verify_sig_pk(const Moderation *moderation, const uint8_t *sig_pk)
{
    if (memcmp(moderation->founder_public_sig_key, sig_pk, SIG_PUBLIC_KEY_SIZE) == 0) {
        return true;
    }

    for (uint16_t i = 0; i < moderation->num_mods; ++i) {
        if (memcmp(moderation->mod_list[i], sig_pk, SIG_PUBLIC_KEY_SIZE) == 0) {
            return true;
        }
    }

    return false;
}

int mod_list_remove_index(Moderation *moderation, size_t index)
{
    if (index >= moderation->num_mods) {
        return -1;
    }

    if (moderation->num_mods == 0) {
        return -1;
    }

    if ((moderation->num_mods - 1) == 0) {
        mod_list_cleanup(moderation);
        return 0;
    }

    --moderation->num_mods;

    if (index != moderation->num_mods) {
        memcpy(moderation->mod_list[index], moderation->mod_list[moderation->num_mods],
               MOD_LIST_ENTRY_SIZE);
    }

    free(moderation->mod_list[moderation->num_mods]);
    moderation->mod_list[moderation->num_mods] = nullptr;

    uint8_t **tmp_list = (uint8_t **)realloc(moderation->mod_list, sizeof(uint8_t *) * moderation->num_mods);

    if (tmp_list == nullptr) {
        return -1;
    }

    moderation->mod_list = tmp_list;

    return 0;
}

int mod_list_remove_entry(Moderation *moderation, const uint8_t *public_sig_key)
{
    if (moderation->num_mods == 0) {
        return -1;
    }

    const int idx = mod_list_index_of_sig_pk(moderation, public_sig_key);

    if (idx == -1) {
        return -1;
    }

    if (mod_list_remove_index(moderation, idx) == -1) {
        return -1;
    }

    return 0;
}

int mod_list_add_entry(Moderation *moderation, const uint8_t *mod_data)
{
    if (moderation->num_mods >= MOD_MAX_NUM_MODERATORS) {
        return -1;
    }

    uint8_t **tmp_list = (uint8_t **)realloc(moderation->mod_list, sizeof(uint8_t *) * (moderation->num_mods + 1));

    if (tmp_list == nullptr) {
        return -1;
    }

    moderation->mod_list = tmp_list;

    tmp_list[moderation->num_mods] = (uint8_t *)malloc(sizeof(uint8_t) * MOD_LIST_ENTRY_SIZE);

    if (tmp_list[moderation->num_mods] == nullptr) {
        return -1;
    }

    memcpy(tmp_list[moderation->num_mods], mod_data, MOD_LIST_ENTRY_SIZE);
    ++moderation->num_mods;

    return 0;
}

void mod_list_cleanup(Moderation *moderation)
{
    free_uint8_t_pointer_array(moderation->mod_list, moderation->num_mods);
    moderation->num_mods = 0;
    moderation->mod_list = nullptr;
}

uint16_t sanctions_creds_pack(const Mod_Sanction_Creds *creds, uint8_t *data, uint16_t length)
{
    if (MOD_SANCTIONS_CREDS_SIZE > length) {
        return 0;
    }

    uint16_t packed_len = 0;

    net_pack_u32(data + packed_len, creds->version);
    packed_len += sizeof(uint32_t);
    memcpy(data + packed_len, creds->hash, MOD_SANCTION_HASH_SIZE);
    packed_len += MOD_SANCTION_HASH_SIZE;
    net_pack_u16(data + packed_len, creds->checksum);
    packed_len += sizeof(uint16_t);
    memcpy(data + packed_len, creds->sig_pk, SIG_PUBLIC_KEY_SIZE);
    packed_len += SIG_PUBLIC_KEY_SIZE;
    memcpy(data + packed_len, creds->sig, SIGNATURE_SIZE);
    packed_len += SIGNATURE_SIZE;

    return packed_len;
}

int sanctions_list_pack(uint8_t *data, uint16_t length, Mod_Sanction *sanctions,
                        const Mod_Sanction_Creds *creds, uint16_t num_sanctions)
{
    uint32_t packed_len = 0;

    for (uint16_t i = 0; i < num_sanctions && i < MOD_MAX_NUM_SANCTIONS; ++i) {
        if (packed_len + sizeof(uint8_t) + SIG_PUBLIC_KEY_SIZE + TIME_STAMP_SIZE > length) {
            return -1;
        }

        memcpy(data + packed_len, &sanctions[i].type, sizeof(uint8_t));
        packed_len += sizeof(uint8_t);
        memcpy(data + packed_len, sanctions[i].public_sig_key, SIG_PUBLIC_KEY_SIZE);
        packed_len += SIG_PUBLIC_KEY_SIZE;
        net_pack_u64(data + packed_len, sanctions[i].time_set);
        packed_len += TIME_STAMP_SIZE;

        const uint8_t sanctions_type = sanctions[i].type;

        if (sanctions_type == SA_OBSERVER) {
            if (packed_len + ENC_PUBLIC_KEY_SIZE > length) {
                return -1;
            }

            memcpy(data + packed_len, sanctions[i].info.target_pk, ENC_PUBLIC_KEY_SIZE);
            packed_len += ENC_PUBLIC_KEY_SIZE;
        } else {
            return -1;
        }

        if (packed_len + SIGNATURE_SIZE > length) {
            return -1;
        }

        /* Signature must be packed last */
        memcpy(data + packed_len, sanctions[i].signature, SIGNATURE_SIZE);
        packed_len += SIGNATURE_SIZE;
    }

    if (creds == nullptr) {
        return packed_len;
    }

    const uint16_t cred_len = sanctions_creds_pack(creds, data + packed_len, length - packed_len);

    if (cred_len != MOD_SANCTIONS_CREDS_SIZE) {
        return -1;
    }

    return packed_len + cred_len;
}

uint16_t sanctions_creds_unpack(Mod_Sanction_Creds *creds, const uint8_t *data, uint16_t length)
{
    if (MOD_SANCTIONS_CREDS_SIZE > length) {
        return 0;
    }

    uint16_t len_processed = 0;

    net_unpack_u32(data + len_processed, &creds->version);
    len_processed += sizeof(uint32_t);
    memcpy(creds->hash, data + len_processed, MOD_SANCTION_HASH_SIZE);
    len_processed += MOD_SANCTION_HASH_SIZE;
    net_unpack_u16(data + len_processed, &creds->checksum);
    len_processed += sizeof(uint16_t);
    memcpy(creds->sig_pk, data + len_processed, SIG_PUBLIC_KEY_SIZE);
    len_processed += SIG_PUBLIC_KEY_SIZE;
    memcpy(creds->sig, data + len_processed, SIGNATURE_SIZE);
    len_processed += SIGNATURE_SIZE;

    return len_processed;
}

int sanctions_list_unpack(Mod_Sanction *sanctions, Mod_Sanction_Creds *creds, uint16_t max_sanctions,
                          const uint8_t *data, uint16_t length, uint16_t *processed_data_len)
{
    uint16_t num = 0;
    uint16_t len_processed = 0;

    while (num < max_sanctions && num < MOD_MAX_NUM_SANCTIONS && len_processed < length) {
        if (len_processed + sizeof(uint8_t) + SIG_PUBLIC_KEY_SIZE + TIME_STAMP_SIZE > length) {
            return -1;
        }

        memcpy(&sanctions[num].type, data + len_processed, sizeof(uint8_t));
        len_processed += sizeof(uint8_t);
        memcpy(sanctions[num].public_sig_key, data + len_processed, SIG_PUBLIC_KEY_SIZE);
        len_processed += SIG_PUBLIC_KEY_SIZE;
        net_unpack_u64(data + len_processed, &sanctions[num].time_set);
        len_processed += TIME_STAMP_SIZE;

        if (sanctions[num].type == SA_OBSERVER) {
            if (len_processed + ENC_PUBLIC_KEY_SIZE > length) {
                return -1;
            }

            memcpy(sanctions[num].info.target_pk, data + len_processed, ENC_PUBLIC_KEY_SIZE);
            len_processed += ENC_PUBLIC_KEY_SIZE;
        } else {
            return -1;
        }

        if (len_processed + SIGNATURE_SIZE > length) {
            return -1;
        }

        memcpy(sanctions[num].signature, data + len_processed, SIGNATURE_SIZE);
        len_processed += SIGNATURE_SIZE;

        ++num;
    }

    const uint16_t creds_len = sanctions_creds_unpack(creds, data + len_processed, length - len_processed);

    if (creds_len != MOD_SANCTIONS_CREDS_SIZE) {
        return -1;
    }

    if (processed_data_len) {
        *processed_data_len = len_processed + creds_len;
    }

    return num;
}


/* Creates a new sanction list hash and puts it in hash.
 *
 * The hash is derived from the signature of all entries plus the version number.
 * hash must have room for at least MOD_SANCTION_HASH_SIZE bytes.
 *
 * If num_sanctions is 0 the hash is zeroed.
 *
 * Return 0 on success.
 * Return -1 on failure.
 */
static int sanctions_list_make_hash(Mod_Sanction *sanctions, uint32_t new_version, uint16_t num_sanctions,
                                    uint8_t *hash)
{
    if (num_sanctions == 0 || sanctions == nullptr) {
        memset(hash, 0, MOD_SANCTION_HASH_SIZE);
        return 0;
    }

    const size_t sig_data_size = num_sanctions * SIGNATURE_SIZE;
    const size_t data_buf_size = sig_data_size + sizeof(uint32_t);

    // check for integer overflower
    if (data_buf_size < num_sanctions) {
        return -1;
    }

    uint8_t *data = (uint8_t *)malloc(data_buf_size);

    if (data == nullptr) {
        return -1;
    }

    for (uint16_t i = 0; i < num_sanctions; ++i) {
        memcpy(&data[i * SIGNATURE_SIZE], sanctions[i].signature, SIGNATURE_SIZE);
    }

    memcpy(&data[sig_data_size], &new_version, sizeof(uint32_t));
    crypto_hash_sha256(hash, data, data_buf_size);

    free(data);

    return 0;
}

/* Verifies that sanction contains valid info and was assigned by a current mod or group founder.
 *
 * Returns 0 on success.
 * Returns -1 on failure.
 */
static int sanctions_list_validate_entry(const Moderation *moderation, Mod_Sanction *sanction)
{
    if (!mod_list_verify_sig_pk(moderation, sanction->public_sig_key)) {
        return -1;
    }

    if (sanction->type >= SA_INVALID) {
        return -1;
    }

    if (sanction->time_set == 0) {
        return -1;
    }

    uint8_t packed_data[sizeof(Mod_Sanction)];
    const int packed_len = sanctions_list_pack(packed_data, sizeof(packed_data), sanction, nullptr, 1);

    if (packed_len <= (int) SIGNATURE_SIZE) {
        return -1;
    }

    if (crypto_sign_verify_detached(sanction->signature, packed_data, packed_len - SIGNATURE_SIZE,
                                    sanction->public_sig_key) == -1) {
        return -1;
    }

    return 0;
}

static uint16_t sanctions_creds_get_checksum(const Mod_Sanction_Creds *creds)
{
    uint16_t sum = 0;

    for (size_t i = 0; i < MOD_SANCTION_HASH_SIZE; ++i) {
        sum += creds->hash[i];
    }

    return sum;
}

static void sanctions_creds_set_checksum(Mod_Sanction_Creds *creds)
{
    creds->checksum = sanctions_creds_get_checksum(creds);
}

int sanctions_list_make_creds(Moderation *moderation)
{
    Mod_Sanction_Creds old_creds;
    memcpy(&old_creds, &moderation->sanctions_creds, sizeof(Mod_Sanction_Creds));

    ++moderation->sanctions_creds.version;

    memcpy(moderation->sanctions_creds.sig_pk, moderation->self_public_sig_key, SIG_PUBLIC_KEY_SIZE);

    uint8_t hash[MOD_SANCTION_HASH_SIZE];

    if (sanctions_list_make_hash(moderation->sanctions, moderation->sanctions_creds.version,
                                 moderation->num_sanctions, hash) == -1) {
        memcpy(&moderation->sanctions_creds, &old_creds, sizeof(Mod_Sanction_Creds));
        return -1;
    }

    memcpy(moderation->sanctions_creds.hash, hash, MOD_SANCTION_HASH_SIZE);

    sanctions_creds_set_checksum(&moderation->sanctions_creds);

    if (crypto_sign_detached(moderation->sanctions_creds.sig, nullptr, moderation->sanctions_creds.hash,
                             MOD_SANCTION_HASH_SIZE, moderation->self_secret_sig_key) == -1) {
        memcpy(&moderation->sanctions_creds, &old_creds, sizeof(Mod_Sanction_Creds));
        return -1;
    }

    return 0;
}

/* Validates sanction list credentials. Verifies that:
 * - the public signature key belongs to a mod or the founder
 * - the signature for the hash was made by the owner of the public signature key.
 * - the received hash matches our own hash of the new sanctions list
 * - the received checksum matches the received hash
 * - the new version is >= our current version
 *
 * Returns 0 on success.
 * Returns -1 on failure.
 */
static int sanctions_creds_validate(const Moderation *moderation, Mod_Sanction *sanctions,
                                    Mod_Sanction_Creds *creds, uint16_t num_sanctions,
                                    uint16_t shared_state_version)
{
    if (!mod_list_verify_sig_pk(moderation, creds->sig_pk)) {
        LOGGER_WARNING(moderation->logger, "Invalid credentials signature pk");
        return -1;
    }

    uint8_t hash[MOD_SANCTION_HASH_SIZE];

    if (sanctions_list_make_hash(sanctions, creds->version, num_sanctions, hash) == -1) {
        return -1;
    }

    if (memcmp(hash, creds->hash, MOD_SANCTION_HASH_SIZE) != 0) {
        LOGGER_WARNING(moderation->logger, "Invalid credentials hash");
        return -1;
    }

    if (creds->checksum != sanctions_creds_get_checksum(creds)) {
        LOGGER_WARNING(moderation->logger, "Invalid credentials checksum");
        return -1;
    }

    if (shared_state_version > 0) {
        if ((creds->version < moderation->sanctions_creds.version)
                && !(creds->version == 0 && moderation->sanctions_creds.version == UINT32_MAX)) {
            LOGGER_WARNING(moderation->logger, "Invalid version");
            return -1;
        }
    }

    if (crypto_sign_verify_detached(creds->sig, hash, MOD_SANCTION_HASH_SIZE, creds->sig_pk) == -1) {
        LOGGER_WARNING(moderation->logger, "Invalid signature");
        return -1;
    }

    return 0;
}

int sanctions_list_check_integrity(const Moderation *moderation, Mod_Sanction_Creds *creds,
                                   Mod_Sanction *sanctions, uint16_t num_sanctions, uint32_t shared_state_version)
{
    for (uint16_t i = 0; i < num_sanctions; ++i) {
        if (sanctions_list_validate_entry(moderation, &sanctions[i]) != 0) {
            LOGGER_WARNING(moderation->logger, "Invalid entry");
            return -1;
        }
    }

    if (sanctions_creds_validate(moderation, sanctions, creds, num_sanctions, shared_state_version) == -1) {
        return -1;
    }

    return 0;
}

/* Removes index-th sanction list entry. New credentials will be validated if creds is non-null.
 *
 * Returns 0 on success.
 * Returns -1 on failure.
 */
static int sanctions_list_remove_index(Moderation *moderation, uint16_t index, Mod_Sanction_Creds *creds,
                                       uint32_t shared_state_version)
{
    if (index >= moderation->num_sanctions || moderation->num_sanctions == 0) {
        return -1;
    }

    const uint16_t new_num = moderation->num_sanctions - 1;

    if (new_num == 0) {
        if (creds) {
            if (sanctions_creds_validate(moderation, nullptr, creds, 0, shared_state_version) == -1) {
                return -1;
            }

            memcpy(&moderation->sanctions_creds, creds, sizeof(Mod_Sanction_Creds));
        }

        sanctions_list_cleanup(moderation);

        return 0;
    }

    /* Operate on a copy of the list in case something goes wrong. */
    const size_t old_size = sizeof(Mod_Sanction) * moderation->num_sanctions;
    Mod_Sanction *sanctions_copy = (Mod_Sanction *)malloc(old_size);

    if (sanctions_copy == nullptr) {
        return -1;
    }

    memcpy(sanctions_copy, moderation->sanctions, old_size);

    if (index != new_num) {
        memcpy(&sanctions_copy[index], &sanctions_copy[new_num], sizeof(Mod_Sanction));
    }

    Mod_Sanction *new_list = (Mod_Sanction *)realloc(sanctions_copy, sizeof(Mod_Sanction) * new_num);

    if (new_list == nullptr) {
        free(sanctions_copy);
        return -1;
    }

    if (creds) {
        if (sanctions_creds_validate(moderation, new_list, creds, new_num, shared_state_version) == -1) {
            free(new_list);
            return -1;
        }

        memcpy(&moderation->sanctions_creds, creds, sizeof(Mod_Sanction_Creds));
    }

    sanctions_list_cleanup(moderation);
    moderation->sanctions = new_list;
    moderation->num_sanctions = new_num;

    return 0;
}

int sanctions_list_remove_observer(Moderation *moderation, const uint8_t *public_key,
                                   Mod_Sanction_Creds *creds,
                                   uint32_t shared_state_version)
{
    for (uint16_t i = 0; i < moderation->num_sanctions; ++i) {
        const Mod_Sanction *curr_sanction = &moderation->sanctions[i];

        if (curr_sanction->type != SA_OBSERVER) {
            continue;
        }

        if (memcmp(public_key, curr_sanction->info.target_pk, ENC_PUBLIC_KEY_SIZE) == 0) {
            if (sanctions_list_remove_index(moderation, i, creds, shared_state_version) == -1) {
                return -1;
            }

            if (creds == nullptr) {
                return sanctions_list_make_creds(moderation);
            }

            return 0;
        }
    }

    return -1;
}

bool sanctions_list_is_observer(const Moderation *moderation, const uint8_t *public_key)
{
    for (uint16_t i = 0; i < moderation->num_sanctions; ++i) {
        const Mod_Sanction *curr_sanction = &moderation->sanctions[i];

        if (curr_sanction->type != SA_OBSERVER) {
            continue;
        }

        if (memcmp(curr_sanction->info.target_pk, public_key, ENC_PUBLIC_KEY_SIZE) == 0) {
            return true;
        }
    }

    return false;
}

bool sanctions_list_entry_exists(const Moderation *moderation, Mod_Sanction *sanction)
{
    if (sanction->type == SA_OBSERVER) {
        return sanctions_list_is_observer(moderation, sanction->info.target_pk);
    }

    return false;
}

static int sanctions_list_sign_entry(const Moderation *moderation, Mod_Sanction *sanction);

int sanctions_list_add_entry(Moderation *moderation, Mod_Sanction *sanction, Mod_Sanction_Creds *creds,
                             uint32_t shared_state_version)
{
    if (moderation->num_sanctions >= MOD_MAX_NUM_SANCTIONS) {
        LOGGER_WARNING(moderation->logger, "num_sanctions %d exceeds maximum", moderation->num_sanctions);
        return -1;
    }

    if (sanctions_list_validate_entry(moderation, sanction) < 0) {
        LOGGER_ERROR(moderation->logger, "Failed to validate sanction");
        return -1;
    }

    if (sanctions_list_entry_exists(moderation, sanction)) {
        LOGGER_WARNING(moderation->logger, "Attempted to add duplicate sanction");
        return -1;
    }

    /* Operate on a copy of the list in case something goes wrong. */
    const size_t old_size = sizeof(Mod_Sanction) * moderation->num_sanctions;
    Mod_Sanction *sanctions_copy = (Mod_Sanction *)malloc(old_size);

    if (sanctions_copy == nullptr) {
        return -1;
    }

    if (old_size > 0) {
        memcpy(sanctions_copy, moderation->sanctions, old_size);
    }

    const uint16_t index = moderation->num_sanctions;
    Mod_Sanction *new_list = (Mod_Sanction *)realloc(sanctions_copy, sizeof(Mod_Sanction) * (index + 1));

    if (new_list == nullptr) {
        free(sanctions_copy);
        return -1;
    }

    memcpy(&new_list[index], sanction, sizeof(Mod_Sanction));

    if (creds) {
        if (sanctions_creds_validate(moderation, new_list, creds, index + 1, shared_state_version) == -1) {
            LOGGER_WARNING(moderation->logger, "Failed to validate credentials");
            free(new_list);
            return -1;
        }

        memcpy(&moderation->sanctions_creds, creds, sizeof(Mod_Sanction_Creds));
    }

    sanctions_list_cleanup(moderation);

    moderation->sanctions = new_list;
    moderation->num_sanctions = index + 1;

    return 0;
}

/* Signs packed sanction data.
 * This function must be called by the owner of the entry's public_sig_key.
 *
 * Returns 0 on success.
 * Returns -1 on failure.
 */
static int sanctions_list_sign_entry(const Moderation *moderation, Mod_Sanction *sanction)
{
    uint8_t packed_data[sizeof(Mod_Sanction)];
    const int packed_len = sanctions_list_pack(packed_data, sizeof(packed_data), sanction, nullptr, 1);

    if (packed_len <= (int) SIGNATURE_SIZE) {
        return -1;
    }

    return crypto_sign_detached(sanction->signature, nullptr, packed_data, packed_len - SIGNATURE_SIZE,
                                moderation->self_secret_sig_key);
}

int sanctions_list_make_entry(Moderation *moderation, const uint8_t *public_key, Mod_Sanction *sanction,
                              uint8_t type)
{
    *sanction = (Mod_Sanction) {
        0
    };

    if (type == SA_OBSERVER) {
        memcpy(sanction->info.target_pk, public_key, ENC_PUBLIC_KEY_SIZE);
    } else {
        LOGGER_ERROR(moderation->logger, "Tried to create sanction with invalid type: %u", type);
        return -1;
    }

    memcpy(sanction->public_sig_key, moderation->self_public_sig_key, SIG_PUBLIC_KEY_SIZE);

    sanction->time_set = (uint64_t) time(nullptr);
    sanction->type = type;

    if (sanctions_list_sign_entry(moderation, sanction) == -1) {
        LOGGER_ERROR(moderation->logger, "Failed to sign sanction");
        return -1;
    }

    if (sanctions_list_add_entry(moderation, sanction, nullptr, 0) == -1) {
        return -1;
    }

    if (sanctions_list_make_creds(moderation) == -1) {
        LOGGER_ERROR(moderation->logger, "Failed to make credentials for new sanction");
        return -1;
    }

    return 0;
}

uint16_t sanctions_list_replace_sig(Moderation *moderation, const uint8_t *public_sig_key)
{
    uint16_t count = 0;

    for (uint16_t i = 0; i < moderation->num_sanctions; ++i) {
        if (memcmp(moderation->sanctions[i].public_sig_key, public_sig_key, SIG_PUBLIC_KEY_SIZE) != 0) {
            continue;
        }

        memcpy(moderation->sanctions[i].public_sig_key, moderation->self_public_sig_key, SIG_PUBLIC_KEY_SIZE);

        if (sanctions_list_sign_entry(moderation, &moderation->sanctions[i]) != -1) {
            ++count;
        }
    }

    if (count) {
        if (sanctions_list_make_creds(moderation) == -1) {
            return 0;
        }
    }

    return count;
}

void sanctions_list_cleanup(Moderation *moderation)
{
    if (moderation->sanctions) {
        free(moderation->sanctions);
    }

    moderation->sanctions = nullptr;
    moderation->num_sanctions = 0;
}

#endif /* VANILLA_NACL */

