/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2020 The TokTok team.
 * Copyright © 2015 Tox project.
 */

/*
 * An implementation of massive text only group chats.
 */

#include "group_moderation.h"

#include <string.h>

#include "DHT.h"
#include "group_connection.h"
#include "mono_time.h"
#include "network.h"
#include "util.h"

#ifndef VANILLA_NACL
#include <sodium.h>
#endif // VANILLA_NACL

#ifndef VANILLA_NACL

#define TIME_STAMP_SIZE sizeof(uint64_t)

int mod_list_unpack(GC_Moderation *moderation, const uint8_t *data, uint32_t length, uint16_t num_mods)
{
    if (length != num_mods * GC_MOD_LIST_ENTRY_SIZE) {
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
        tmp_list[i] = (uint8_t *)malloc(sizeof(uint8_t) * GC_MOD_LIST_ENTRY_SIZE);

        if (tmp_list[i] == nullptr) {
            free_uint8_t_pointer_array(tmp_list, i);
            return -1;
        }

        memcpy(tmp_list[i], &data[i * GC_MOD_LIST_ENTRY_SIZE], GC_MOD_LIST_ENTRY_SIZE);
        unpacked_len += GC_MOD_LIST_ENTRY_SIZE;
    }

    moderation->mod_list = tmp_list;
    moderation->num_mods = num_mods;

    return unpacked_len;
}

void mod_list_pack(const GC_Moderation *moderation, uint8_t *data)
{
    for (uint16_t i = 0; i < moderation->num_mods && i < MAX_GC_MODERATORS; ++i) {
        memcpy(&data[i * GC_MOD_LIST_ENTRY_SIZE], moderation->mod_list[i], GC_MOD_LIST_ENTRY_SIZE);
    }
}

void mod_list_get_data_hash(uint8_t *hash, const uint8_t *packed_mod_list, size_t length)
{
    crypto_hash_sha256(hash, packed_mod_list, length);
}

int mod_list_make_hash(GC_Moderation *moderation, uint8_t *hash)
{
    if (moderation->num_mods == 0) {
        memset(hash, 0, GC_MODERATION_HASH_SIZE);
        return 0;
    }

    const size_t data_buf_size = moderation->num_mods * GC_MOD_LIST_ENTRY_SIZE;
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
static int mod_list_index_of_sig_pk(const GC_Moderation *moderation, const uint8_t *public_sig_key)
{
    for (uint16_t i = 0; i < moderation->num_mods; ++i) {
        if (memcmp(moderation->mod_list[i], public_sig_key, SIG_PUBLIC_KEY_SIZE) == 0) {
            return i;
        }
    }

    return -1;
}

bool mod_list_verify_sig_pk(const GC_Moderation *moderation, const uint8_t *sig_pk)
{
    if (memcmp(get_sig_pk(moderation->founder_public_key), sig_pk, SIG_PUBLIC_KEY_SIZE) == 0) {
        return true;
    }

    for (uint16_t i = 0; i < moderation->num_mods; ++i) {
        if (memcmp(moderation->mod_list[i], sig_pk, SIG_PUBLIC_KEY_SIZE) == 0) {
            return true;
        }
    }

    return false;
}

int mod_list_remove_index(GC_Moderation *moderation, size_t index)
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
               GC_MOD_LIST_ENTRY_SIZE);
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

int mod_list_remove_entry(GC_Moderation *moderation, const uint8_t *public_sig_key)
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

int mod_list_add_entry(GC_Moderation *moderation, const uint8_t *mod_data)
{
    if (moderation->num_mods >= MAX_GC_MODERATORS) {
        return -1;
    }

    uint8_t **tmp_list = (uint8_t **)realloc(moderation->mod_list, sizeof(uint8_t *) * (moderation->num_mods + 1));

    if (tmp_list == nullptr) {
        return -1;
    }

    moderation->mod_list = tmp_list;

    tmp_list[moderation->num_mods] = (uint8_t *)malloc(sizeof(uint8_t) * GC_MOD_LIST_ENTRY_SIZE);

    if (tmp_list[moderation->num_mods] == nullptr) {
        return -1;
    }

    memcpy(tmp_list[moderation->num_mods], mod_data, GC_MOD_LIST_ENTRY_SIZE);
    ++moderation->num_mods;

    return 0;
}

void mod_list_cleanup(GC_Moderation *moderation)
{
    free_uint8_t_pointer_array(moderation->mod_list, moderation->num_mods);
    moderation->num_mods = 0;
    moderation->mod_list = nullptr;
}

uint16_t sanctions_creds_pack(const struct GC_Sanction_Creds *creds, uint8_t *data, uint16_t length)
{
    if (GC_SANCTIONS_CREDENTIALS_SIZE > length) {
        return 0;
    }

    uint16_t packed_len = 0;

    net_pack_u32(data + packed_len, creds->version);
    packed_len += sizeof(uint32_t);
    memcpy(data + packed_len, creds->hash, GC_SANCTION_HASH_SIZE);
    packed_len += GC_SANCTION_HASH_SIZE;
    net_pack_u16(data + packed_len, creds->checksum);
    packed_len += sizeof(uint16_t);
    memcpy(data + packed_len, creds->sig_pk, SIG_PUBLIC_KEY_SIZE);
    packed_len += SIG_PUBLIC_KEY_SIZE;
    memcpy(data + packed_len, creds->sig, SIGNATURE_SIZE);
    packed_len += SIGNATURE_SIZE;

    return packed_len;
}

int sanctions_list_pack(uint8_t *data, uint16_t length, struct GC_Sanction *sanctions,
                        const struct GC_Sanction_Creds *creds, uint16_t num_sanctions)
{
    uint32_t packed_len = 0;

    for (uint16_t i = 0; i < num_sanctions && i < MAX_GC_SANCTIONS; ++i) {
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

    if (cred_len != GC_SANCTIONS_CREDENTIALS_SIZE) {
        return -1;
    }

    return packed_len + cred_len;
}

uint16_t sanctions_creds_unpack(struct GC_Sanction_Creds *creds, const uint8_t *data, uint16_t length)
{
    if (GC_SANCTIONS_CREDENTIALS_SIZE > length) {
        return 0;
    }

    uint16_t len_processed = 0;

    net_unpack_u32(data + len_processed, &creds->version);
    len_processed += sizeof(uint32_t);
    memcpy(creds->hash, data + len_processed, GC_SANCTION_HASH_SIZE);
    len_processed += GC_SANCTION_HASH_SIZE;
    net_unpack_u16(data + len_processed, &creds->checksum);
    len_processed += sizeof(uint16_t);
    memcpy(creds->sig_pk, data + len_processed, SIG_PUBLIC_KEY_SIZE);
    len_processed += SIG_PUBLIC_KEY_SIZE;
    memcpy(creds->sig, data + len_processed, SIGNATURE_SIZE);
    len_processed += SIGNATURE_SIZE;

    return len_processed;
}

int sanctions_list_unpack(struct GC_Sanction *sanctions, struct GC_Sanction_Creds *creds, uint16_t max_sanctions,
                          const uint8_t *data, uint16_t length, uint16_t *processed_data_len)
{
    uint16_t num = 0;
    uint16_t len_processed = 0;

    while (num < max_sanctions && num < MAX_GC_SANCTIONS && len_processed < length) {
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

    if (creds_len != GC_SANCTIONS_CREDENTIALS_SIZE) {
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
 * hash must have room for at least GC_SANCTION_HASH_SIZE bytes.
 *
 * If num_sanctions is 0 the hash is zeroed.
 *
 * Return 0 on success.
 * Return -1 on failure.
 */
static int sanctions_list_make_hash(struct GC_Sanction *sanctions, uint32_t new_version, uint16_t num_sanctions,
                                    uint8_t *hash)
{
    if (num_sanctions == 0 || sanctions == nullptr) {
        memset(hash, 0, GC_SANCTION_HASH_SIZE);
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
static int sanctions_list_validate_entry(const GC_Chat *chat, struct GC_Sanction *sanction)
{
    if (!mod_list_verify_sig_pk(&chat->moderation, sanction->public_sig_key)) {
        return -1;
    }

    if (sanction->type >= SA_INVALID) {
        return -1;
    }

    if (sanction->time_set == 0) {
        return -1;
    }

    uint8_t packed_data[sizeof(struct GC_Sanction)];
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

static uint16_t sanctions_creds_get_checksum(const struct GC_Sanction_Creds *creds)
{
    uint16_t sum = 0;

    for (size_t i = 0; i < GC_SANCTION_HASH_SIZE; ++i) {
        sum += creds->hash[i];
    }

    return sum;
}

static void sanctions_creds_set_checksum(struct GC_Sanction_Creds *creds)
{
    creds->checksum = sanctions_creds_get_checksum(creds);
}

int sanctions_list_make_creds(GC_Chat *chat)
{
    struct GC_Sanction_Creds old_creds;
    memcpy(&old_creds, &chat->moderation.sanctions_creds, sizeof(struct GC_Sanction_Creds));

    ++chat->moderation.sanctions_creds.version;

    memcpy(chat->moderation.sanctions_creds.sig_pk, get_sig_pk(chat->self_public_key), SIG_PUBLIC_KEY_SIZE);

    uint8_t hash[GC_SANCTION_HASH_SIZE];

    if (sanctions_list_make_hash(chat->moderation.sanctions, chat->moderation.sanctions_creds.version,
                                 chat->moderation.num_sanctions, hash) == -1) {
        memcpy(&chat->moderation.sanctions_creds, &old_creds, sizeof(struct GC_Sanction_Creds));
        return -1;
    }

    memcpy(chat->moderation.sanctions_creds.hash, hash, GC_SANCTION_HASH_SIZE);

    sanctions_creds_set_checksum(&chat->moderation.sanctions_creds);

    if (crypto_sign_detached(chat->moderation.sanctions_creds.sig, nullptr, chat->moderation.sanctions_creds.hash,
                             GC_SANCTION_HASH_SIZE, get_sig_sk(chat->self_secret_key)) == -1) {
        memcpy(&chat->moderation.sanctions_creds, &old_creds, sizeof(struct GC_Sanction_Creds));
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
static int sanctions_creds_validate(const GC_Chat *chat, struct GC_Sanction *sanctions, struct GC_Sanction_Creds *creds,
                                    uint16_t num_sanctions)
{
    if (!mod_list_verify_sig_pk(&chat->moderation, creds->sig_pk)) {
        LOGGER_WARNING(chat->logger, "Invalid credentials signature pk");
        return -1;
    }

    uint8_t hash[GC_SANCTION_HASH_SIZE];

    if (sanctions_list_make_hash(sanctions, creds->version, num_sanctions, hash) == -1) {
        return -1;
    }

    if (memcmp(hash, creds->hash, GC_SANCTION_HASH_SIZE) != 0) {
        LOGGER_WARNING(chat->logger, "Invalid credentials hash");
        return -1;
    }

    if (creds->checksum != sanctions_creds_get_checksum(creds)) {
        LOGGER_WARNING(chat->logger, "Invalid credentials checksum");
        return -1;
    }

    if (chat->shared_state.version > 0) {
        if ((creds->version < chat->moderation.sanctions_creds.version)
                && !(creds->version == 0 && chat->moderation.sanctions_creds.version == UINT32_MAX)) {
            LOGGER_WARNING(chat->logger, "Invalid version");
            return -1;
        }
    }

    if (crypto_sign_verify_detached(creds->sig, hash, GC_SANCTION_HASH_SIZE, creds->sig_pk) == -1) {
        LOGGER_WARNING(chat->logger, "Invalid signature");
        return -1;
    }

    return 0;
}

int sanctions_list_check_integrity(const GC_Chat *chat, struct GC_Sanction_Creds *creds,
                                   struct GC_Sanction *sanctions, uint16_t num_sanctions)
{
    for (uint16_t i = 0; i < num_sanctions; ++i) {
        if (sanctions_list_validate_entry(chat, &sanctions[i]) != 0) {
            LOGGER_WARNING(chat->logger, "Invalid entry");
            return -1;
        }
    }

    if (sanctions_creds_validate(chat, sanctions, creds, num_sanctions) == -1) {
        return -1;
    }

    return 0;
}

/* Removes index-th sanction list entry. New credentials will be validated if creds is non-null.
 *
 * Returns 0 on success.
 * Returns -1 on failure.
 */
static int sanctions_list_remove_index(GC_Chat *chat, uint16_t index, struct GC_Sanction_Creds *creds)
{
    if (index >= chat->moderation.num_sanctions || chat->moderation.num_sanctions == 0) {
        return -1;
    }

    const uint16_t new_num = chat->moderation.num_sanctions - 1;

    if (new_num == 0) {
        if (creds) {
            if (sanctions_creds_validate(chat, nullptr, creds, 0) == -1) {
                return -1;
            }

            memcpy(&chat->moderation.sanctions_creds, creds, sizeof(struct GC_Sanction_Creds));
        }

        sanctions_list_cleanup(chat);

        return 0;
    }

    /* Operate on a copy of the list in case something goes wrong. */
    const size_t old_size = sizeof(struct GC_Sanction) * chat->moderation.num_sanctions;
    struct GC_Sanction *sanctions_copy = (struct GC_Sanction *)malloc(old_size);

    if (sanctions_copy == nullptr) {
        return -1;
    }

    memcpy(sanctions_copy, chat->moderation.sanctions, old_size);

    if (index != new_num) {
        memcpy(&sanctions_copy[index], &sanctions_copy[new_num], sizeof(struct GC_Sanction));
    }

    struct GC_Sanction *new_list = (struct GC_Sanction *)realloc(sanctions_copy, sizeof(struct GC_Sanction) * new_num);

    if (new_list == nullptr) {
        free(sanctions_copy);
        return -1;
    }

    if (creds) {
        if (sanctions_creds_validate(chat, new_list, creds, new_num) == -1) {
            free(new_list);
            return -1;
        }

        memcpy(&chat->moderation.sanctions_creds, creds, sizeof(struct GC_Sanction_Creds));
    }

    sanctions_list_cleanup(chat);
    chat->moderation.sanctions = new_list;
    chat->moderation.num_sanctions = new_num;

    return 0;
}

int sanctions_list_remove_observer(GC_Chat *chat, const uint8_t *public_key, struct GC_Sanction_Creds *creds)
{
    for (uint16_t i = 0; i < chat->moderation.num_sanctions; ++i) {
        const struct GC_Sanction *curr_sanction = &chat->moderation.sanctions[i];

        if (curr_sanction->type != SA_OBSERVER) {
            continue;
        }

        if (memcmp(public_key, curr_sanction->info.target_pk, ENC_PUBLIC_KEY_SIZE) == 0) {
            if (sanctions_list_remove_index(chat, i, creds) == -1) {
                return -1;
            }

            if (creds == nullptr) {
                return sanctions_list_make_creds(chat);
            }

            return 0;
        }
    }

    return -1;
}

bool sanctions_list_is_observer(const GC_Chat *chat, const uint8_t *public_key)
{
    for (uint16_t i = 0; i < chat->moderation.num_sanctions; ++i) {
        const struct GC_Sanction *curr_sanction = &chat->moderation.sanctions[i];

        if (curr_sanction->type != SA_OBSERVER) {
            continue;
        }

        if (memcmp(curr_sanction->info.target_pk, public_key, ENC_PUBLIC_KEY_SIZE) == 0) {
            return true;
        }
    }

    return false;
}

bool sanctions_list_is_observer_sig(const GC_Chat *chat, const uint8_t *public_sig_key)
{
    uint8_t public_key[ENC_PUBLIC_KEY_SIZE];

    if (gc_get_enc_pk_from_sig_pk(chat, public_key, public_sig_key) != 0) {
        return false;
    }

    return sanctions_list_is_observer(chat, public_key);
}

bool sanctions_list_entry_exists(const GC_Chat *chat, struct GC_Sanction *sanction)
{
    if (sanction->type == SA_OBSERVER) {
        return sanctions_list_is_observer(chat, sanction->info.target_pk);
    }

    return false;
}

static int sanctions_list_sign_entry(const GC_Chat *chat, struct GC_Sanction *sanction);

int sanctions_list_add_entry(GC_Chat *chat, struct GC_Sanction *sanction, struct GC_Sanction_Creds *creds)
{
    if (chat->moderation.num_sanctions >= MAX_GC_SANCTIONS) {
        LOGGER_WARNING(chat->logger, "num_sanctions %d exceeds maximum", chat->moderation.num_sanctions);
        return -1;
    }

    if (sanctions_list_validate_entry(chat, sanction) < 0) {
        LOGGER_ERROR(chat->logger, "Failed to validate sanction");
        return -1;
    }

    if (sanctions_list_entry_exists(chat, sanction)) {
        LOGGER_WARNING(chat->logger, "Attempted to add duplicate sanction");
        return -1;
    }

    /* Operate on a copy of the list in case something goes wrong. */
    const size_t old_size = sizeof(struct GC_Sanction) * chat->moderation.num_sanctions;
    struct GC_Sanction *sanctions_copy = (struct GC_Sanction *)malloc(old_size);

    if (sanctions_copy == nullptr) {
        return -1;
    }

    if (old_size > 0) {
        memcpy(sanctions_copy, chat->moderation.sanctions, old_size);
    }

    const uint16_t index = chat->moderation.num_sanctions;
    struct GC_Sanction *new_list = (struct GC_Sanction *)realloc(sanctions_copy, sizeof(struct GC_Sanction) * (index + 1));

    if (new_list == nullptr) {
        free(sanctions_copy);
        return -1;
    }

    memcpy(&new_list[index], sanction, sizeof(struct GC_Sanction));

    if (creds) {
        if (sanctions_creds_validate(chat, new_list, creds, index + 1) == -1) {
            LOGGER_WARNING(chat->logger, "Failed to validate credentials");
            free(new_list);
            return -1;
        }

        memcpy(&chat->moderation.sanctions_creds, creds, sizeof(struct GC_Sanction_Creds));
    }

    sanctions_list_cleanup(chat);
    chat->moderation.sanctions = new_list;
    chat->moderation.num_sanctions = index + 1;

    return 0;
}

/* Signs packed sanction data.
 * This function must be called by the owner of the entry's public_sig_key.
 *
 * Returns 0 on success.
 * Returns -1 on failure.
 */
static int sanctions_list_sign_entry(const GC_Chat *chat, struct GC_Sanction *sanction)
{
    uint8_t packed_data[sizeof(struct GC_Sanction)];
    const int packed_len = sanctions_list_pack(packed_data, sizeof(packed_data), sanction, nullptr, 1);

    if (packed_len <= (int) SIGNATURE_SIZE) {
        return -1;
    }

    return crypto_sign_detached(sanction->signature, nullptr, packed_data, packed_len - SIGNATURE_SIZE,
                                get_sig_sk(chat->self_secret_key));
}

int sanctions_list_make_entry(GC_Chat *chat, uint32_t peer_number, struct GC_Sanction *sanction, uint8_t type)
{
    GC_Connection *gconn = gcc_get_connection(chat, peer_number);

    if (gconn == nullptr) {
        return -1;
    }

    *sanction = (struct GC_Sanction) {
        0
    };

    if (type == SA_OBSERVER) {
        memcpy(sanction->info.target_pk, gconn->addr.public_key, ENC_PUBLIC_KEY_SIZE);
    } else {
        LOGGER_ERROR(chat->logger, "Tried to create sanction with invalid type: %u", type);
        return -1;
    }

    memcpy(sanction->public_sig_key, get_sig_pk(chat->self_public_key), SIG_PUBLIC_KEY_SIZE);
    sanction->time_set = (uint64_t) time(nullptr);
    sanction->type = type;

    if (sanctions_list_sign_entry(chat, sanction) == -1) {
        LOGGER_ERROR(chat->logger, "Failed to sign sanction");
        return -1;
    }

    if (sanctions_list_add_entry(chat, sanction, nullptr) == -1) {
        return -1;
    }

    if (sanctions_list_make_creds(chat) == -1) {
        LOGGER_ERROR(chat->logger, "Failed to make credentials for new sanction");
        return -1;
    }

    return 0;
}

uint16_t sanctions_list_replace_sig(GC_Chat *chat, const uint8_t *public_sig_key)
{
    uint16_t count = 0;

    for (uint16_t i = 0; i < chat->moderation.num_sanctions; ++i) {
        if (memcmp(chat->moderation.sanctions[i].public_sig_key, public_sig_key, SIG_PUBLIC_KEY_SIZE) != 0) {
            continue;
        }

        memcpy(chat->moderation.sanctions[i].public_sig_key, get_sig_pk(chat->self_public_key), SIG_PUBLIC_KEY_SIZE);

        if (sanctions_list_sign_entry(chat, &chat->moderation.sanctions[i]) != -1) {
            ++count;
        }
    }

    if (count) {
        if (sanctions_list_make_creds(chat) == -1) {
            return 0;
        }
    }

    return count;
}

void sanctions_list_cleanup(GC_Chat *chat)
{
    if (chat->moderation.sanctions) {
        free(chat->moderation.sanctions);
    }

    chat->moderation.sanctions = nullptr;
    chat->moderation.num_sanctions = 0;
}

#endif /* VANILLA_NACL */

