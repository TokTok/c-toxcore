/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2020 The TokTok team.
 * Copyright © 2015 Tox project.
 */

/**
 * Packer and unpacker functions for saving and loading groups.
 */

#include "group_pack.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "DHT.h"
#include "bin_pack.h"
#include "bin_unpack.h"
#include "ccompat.h"
#include "group_common.h"
#include "group_moderation.h"
#include "logger.h"
#include "util.h"

/** @{
 * Generated code.
 */

typedef struct GC_Shared_State_Values {
    bool manually_disconnected;
    uint16_t group_name_len;
    uint8_t privacy_state;
    uint16_t maxpeers;
    uint16_t password_length;
    uint32_t version;
    uint32_t topic_lock;
    uint8_t voice_state;
} GC_Shared_State_Values;

non_null()
static bool gc_shared_state_values_pack(const GC_Shared_State_Values *vals, Bin_Pack *bp)
{
    return bin_pack_array(bp, 8) //
        && bin_pack_bool(bp, vals->manually_disconnected)  // 1
        && bin_pack_u16(bp, vals->group_name_len)  // 2
        && bin_pack_u08(bp, vals->privacy_state)  // 3
        && bin_pack_u16(bp, vals->maxpeers)  // 4
        && bin_pack_u16(bp, vals->password_length)  // 5
        && bin_pack_u32(bp, vals->version)  // 6
        && bin_pack_u32(bp, vals->topic_lock)  // 7
        && bin_pack_u08(bp, vals->voice_state);  // 8
}

typedef struct GC_Shared_State_Bin {
    uint8_t sig[SIGNATURE_SIZE];
    uint8_t founder_public_key[EXT_PUBLIC_KEY_SIZE];
    uint8_t group_name[MAX_GC_GROUP_NAME_SIZE];
    uint32_t group_name_size;
    uint8_t password[MAX_GC_PASSWORD_SIZE];
    uint32_t password_size;
    uint8_t mod_list_hash[MOD_MODERATION_HASH_SIZE];
} GC_Shared_State_Bin;

non_null()
static bool gc_shared_state_bin_pack(const GC_Shared_State_Bin *vals, Bin_Pack *bp)
{
    return bin_pack_array(bp, 5)  //
        && bin_pack_bin(bp, vals->sig, SIGNATURE_SIZE)  // 1
        && bin_pack_bin(bp, vals->founder_public_key, EXT_PUBLIC_KEY_SIZE)  // 2
        && bin_pack_bin(bp, vals->group_name, vals->group_name_size)  // 3
        && bin_pack_bin(bp, vals->password, vals->password_size)  // 4
        && bin_pack_bin(bp, vals->mod_list_hash, MOD_MODERATION_HASH_SIZE);  // 5
}

typedef struct GC_Topic_Info {
    uint32_t version;
    uint16_t length;
    uint16_t checksum;
    uint8_t topic[MAX_GC_TOPIC_SIZE];
    uint32_t topic_length;
    uint8_t public_key_sig[SIG_PUBLIC_KEY_SIZE];
    uint8_t sig[SIGNATURE_SIZE];
} GC_Topic_Info;

non_null()
static bool gc_topic_info_pack(const GC_Topic_Info *info, Bin_Pack *bp)
{
    return bin_pack_array(bp, 6)  //
        && bin_pack_u32(bp, info->version)  //
        && bin_pack_u16(bp, info->length)  //
        && bin_pack_u16(bp, info->checksum)  //
        && bin_pack_bin(bp, info->topic, info->topic_length)  //
        && bin_pack_bin(bp, info->public_key_sig, SIG_PUBLIC_KEY_SIZE)  //
        && bin_pack_bin(bp, info->sig, SIGNATURE_SIZE);
}

typedef struct GC_Mod_List {
    uint16_t num_mods;
    uint8_t *packed_mod_list;
    uint32_t packed_mod_list_size;
} GC_Mod_List;

non_null()
static bool gc_mod_list_pack(const GC_Mod_List *mods, Bin_Pack *bp)
{
    return bin_pack_array(bp, 2)  //
        && bin_pack_u16(bp, mods->num_mods)  //
        && bin_pack_bin(bp, mods->packed_mod_list, mods->packed_mod_list_size);
}

typedef struct GC_Keys {
    uint8_t chat_public_key[EXT_PUBLIC_KEY_SIZE];
    uint8_t chat_secret_key[EXT_SECRET_KEY_SIZE];
    uint8_t self_public_key[EXT_PUBLIC_KEY_SIZE];
    uint8_t self_secret_key[EXT_SECRET_KEY_SIZE];
} GC_Keys;

non_null()
static bool gc_keys_pack(const GC_Keys *keys, Bin_Pack *bp)
{
    return bin_pack_array(bp, 4)  //
        && bin_pack_bin(bp, keys->chat_public_key, EXT_PUBLIC_KEY_SIZE)  //
        && bin_pack_bin(bp, keys->chat_secret_key, EXT_SECRET_KEY_SIZE)  //
        && bin_pack_bin(bp, keys->self_public_key, EXT_PUBLIC_KEY_SIZE)  //
        && bin_pack_bin(bp, keys->self_secret_key, EXT_SECRET_KEY_SIZE);
}

typedef struct GC_Self_Info {
    uint16_t nick_length;
    uint8_t role;
    uint8_t status;
    uint8_t nick[MAX_GC_NICK_SIZE];
    uint32_t nick_size;
} GC_Self_Info;

non_null()
static bool gc_self_info_pack(const GC_Self_Info *info, Bin_Pack *bp)
{
    return bin_pack_array(bp, 4)  //
        && bin_pack_u16(bp, info->nick_length)  //
        && bin_pack_u08(bp, info->role)  //
        && bin_pack_u08(bp, info->status)  //
        && bin_pack_bin(bp, info->nick, info->nick_size);
}

typedef struct GC_Saved_Peers {
    uint16_t packed_size;
    uint8_t *packed_peers;
    uint32_t packed_peers_size;
} GC_Saved_Peers;

non_null()
static bool gc_saved_peers_pack(const GC_Saved_Peers *peers, Bin_Pack *bp)
{
    return bin_pack_array(bp, 2)  //
        && bin_pack_u16(bp, peers->packed_size)  //
        && bin_pack_bin(bp, peers->packed_peers, peers->packed_peers_size);
}

//!TOKSTYLE-
// TODO(iphydf): Use this generated code.
#if 0
typedef struct GC_Shared_State {
    GC_Shared_State_Values vals;
    GC_Shared_State_Bin bin;
    GC_Topic_Info topic;
    GC_Mod_List mods;
    GC_Keys keys;
    GC_Self_Info self;
    GC_Saved_Peers peers;
} GC_Shared_State;

non_null()
static bool gc_shared_state_pack(const GC_Shared_State *state, Bin_Pack *bp)
{
    return bin_pack_array(bp, 7)  //
        && gc_shared_state_values_pack(&state->vals, bp)  //
        && gc_shared_state_bin_pack(&state->bin, bp)  //
        && gc_topic_info_pack(&state->topic, bp)  //
        && gc_mod_list_pack(&state->mods, bp)  //
        && gc_keys_pack(&state->keys, bp)  //
        && gc_self_info_pack(&state->self, bp)  //
        && gc_saved_peers_pack(&state->peers, bp);
}
#endif
//!TOKSTYLE+

/** @} */

bool group_privacy_state_from_int(uint8_t value, Group_Privacy_State *out)
{
    switch (value) {
        case GI_PUBLIC: {
            *out = GI_PUBLIC;
            return true;
        }

        case GI_PRIVATE: {
            *out = GI_PRIVATE;
            return true;
        }

        default: {
            *out = GI_PUBLIC;
            return false;
        }
    }
}

bool group_voice_state_from_int(uint8_t value, Group_Voice_State *out)
{
    switch (value) {
        case GV_ALL: {
            *out = GV_ALL;
            return true;
        }

        case GV_MODS: {
            *out = GV_MODS;
            return true;
        }

        case GV_FOUNDER: {
            *out = GV_FOUNDER;
            return true;
        }

        default: {
            *out = GV_ALL;
            return false;
        }
    }
}

non_null()
static bool load_unpack_state_values(GC_Chat *chat, Bin_Unpack *bu)
{
    if (!bin_unpack_array_fixed(bu, 8, nullptr)) {
        LOGGER_ERROR(chat->log, "Group state values array malformed");
        return false;
    }

    bool manually_disconnected = false;
    uint8_t privacy_state = 0;
    uint8_t voice_state = 0;

    if (!(bin_unpack_bool(bu, &manually_disconnected)
            && bin_unpack_u16(bu, &chat->shared_state.group_name_len)
            && bin_unpack_u08(bu, &privacy_state)
            && bin_unpack_u16(bu, &chat->shared_state.maxpeers)
            && bin_unpack_u16(bu, &chat->shared_state.password_length)
            && bin_unpack_u32(bu, &chat->shared_state.version)
            && bin_unpack_u32(bu, &chat->shared_state.topic_lock)
            && bin_unpack_u08(bu, &voice_state))) {
        LOGGER_ERROR(chat->log, "Failed to unpack state value");
        return false;
    }

    chat->connection_state = manually_disconnected ? CS_DISCONNECTED : CS_CONNECTING;
    group_privacy_state_from_int(privacy_state, &chat->shared_state.privacy_state);
    group_voice_state_from_int(voice_state, &chat->shared_state.voice_state);

    // we always load saved groups as private in case the group became private while we were offline.
    // this will have no detrimental effect if the group is public, as the correct privacy
    // state will be set via sync.
    chat->join_type = HJ_PRIVATE;

    return true;
}

non_null()
static bool load_unpack_state_bin(GC_Chat *chat, Bin_Unpack *bu)
{
    if (!bin_unpack_array_fixed(bu, 5, nullptr)) {
        LOGGER_ERROR(chat->log, "Group state binary array malformed");
        return false;
    }

    if (!bin_unpack_bin_fixed(bu, chat->shared_state_sig, SIGNATURE_SIZE)) {
        LOGGER_ERROR(chat->log, "Failed to unpack shared state signature");
        return false;
    }

    if (!bin_unpack_bin_fixed(bu, chat->shared_state.founder_public_key, EXT_PUBLIC_KEY_SIZE)) {
        LOGGER_ERROR(chat->log, "Failed to unpack founder public key");
        return false;
    }

    if (!(bin_unpack_bin_max(bu, chat->shared_state.group_name, &chat->shared_state.group_name_len, sizeof(chat->shared_state.group_name))
            && bin_unpack_bin_max(bu, chat->shared_state.password, &chat->shared_state.password_length, sizeof(chat->shared_state.password))
            && bin_unpack_bin_fixed(bu, chat->shared_state.mod_list_hash, MOD_MODERATION_HASH_SIZE))) {
        LOGGER_ERROR(chat->log, "Failed to unpack state binary data");
        return false;
    }

    return true;
}

non_null()
static bool load_unpack_topic_info(GC_Chat *chat, Bin_Unpack *bu)
{
    if (!bin_unpack_array_fixed(bu, 6, nullptr)) {
        LOGGER_ERROR(chat->log, "Group topic array malformed");
        return false;
    }

    if (!(bin_unpack_u32(bu, &chat->topic_info.version)
            && bin_unpack_u16(bu, &chat->topic_info.length)
            && bin_unpack_u16(bu, &chat->topic_info.checksum)
            && bin_unpack_bin_max(bu, chat->topic_info.topic, &chat->topic_info.length, sizeof(chat->topic_info.topic))
            && bin_unpack_bin_fixed(bu, chat->topic_info.public_sig_key, SIG_PUBLIC_KEY_SIZE)
            && bin_unpack_bin_fixed(bu, chat->topic_sig, SIGNATURE_SIZE))) {
        LOGGER_ERROR(chat->log, "Failed to unpack topic info");
        return false;
    }

    return true;
}

non_null()
static bool load_unpack_mod_list(GC_Chat *chat, Bin_Unpack *bu)
{
    uint32_t actual_size = 0;
    if (!bin_unpack_array_fixed(bu, 2, &actual_size)) {
        LOGGER_ERROR(chat->log, "Group mod list array malformed: %d != 2", actual_size);
        return false;
    }

    if (!bin_unpack_u16(bu, &chat->moderation.num_mods)) {
        LOGGER_ERROR(chat->log, "Failed to unpack mod list value");
        return false;
    }

    if (chat->moderation.num_mods == 0) {
        bin_unpack_nil(bu);
        return true;
    }

    if (chat->moderation.num_mods > MOD_MAX_NUM_MODERATORS) {
        LOGGER_ERROR(chat->log, "moderation count %u exceeds maximum %u", chat->moderation.num_mods, MOD_MAX_NUM_MODERATORS);
        chat->moderation.num_mods = MOD_MAX_NUM_MODERATORS;
    }

    uint8_t *packed_mod_list = (uint8_t *)malloc(chat->moderation.num_mods * MOD_LIST_ENTRY_SIZE);

    if (packed_mod_list == nullptr) {
        LOGGER_ERROR(chat->log, "Failed to allocate memory for packed mod list");
        return false;
    }

    const size_t packed_size = chat->moderation.num_mods * MOD_LIST_ENTRY_SIZE;

    if (!bin_unpack_bin_fixed(bu, packed_mod_list, packed_size)) {
        LOGGER_ERROR(chat->log, "Failed to unpack mod list binary data");
        free(packed_mod_list);
        return false;
    }

    if (mod_list_unpack(&chat->moderation, packed_mod_list, packed_size, chat->moderation.num_mods) == -1) {
        LOGGER_ERROR(chat->log, "Failed to unpack mod list info");
        free(packed_mod_list);
        return false;
    }

    free(packed_mod_list);

    return true;
}

non_null()
static bool load_unpack_keys(GC_Chat *chat, Bin_Unpack *bu)
{
    if (!bin_unpack_array_fixed(bu, 4, nullptr)) {
        LOGGER_ERROR(chat->log, "Group keys array malformed");
        return false;
    }

    if (!(bin_unpack_bin_fixed(bu, chat->chat_public_key, EXT_PUBLIC_KEY_SIZE)
            && bin_unpack_bin_fixed(bu, chat->chat_secret_key, EXT_SECRET_KEY_SIZE)
            && bin_unpack_bin_fixed(bu, chat->self_public_key, EXT_PUBLIC_KEY_SIZE)
            && bin_unpack_bin_fixed(bu, chat->self_secret_key, EXT_SECRET_KEY_SIZE))) {
        LOGGER_ERROR(chat->log, "Failed to unpack keys");
        return false;
    }

    return true;
}

non_null()
static bool load_unpack_self_info(GC_Chat *chat, Bin_Unpack *bu)
{
    if (!bin_unpack_array_fixed(bu, 4, nullptr)) {
        LOGGER_ERROR(chat->log, "Group self info array malformed");
        return false;
    }

    uint8_t self_nick[MAX_GC_NICK_SIZE];
    uint16_t self_nick_len = 0;
    uint8_t self_role = GR_USER;
    uint8_t self_status = GS_NONE;

    if (!(bin_unpack_u16(bu, &self_nick_len)
            && bin_unpack_u08(bu, &self_role)
            && bin_unpack_u08(bu, &self_status))) {
        LOGGER_ERROR(chat->log, "Failed to unpack self values");
        return false;
    }

    if (self_nick_len > MAX_GC_NICK_SIZE) {
        LOGGER_ERROR(chat->log, "self_nick too big (%u bytes), truncating to %d", self_nick_len, MAX_GC_NICK_SIZE);
        self_nick_len = MAX_GC_NICK_SIZE;
    }

    if (!bin_unpack_bin_fixed(bu, self_nick, self_nick_len)) {
        LOGGER_ERROR(chat->log, "Failed to unpack self nick bytes");
        return false;
    }

    // we have to add ourself before setting self info
    if (peer_add(chat, nullptr, chat->self_public_key) != 0) {
        LOGGER_ERROR(chat->log, "Failed to add self to peer list");
        return false;
    }

    if (chat->numpeers == 0) {
        LOGGER_ERROR(chat->log, "Failed to unpack self: numpeers should be > 0");
        return false;
    }

    GC_Peer *self = &chat->group[0];

    memcpy(self->gconn.addr.public_key, chat->self_public_key, EXT_PUBLIC_KEY_SIZE);
    memcpy(self->nick, self_nick, self_nick_len);
    self->nick_length = self_nick_len;
    self->role = (Group_Role)self_role;
    self->status = (Group_Peer_Status)self_status;
    self->gconn.confirmed = true;

    return true;
}

non_null()
static bool load_unpack_saved_peers(GC_Chat *chat, Bin_Unpack *bu)
{
    if (!bin_unpack_array_fixed(bu, 2, nullptr)) {
        LOGGER_ERROR(chat->log, "Group saved peers array malformed");
        return false;
    }

    // Saved peers
    uint16_t saved_peers_size = 0;

    if (!bin_unpack_u16(bu, &saved_peers_size)) {
        LOGGER_ERROR(chat->log, "Failed to unpack saved peers value");
        return false;
    }

    if (saved_peers_size == 0) {
        bin_unpack_nil(bu);
        return true;
    }

    uint8_t *saved_peers = (uint8_t *)malloc(saved_peers_size * GC_SAVED_PEER_SIZE);

    if (saved_peers == nullptr) {
        LOGGER_ERROR(chat->log, "Failed to allocate memory for saved peer list");
        return false;
    }

    if (!bin_unpack_bin_fixed(bu, saved_peers, saved_peers_size)) {
        LOGGER_ERROR(chat->log, "Failed to unpack saved peers binary data");
        free(saved_peers);
        return false;
    }

    if (unpack_gc_saved_peers(chat, saved_peers, saved_peers_size) == -1) {
        LOGGER_ERROR(chat->log, "Failed to unpack saved peers");  // recoverable error
    }

    free(saved_peers);

    return true;
}

bool gc_load_unpack_group(GC_Chat *chat, Bin_Unpack *bu)
{
    uint32_t actual_size;
    if (!bin_unpack_array_fixed(bu, 7, &actual_size)) {
        LOGGER_ERROR(chat->log, "Group info array malformed: %d != 7", actual_size);
        return false;
    }

    return load_unpack_state_values(chat, bu)
           && load_unpack_state_bin(chat, bu)
           && load_unpack_topic_info(chat, bu)
           && load_unpack_mod_list(chat, bu)
           && load_unpack_keys(chat, bu)
           && load_unpack_self_info(chat, bu)
           && load_unpack_saved_peers(chat, bu);
}

non_null()
static bool save_pack_state_values(const GC_Chat *chat, Bin_Pack *bp)
{
    const GC_Shared_State_Values vals = {
        chat->connection_state == CS_DISCONNECTED,  // 1
        chat->shared_state.group_name_len,  // 2
        chat->shared_state.privacy_state,  // 3
        chat->shared_state.maxpeers,  // 4
        chat->shared_state.password_length,  // 5
        chat->shared_state.version,  // 6
        chat->shared_state.topic_lock,  // 7
        chat->shared_state.voice_state,  // 8
    };
    return gc_shared_state_values_pack(&vals, bp);
}

non_null()
static bool save_pack_state_bin(const GC_Chat *chat, Bin_Pack *bp)
{
    GC_Shared_State_Bin vals;
    memcpy(vals.sig, chat->shared_state_sig, SIGNATURE_SIZE);
    memcpy(vals.founder_public_key, chat->shared_state.founder_public_key, EXT_PUBLIC_KEY_SIZE);
    memcpy(vals.group_name, chat->shared_state.group_name, MAX_GC_GROUP_NAME_SIZE);
    vals.group_name_size = chat->shared_state.group_name_len;
    memcpy(vals.password, chat->shared_state.password, MAX_GC_PASSWORD_SIZE);
    vals.password_size = chat->shared_state.password_length;
    memcpy(vals.mod_list_hash, chat->shared_state.mod_list_hash, MOD_MODERATION_HASH_SIZE);
    return gc_shared_state_bin_pack(&vals, bp);
}

non_null()
static bool save_pack_topic_info(const GC_Chat *chat, Bin_Pack *bp)
{
    GC_Topic_Info info;
    info.version = chat->topic_info.version;
    info.length = chat->topic_info.length;
    info.checksum = chat->topic_info.checksum;
    memcpy(info.topic, chat->topic_info.topic, MAX_GC_TOPIC_SIZE);
    memcpy(info.public_key_sig, chat->topic_info.public_sig_key, SIG_PUBLIC_KEY_SIZE);
    memcpy(info.sig, chat->topic_sig, SIGNATURE_SIZE);
    return gc_topic_info_pack(&info, bp);
}

non_null()
static bool save_pack_mod_list(const GC_Chat *chat, Bin_Pack *bp)
{
    GC_Mod_List mods;
    mods.num_mods = min_u16(chat->moderation.num_mods, MOD_MAX_NUM_MODERATORS);

    const uint32_t packed_mod_list_size = mods.num_mods * MOD_LIST_ENTRY_SIZE;
    uint8_t *packed_mod_list = (uint8_t *)malloc(packed_mod_list_size);

    // we can still recover without the mod list
    if (packed_mod_list == nullptr) {
        LOGGER_ERROR(chat->log, "Failed to allocate memory for moderation list");

        mods.packed_mod_list = nullptr;
        mods.packed_mod_list_size = 0;
    } else {
        mod_list_pack(&chat->moderation, packed_mod_list);

        mods.packed_mod_list = packed_mod_list;
        mods.packed_mod_list_size = packed_mod_list_size;
    }

    const bool result = gc_mod_list_pack(&mods, bp);
    free(packed_mod_list);
    return result;
}

non_null()
static bool save_pack_keys(const GC_Chat *chat, Bin_Pack *bp)
{
    GC_Keys keys;
    memcpy(keys.chat_public_key, chat->chat_public_key, EXT_PUBLIC_KEY_SIZE);
    memcpy(keys.chat_secret_key, chat->chat_secret_key, EXT_SECRET_KEY_SIZE);
    memcpy(keys.self_public_key, chat->self_public_key, EXT_PUBLIC_KEY_SIZE);
    memcpy(keys.self_secret_key, chat->self_secret_key, EXT_SECRET_KEY_SIZE);
    return gc_keys_pack(&keys, bp);
}

non_null()
static bool save_pack_self_info(const GC_Chat *chat, Bin_Pack *bp)
{
    GC_Peer *self = &chat->group[0];

    if (self->nick_length > MAX_GC_NICK_SIZE) {
        LOGGER_ERROR(chat->log, "self_nick is too big (%u). Truncating to %d", self->nick_length, MAX_GC_NICK_SIZE);
        self->nick_length = MAX_GC_NICK_SIZE;
    }

    GC_Self_Info info;
    info.nick_length = self->nick_length;
    info.role = (uint8_t)self->role;
    info.status = self->status;
    memcpy(info.nick, self->nick, MAX_GC_NICK_SIZE);
    info.nick_size = self->nick_length;
    return gc_self_info_pack(&info, bp);
}

non_null()
static bool save_pack_saved_peers(const GC_Chat *chat, Bin_Pack *bp)
{
    uint16_t saved_peers_size;
    uint8_t *saved_peers = (uint8_t *)malloc(GC_MAX_SAVED_PEERS * GC_SAVED_PEER_SIZE);

    // we can still recover without the saved peers list
    if (saved_peers == nullptr) {
        LOGGER_ERROR(chat->log, "Failed to allocate memory for saved peers list");

        saved_peers_size = 0;
    } else {
        uint16_t packed_size = 0;
        const int count = pack_gc_saved_peers(
            chat, saved_peers, GC_MAX_SAVED_PEERS * GC_SAVED_PEER_SIZE, &packed_size);

        if (count < 0) {
            LOGGER_ERROR(chat->log, "Failed to pack saved peers");
        }

        saved_peers_size = packed_size;
    }

    const GC_Saved_Peers peers = {
        saved_peers_size,  // XXX: duplicated for historical reasons
        saved_peers,
        saved_peers_size,
    };

    const bool result = gc_saved_peers_pack(&peers, bp);
    free(saved_peers);
    return result;
}

void gc_save_pack_group(const GC_Chat *chat, Bin_Pack *bp)
{
    if (chat->numpeers == 0) {
        LOGGER_ERROR(chat->log, "Failed to pack group: numpeers is 0");
        return;
    }

    bin_pack_array(bp, 7);

    save_pack_state_values(chat, bp); // 1
    save_pack_state_bin(chat, bp); // 2
    save_pack_topic_info(chat, bp); // 3
    save_pack_mod_list(chat, bp); // 4
    save_pack_keys(chat, bp); // 5
    save_pack_self_info(chat, bp); // 6
    save_pack_saved_peers(chat, bp); // 7
}
