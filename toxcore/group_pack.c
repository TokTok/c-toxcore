/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2020 The TokTok team.
 * Copyright © 2015 Tox project.
 */

/**
 * Packer and unpacker functions for saving and loading groups.
 */

#include "group_pack.h"

#include <assert.h>
#include <stdint.h>

#include "bin_unpack.h"

non_null()
static bool load_unpack_state_values(GC_Chat *chat, const msgpack_object *obj)
{
    if (obj->type != MSGPACK_OBJECT_ARRAY || obj->via.array.size < 8) {
        LOGGER_ERROR(chat->log, "Group state values array malformed (type: %d)", obj->type);
        return false;
    }

    bool manually_disconnected = 0;
    uint8_t privacy_state = 0;
    uint8_t voice_state = 0;

    if (!(bin_unpack_bool(&manually_disconnected, &obj->via.array.ptr[0])
            && bin_unpack_u16(&chat->shared_state.group_name_len, &obj->via.array.ptr[1])
            && bin_unpack_u08(&privacy_state, &obj->via.array.ptr[2])
            && bin_unpack_u16(&chat->shared_state.maxpeers, &obj->via.array.ptr[3])
            && bin_unpack_u16(&chat->shared_state.password_length, &obj->via.array.ptr[4])
            && bin_unpack_u32(&chat->shared_state.version, &obj->via.array.ptr[5])
            && bin_unpack_u32(&chat->shared_state.topic_lock, &obj->via.array.ptr[6])
            && bin_unpack_u08(&voice_state, &obj->via.array.ptr[7]))) {
        LOGGER_ERROR(chat->log, "Failed to unpack state value");
        return false;
    }

    chat->connection_state = manually_disconnected ? CS_DISCONNECTED : CS_CONNECTING;
    chat->shared_state.privacy_state = (Group_Privacy_State)privacy_state;
    chat->shared_state.voice_state = (Group_Voice_State)voice_state;

    return true;
}

non_null()
static bool load_unpack_state_bin(GC_Chat *chat, const msgpack_object *obj)
{
    if (obj->type != MSGPACK_OBJECT_ARRAY || obj->via.array.size < 5) {
        LOGGER_ERROR(chat->log, "Group state binary array malformed (type: %d)", obj->type);
        return false;
    }

    if (!(bin_unpack_bytes_fixed(chat->shared_state_sig, SIGNATURE_SIZE, &obj->via.array.ptr[0])
            && bin_unpack_bytes_fixed(chat->shared_state.founder_public_key, EXT_PUBLIC_KEY_SIZE, &obj->via.array.ptr[1])
            && bin_unpack_bytes_fixed(chat->shared_state.group_name, MAX_GC_GROUP_NAME_SIZE, &obj->via.array.ptr[2])
            && bin_unpack_bytes_fixed(chat->shared_state.password, MAX_GC_PASSWORD_SIZE, &obj->via.array.ptr[3])
            && bin_unpack_bytes_fixed(chat->shared_state.mod_list_hash, MOD_MODERATION_HASH_SIZE, &obj->via.array.ptr[4]))) {
        LOGGER_ERROR(chat->log, "Failed to unpack state binary data");
        return false;
    }

    return true;
}

non_null()
static bool load_unpack_topic_info(GC_Chat *chat, const msgpack_object *obj)
{
    if (obj->type != MSGPACK_OBJECT_ARRAY || obj->via.array.size < 6) {
        LOGGER_ERROR(chat->log, "Group topic array malformed (type: %d)", obj->type);
        return false;
    }

    if (!(bin_unpack_u32(&chat->topic_info.version, &obj->via.array.ptr[0])
            && bin_unpack_u16(&chat->topic_info.length, &obj->via.array.ptr[1])
            && bin_unpack_u16(&chat->topic_info.checksum, &obj->via.array.ptr[2])
            && bin_unpack_bytes_fixed(chat->topic_info.topic, MAX_GC_TOPIC_SIZE, &obj->via.array.ptr[3])
            && bin_unpack_bytes_fixed(chat->topic_info.public_sig_key, SIG_PUBLIC_KEY_SIZE, &obj->via.array.ptr[4])
            && bin_unpack_bytes_fixed(chat->topic_sig, SIGNATURE_SIZE, &obj->via.array.ptr[5]))) {
        LOGGER_ERROR(chat->log, "Failed to unpack topic info");
        return false;
    }

    return true;
}

non_null()
static bool load_unpack_mod_list(GC_Chat *chat, const msgpack_object *obj)
{
    if (obj->type != MSGPACK_OBJECT_ARRAY || obj->via.array.size < 2) {
        LOGGER_ERROR(chat->log, "Group mod list array malformed (type: %d)", obj->type);
        return false;
    }

    uint8_t packed_mod_list[GROUP_SAVE_MAX_MODERATORS * MOD_LIST_ENTRY_SIZE];

    if (!(bin_unpack_u16(&chat->moderation.num_mods, &obj->via.array.ptr[0])
            && bin_unpack_bytes_fixed(packed_mod_list, sizeof(packed_mod_list), &obj->via.array.ptr[1]))) {
        LOGGER_ERROR(chat->log, "Failed to unpack mod list binary data");
        return false;
    }

    if (mod_list_unpack(&chat->moderation, packed_mod_list, sizeof(packed_mod_list), chat->moderation.num_mods) == -1) {
        LOGGER_ERROR(chat->log, "Failed to unpack mod list info");
        return false;
    }

    return true;
}

non_null()
static bool load_unpack_keys(GC_Chat *chat, const msgpack_object *obj)
{
    if (obj->type != MSGPACK_OBJECT_ARRAY || obj->via.array.size < 4) {
        LOGGER_ERROR(chat->log, "Group keys array malformed (type: %d)", obj->type);
        return false;
    }

    if (!(bin_unpack_bytes_fixed(chat->chat_public_key, EXT_PUBLIC_KEY_SIZE, &obj->via.array.ptr[0])
            && bin_unpack_bytes_fixed(chat->chat_secret_key, EXT_SECRET_KEY_SIZE, &obj->via.array.ptr[1])
            && bin_unpack_bytes_fixed(chat->self_public_key, EXT_PUBLIC_KEY_SIZE, &obj->via.array.ptr[2])
            && bin_unpack_bytes_fixed(chat->self_secret_key, EXT_SECRET_KEY_SIZE, &obj->via.array.ptr[3]))) {
        LOGGER_ERROR(chat->log, "Failed to unpack keys");
        return false;
    }

    return true;
}

non_null()
static bool load_unpack_self_info(GC_Chat *chat, const msgpack_object *obj)
{
    if (obj->type != MSGPACK_OBJECT_ARRAY || obj->via.array.size < 4) {
        LOGGER_ERROR(chat->log, "Group self info array malformed (type: %d)", obj->type);
        return false;
    }

    uint8_t self_nick[MAX_GC_NICK_SIZE];
    uint16_t self_nick_len = 0;
    uint8_t self_role = GR_USER;
    uint8_t self_status = GS_NONE;

    if (!(bin_unpack_u16(&self_nick_len, &obj->via.array.ptr[0])
            && bin_unpack_bytes_fixed(self_nick, sizeof(self_nick), &obj->via.array.ptr[1])
            && bin_unpack_u08(&self_role, &obj->via.array.ptr[2])
            && bin_unpack_u08(&self_status, &obj->via.array.ptr[3]))) {
        LOGGER_ERROR(chat->log, "Failed to unpack self info");
        return false;
    }

    // we have to add ourself before setting self info
    if (peer_add(chat, nullptr, chat->self_public_key) != 0) {
        LOGGER_ERROR(chat->log, "Failed to add self to peer list");
        return false;
    }

    assert(chat->numpeers > 0);
    assert(self_nick_len <= MAX_GC_NICK_SIZE);

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
static bool load_unpack_saved_peers(GC_Chat *chat, const msgpack_object *obj)
{
    if (obj->type != MSGPACK_OBJECT_ARRAY || obj->via.array.size < 2) {
        LOGGER_ERROR(chat->log, "Group saved peers array malformed (type: %d)", obj->type);
        return false;
    }

    // Saved peers
    uint8_t num_saved_peers = 0;

    if (!bin_unpack_u08(&num_saved_peers, &obj->via.array.ptr[0])) {
        LOGGER_ERROR(chat->log, "Failed to unpack saved peers value");
        return false;
    }

    uint8_t saved_peers[GC_SAVED_PEER_SIZE * GC_MAX_SAVED_PEERS];

    if (!bin_unpack_bytes_fixed(saved_peers, sizeof(saved_peers), &obj->via.array.ptr[1])) {
        LOGGER_ERROR(chat->log, "Failed to unpack saved peers binary data");
        return false;
    }

    if (unpack_gc_saved_peers(chat, saved_peers, sizeof(saved_peers), num_saved_peers) == -1) {
        LOGGER_WARNING(chat->log, "Failed to unpack saved peers");  // recoverable error
    }

    return true;
}

bool gc_load_unpack_group(GC_Chat *chat, const msgpack_object *obj)
{
    if (obj->type != MSGPACK_OBJECT_ARRAY || obj->via.array.size < 7) {
        LOGGER_ERROR(chat->log, "Group info array malformed (type %d)", obj->type);
        return false;
    }

    return load_unpack_state_values(chat,   &obj->via.array.ptr[0])
           && load_unpack_state_bin(chat,   &obj->via.array.ptr[1])
           && load_unpack_topic_info(chat,  &obj->via.array.ptr[2])
           && load_unpack_mod_list(chat,    &obj->via.array.ptr[3])
           && load_unpack_keys(chat,        &obj->via.array.ptr[4])
           && load_unpack_self_info(chat,   &obj->via.array.ptr[5])
           && load_unpack_saved_peers(chat, &obj->via.array.ptr[6]);
}

non_null()
static void save_pack_state_values(const GC_Chat *chat, msgpack_packer *mp)
{
    msgpack_pack_array(mp, 8);

    if (chat->connection_state == CS_DISCONNECTED) { // 1
        msgpack_pack_true(mp);
    } else {
        msgpack_pack_false(mp);
    }
    msgpack_pack_uint16(mp, chat->shared_state.group_name_len); // 2
    msgpack_pack_uint8(mp, chat->shared_state.privacy_state); // 3
    msgpack_pack_uint16(mp, chat->shared_state.maxpeers); // 4
    msgpack_pack_uint16(mp, chat->shared_state.password_length); // 5
    msgpack_pack_uint32(mp, chat->shared_state.version); // 6
    msgpack_pack_uint32(mp, chat->shared_state.topic_lock); // 7
    msgpack_pack_uint8(mp, chat->shared_state.voice_state); // 8
}

non_null()
static void save_pack_state_bin(const GC_Chat *chat, msgpack_packer *mp)
{
    msgpack_pack_array(mp, 5);

    msgpack_pack_bin(mp, SIGNATURE_SIZE);
    msgpack_pack_bin_body(mp, chat->shared_state_sig, SIGNATURE_SIZE); // 1
    msgpack_pack_bin(mp, EXT_PUBLIC_KEY_SIZE);
    msgpack_pack_bin_body(mp, chat->shared_state.founder_public_key, EXT_PUBLIC_KEY_SIZE); // 2
    msgpack_pack_bin(mp, MAX_GC_GROUP_NAME_SIZE);
    msgpack_pack_bin_body(mp, chat->shared_state.group_name, MAX_GC_GROUP_NAME_SIZE); // 3
    msgpack_pack_bin(mp, MAX_GC_PASSWORD_SIZE);
    msgpack_pack_bin_body(mp, chat->shared_state.password, MAX_GC_PASSWORD_SIZE); // 4
    msgpack_pack_bin(mp, MOD_MODERATION_HASH_SIZE);
    msgpack_pack_bin_body(mp, chat->shared_state.mod_list_hash, MOD_MODERATION_HASH_SIZE); // 5
}

non_null()
static void save_pack_topic_info(const GC_Chat *chat, msgpack_packer *mp)
{
    msgpack_pack_array(mp, 6);

    msgpack_pack_uint32(mp, chat->topic_info.version); // 1
    msgpack_pack_uint16(mp, chat->topic_info.length); // 2
    msgpack_pack_uint16(mp, chat->topic_info.checksum); // 3
    msgpack_pack_bin(mp, MAX_GC_TOPIC_SIZE);
    msgpack_pack_bin_body(mp, chat->topic_info.topic, MAX_GC_TOPIC_SIZE); // 4
    msgpack_pack_bin(mp, SIG_PUBLIC_KEY_SIZE);
    msgpack_pack_bin_body(mp, chat->topic_info.public_sig_key, SIG_PUBLIC_KEY_SIZE); // 5
    msgpack_pack_bin(mp, SIGNATURE_SIZE);
    msgpack_pack_bin_body(mp, chat->topic_sig, SIGNATURE_SIZE); // 6
}

non_null()
static void save_pack_mod_list(const GC_Chat *chat, msgpack_packer *mp)
{
    msgpack_pack_array(mp, 2);

    uint8_t packed_mod_list[GROUP_SAVE_MAX_MODERATORS * MOD_LIST_ENTRY_SIZE];
    mod_list_pack(&chat->moderation, packed_mod_list);

    msgpack_pack_uint16(mp, chat->moderation.num_mods); // 1
    msgpack_pack_bin(mp, sizeof(packed_mod_list));
    msgpack_pack_bin_body(mp, packed_mod_list, sizeof(packed_mod_list)); // 2
}

non_null()
static void save_pack_keys(const GC_Chat *chat, msgpack_packer *mp)
{
    msgpack_pack_array(mp, 4);

    msgpack_pack_bin(mp, EXT_PUBLIC_KEY_SIZE);
    msgpack_pack_bin_body(mp, chat->chat_public_key, EXT_PUBLIC_KEY_SIZE); // 1
    msgpack_pack_bin(mp, EXT_SECRET_KEY_SIZE);
    msgpack_pack_bin_body(mp, chat->chat_secret_key, EXT_SECRET_KEY_SIZE); // 2
    msgpack_pack_bin(mp, EXT_PUBLIC_KEY_SIZE);
    msgpack_pack_bin_body(mp, chat->self_public_key, EXT_PUBLIC_KEY_SIZE); // 3
    msgpack_pack_bin(mp, EXT_SECRET_KEY_SIZE);
    msgpack_pack_bin_body(mp, chat->self_secret_key, EXT_SECRET_KEY_SIZE); // 4
}

non_null()
static void save_pack_self_info(const GC_Chat *chat, msgpack_packer *mp)
{
    msgpack_pack_array(mp, 4);

    const GC_Peer *self = &chat->group[0];

    msgpack_pack_uint16(mp, self->nick_length); // 1
    msgpack_pack_bin(mp, sizeof(self->nick));
    msgpack_pack_bin_body(mp, self->nick, sizeof(self->nick)); // 2
    msgpack_pack_uint8(mp, (uint8_t)self->role); // 3
    msgpack_pack_uint8(mp, (uint8_t)self->status); // 4
}

non_null()
static void save_pack_saved_peers(const GC_Chat *chat, msgpack_packer *mp)
{
    msgpack_pack_array(mp, 2);

    uint8_t saved_peers[GC_SAVED_PEER_SIZE * GC_MAX_SAVED_PEERS];
    int packed_num = pack_gc_saved_peers(chat, saved_peers, (uint16_t)sizeof(saved_peers));

    if (packed_num < 0) {
        packed_num = 0;
        LOGGER_WARNING(chat->log, "Failed to pack saved peers");
    }

    msgpack_pack_uint8(mp, packed_num); // 1
    msgpack_pack_bin(mp, sizeof(saved_peers));
    msgpack_pack_bin_body(mp, saved_peers, sizeof(saved_peers)); // 2
}

void gc_save_pack_group(const GC_Chat *chat, msgpack_packer *mp)
{
    if (chat->numpeers == 0) {
        LOGGER_ERROR(chat->log, "Failed to pack group: numpeers is 0");
        return;
    }

    msgpack_pack_array(mp, 7);

    save_pack_state_values(chat, mp); // 1
    save_pack_state_bin(chat, mp); // 2
    save_pack_topic_info(chat, mp); // 3
    save_pack_mod_list(chat, mp); // 4
    save_pack_keys(chat, mp); // 5
    save_pack_self_info(chat, mp); // 6
    save_pack_saved_peers(chat, mp); // 7
}
