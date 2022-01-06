/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2020 The TokTok team.
 * Copyright © 2015 Tox project.
 */

/*
 * An implementation of massive text only group chats.
 */

#include "group_chats.h"

#include <string.h>

#include "DHT.h"
#include "LAN_discovery.h"
#include "Messenger.h"
#include "TCP_connection.h"
#include "friend_connection.h"
#include "group_announce.h"
#include "group_connection.h"
#include "group_moderation.h"
#include "mono_time.h"
#include "network.h"
#include "util.h"

#ifndef VANILLA_NACL
#include <sodium.h>
#endif  // VANILLA_NACL

#ifndef VANILLA_NACL

/* The minimum size of a plaintext group handshake packet */
#define GC_MIN_HS_PACKET_PAYLOAD_SIZE (1 + ENC_PUBLIC_KEY_SIZE + SIG_PUBLIC_KEY_SIZE + 1)

/* The minimum size of an encrypted group handshake packet. */
#define GC_MIN_ENCRYPTED_HS_PAYLOAD_SIZE (1 + ENC_PUBLIC_KEY_SIZE + ENC_PUBLIC_KEY_SIZE +\
                                          GC_MIN_HS_PACKET_PAYLOAD_SIZE + CRYPTO_NONCE_SIZE + CRYPTO_MAC_SIZE)

/* Size of a group's shared state in packed format */
#define GC_PACKED_SHARED_STATE_SIZE (EXT_PUBLIC_KEY_SIZE + sizeof(uint32_t) + MAX_GC_GROUP_NAME_SIZE +\
                                     sizeof(uint16_t) + 1 + sizeof(uint16_t) + MAX_GC_PASSWORD_SIZE +\
                                     GC_MODERATION_HASH_SIZE + sizeof(uint32_t) + sizeof(uint32_t))

/* Minimum size of a topic packet; includes topic length, public signature key, topic version and checksum */
#define GC_MIN_PACKED_TOPIC_INFO_SIZE (sizeof(uint16_t) + SIG_PUBLIC_KEY_SIZE + sizeof(uint32_t) + sizeof(uint16_t))

#define GC_SHARED_STATE_ENC_PACKET_SIZE (SIGNATURE_SIZE + GC_PACKED_SHARED_STATE_SIZE)

/* Header information attached to all broadcast messages: broadcast_type */
#define GC_BROADCAST_ENC_HEADER_SIZE 1

/* Size of a group packet message ID */
#define GC_MESSAGE_ID_BYTES sizeof(uint64_t)

/* Size of a lossless ack packet */
#define GC_LOSSLESS_ACK_PACKET_SIZE (GC_MESSAGE_ID_BYTES + 1)

/* Smallest possible size of an encrypted lossless payload.
 *
 * Data includes the message_id, group packet type, and the nonce and MAC for decryption.
 */
#define GC_MIN_LOSSLESS_PAYLOAD_SIZE (GC_MESSAGE_ID_BYTES + CRYPTO_NONCE_SIZE + 1 + CRYPTO_MAC_SIZE)

/* Smallest possible size of a lossy group packet */
#define GC_MIN_LOSSY_PAYLOAD_SIZE (GC_MIN_LOSSLESS_PAYLOAD_SIZE - GC_MESSAGE_ID_BYTES)

/* Maximum number of bytes to pad packets with */
#define GC_MAX_PACKET_PADDING 8

/* Minimum size of a ping packet, which contains the peer count, peer list checksum, shared state version,
 * sanctions list version, sanctions list checksum, topic version, and topic checksum
 */
#define GC_PING_PACKET_MIN_DATA_SIZE ((sizeof(uint16_t) * 4) + (sizeof(uint32_t) * 3))

/* How often we can send a group sync request packet */
#define GC_SYNC_REQUEST_LIMIT 2

/* How often we try to handshake with an unconfirmed peer */
#define GC_SEND_HANDSHAKE_INTERVAL 3

/* How often we rotate session encryption keys with a peer */
#define GC_KEY_ROTATION_TIMEOUT (5 * 60)

/* How often we try to reconnect to peers that recently timed out */
#define GC_TIMED_OUT_RECONN_TIMEOUT (GC_UNCONFIRMED_PEER_TIMEOUT * 3)

/* How long before we stop trying to reconnect with a timed out peer */
#define GC_TIMED_OUT_STALE_TIMEOUT (60 * 15)


/* Types of broadcast messages. */
typedef enum Group_Message_Type {
    GC_MESSAGE_TYPE_NORMAL = 0x00,
    GC_MESSAGE_TYPE_ACTION = 0x01,
} Group_Message_Type;

/* Types of handshake request packets. */
typedef enum Group_Handshake_Packet_Type {
    GH_REQUEST  = 0x00,  // Requests a handshake
    GH_RESPONSE = 0x01,  // Responds to a handshake request
} Group_Handshake_Packet_Type;

/* Types of handshake requests (within a handshake request packet). */
typedef enum Group_Handshake_Request_Type {
    HS_INVITE_REQUEST     = 0x00,   // Requests an invite to the group
    HS_PEER_INFO_EXCHANGE = 0x01,   // Requests a peer info exchange
} Group_Handshake_Request_Type;

/* Theses bitmasks determine what group state info a peer is requesting in a sync request */
typedef enum Group_Sync_Flags {
    GF_PEERS      = (1 << 0), // 1
    GF_TOPIC      = (1 << 1), // 2
    GF_STATE      = (1 << 2), // 4
} Group_Sync_Flags;


static bool self_gc_is_founder(const GC_Chat *chat);
static bool group_number_valid(const GC_Session *c, int group_number);
static int peer_add(const Messenger *m, int group_number, const IP_Port *ipp, const uint8_t *public_key);
static int peer_update(Messenger *m, int group_number, GC_GroupPeer *peer, uint32_t peer_number);
static int group_delete(GC_Session *c, GC_Chat *chat);
static void group_cleanup(GC_Session *c, GC_Chat *chat);
static bool group_exists(const GC_Session *c, const uint8_t *chat_id);
static void add_tcp_relays_to_chat(Messenger *m, GC_Chat *chat);
static int peer_delete(Messenger *m, int group_number, uint32_t peer_number, Group_Exit_Type exit_type,
                       const uint8_t *data, uint16_t length, void *userdata);
static int create_gc_session_keypair(uint8_t *public_key, uint8_t *secret_key);
static size_t load_gc_peers(Messenger *m, GC_Chat *chat, const GC_SavedPeerInfo *addrs, uint16_t num_addrs);

/* Return true if `peer_number` is our own. */
static bool peer_number_is_self(int peer_number)
{
    return peer_number == 0;
}

/* Returns the amount of empty padding a packet of designated length should have. */
static uint16_t group_packet_padding_length(uint16_t length)
{
    return (MAX_GC_PACKET_SIZE - length) % GC_MAX_PACKET_PADDING;
}

void gc_get_self_nick(const GC_Chat *chat, uint8_t *nick)
{
    if (nick != nullptr) {
        memcpy(nick, chat->group[0].nick, chat->group[0].nick_length);
    }
}

uint16_t gc_get_self_nick_size(const GC_Chat *chat)
{
    return chat->group[0].nick_length;
}

/* Sets self nick to `nick`.
 *
 * Returns 0 on success.
 * Returns -1 if `nick` is null or `length` is greater than MAX_GC_NICK_SIZE.
 */
static int self_gc_set_nick(const GC_Chat *chat, const uint8_t *nick, size_t length)
{
    if (nick == nullptr || length > MAX_GC_NICK_SIZE) {
        return -1;
    }

    memcpy(chat->group[0].nick, nick, length);
    chat->group[0].nick_length = length;

    return 0;
}

Group_Role gc_get_self_role(const GC_Chat *chat)
{
    return chat->group[0].role;
}

/* Sets self role. If role is invalid this function has no effect. */
static void self_gc_set_role(GC_Chat *chat, Group_Role role)
{
    if (role <= GR_OBSERVER) {
        chat->group[0].role = role;
    }
}

uint8_t gc_get_self_status(const GC_Chat *chat)
{
    return chat->group[0].status;
}

/* Sets self status. If status is invalid this function has no effect. */
static void self_gc_set_status(GC_Chat *chat, Group_Peer_Status status)
{
    if (status <= GS_BUSY) {
        chat->group[0].status = status;
    }
}

/* Sets self confirmed status. */
static void self_gc_set_confirmed(GC_Chat *chat, bool confirmed)
{
    chat->gcc[0].confirmed = confirmed;
}

uint32_t gc_get_self_peer_id(const GC_Chat *chat)
{
    return chat->group[0].peer_id;
}

/* Returns true if self has the founder role */
static bool self_gc_is_founder(const GC_Chat *chat)
{
    return gc_get_self_role(chat) == GR_FOUNDER;
}

void gc_get_self_public_key(const GC_Chat *chat, uint8_t *public_key)
{
    if (public_key != nullptr) {
        memcpy(public_key, chat->self_public_key, ENC_PUBLIC_KEY_SIZE);
    }
}

/* Sets self extended public key to `ext_public_key`.
 *
 * If `ext_public_key` is null this function has no effect.
 */
static void self_gc_set_ext_public_key(GC_Chat *chat, const uint8_t *ext_public_key)
{
    if (ext_public_key != nullptr) {
        memcpy(chat->gcc[0].addr.public_key, ext_public_key, EXT_PUBLIC_KEY_SIZE);
    }
}

void gc_pack_group_info(const GC_Chat *chat, Saved_Group *temp)
{
    *temp = (Saved_Group) {
        0
    };

    temp->shared_state_version = net_htonl(chat->shared_state.version);
    memcpy(temp->shared_state_signature, chat->shared_state_sig, SIGNATURE_SIZE);
    memcpy(temp->founder_public_key, chat->shared_state.founder_public_key, EXT_PUBLIC_KEY_SIZE);
    temp->group_name_length = net_htons(chat->shared_state.group_name_len);
    memcpy(temp->group_name, chat->shared_state.group_name, MAX_GC_GROUP_NAME_SIZE);
    temp->privacy_state = chat->shared_state.privacy_state;
    temp->maxpeers = net_htons(chat->shared_state.maxpeers);
    temp->password_length = net_htons(chat->shared_state.password_length);
    memcpy(temp->password, chat->shared_state.password, MAX_GC_PASSWORD_SIZE);
    memcpy(temp->mod_list_hash, chat->shared_state.mod_list_hash, GC_MODERATION_HASH_SIZE);
    temp->topic_lock = net_htonl(chat->shared_state.topic_lock);
    temp->topic_length = net_htons(chat->topic_info.length);
    memcpy(temp->topic, chat->topic_info.topic, MAX_GC_TOPIC_SIZE);
    memcpy(temp->topic_public_sig_key, chat->topic_info.public_sig_key, SIG_PUBLIC_KEY_SIZE);
    temp->topic_version = net_htonl(chat->topic_info.version);
    memcpy(temp->topic_signature, chat->topic_sig, SIGNATURE_SIZE);

    memcpy(temp->chat_public_key, chat->chat_public_key, EXT_PUBLIC_KEY_SIZE);
    memcpy(temp->chat_secret_key, chat->chat_secret_key, EXT_SECRET_KEY_SIZE);  /* empty for non-founders */

    memcpy(temp->addrs, &chat->saved_peers, GC_MAX_SAVED_PEERS * sizeof(GC_SavedPeerInfo));

    temp->num_mods = net_htons(chat->moderation.num_mods);
    mod_list_pack(chat, temp->mod_list);

    const bool is_manually_disconnected = chat->connection_state == CS_DISCONNECTED;
    temp->group_connection_state = is_manually_disconnected ? SGCS_DISCONNECTED : SGCS_CONNECTED;

    memcpy(temp->self_public_key, chat->self_public_key, EXT_PUBLIC_KEY_SIZE);
    memcpy(temp->self_secret_key, chat->self_secret_key, EXT_SECRET_KEY_SIZE);

    gc_get_self_nick(chat, temp->self_nick);
    temp->self_nick_length = net_htons(gc_get_self_nick_size(chat));
    temp->self_role = gc_get_self_role(chat);
    temp->self_status = gc_get_self_status(chat);
}

/* Returns true if chat privacy state is set to public. */
static bool is_public_chat(const GC_Chat *chat)
{
    return chat->shared_state.privacy_state == GI_PUBLIC;
}

/* Returns true if group is password protected */
static bool chat_is_password_protected(const GC_Chat *chat)
{
    return chat->shared_state.password_length > 0;
}

/* Returns true if `password` matches the current group password. */
static bool validate_password(const GC_Chat *chat, const uint8_t *password, uint16_t length)
{
    if (length != chat->shared_state.password_length) {
        return false;
    }

    if (memcmp(chat->shared_state.password, password, length) != 0) {
        return false;
    }

    return true;
}

static int get_peer_number_of_enc_pk(const GC_Chat *chat, const uint8_t *public_enc_key, bool confirmed);

/* Returns the chat object that contains a self_public_key equal to `id`.
 *
 * `id` must be at least ENC_PUBLIC_KEY_SIZE bytes in length.
 */
static const GC_Chat *get_chat_by_id(const GC_Session *c, const uint8_t *id)
{
    if (c == nullptr) {
        return nullptr;
    }

    for (uint32_t i = 0; i < c->num_chats; ++i) {
        const GC_Chat *chat = &c->chats[i];

        if (memcmp(id, chat->self_public_key, ENC_PUBLIC_KEY_SIZE) == 0) {
            return chat;
        }

        if (get_peer_number_of_enc_pk(chat, id, false) != -1) {
            return chat;
        }
    }

    return nullptr;
}

/* Returns the jenkins hash of a 32 byte public encryption key. */
uint32_t gc_get_pk_jenkins_hash(const uint8_t *public_key)
{
    return jenkins_one_at_a_time_hash(public_key, ENC_PUBLIC_KEY_SIZE);
}

/* Sets the sum of the public_key_hash of all confirmed peers.
 *
 * Must be called every time a peer is confirmed or deleted.
 */
static void set_gc_peerlist_checksum(GC_Chat *chat)
{
    uint16_t sum = 0;

    for (uint32_t i = 0; i < chat->numpeers; ++i) {
        const GC_Connection *gconn = &chat->gcc[i];

        if (gconn->confirmed) {
            sum += gconn->public_key_hash;
        }
    }

    chat->peers_checksum = sum;
}

/* Returns a checksum of the topic currently set in `topic_info`. */
static uint16_t get_gc_topic_checksum(const GC_TopicInfo *topic_info)
{
    uint16_t sum = 0;

    for (uint16_t i = 0; i < topic_info->length; ++i) {
        sum += topic_info->topic[i];
    }

    return sum;
}

/* Sets the checksum of the topic currently set in `topic_info`.
 *
 * This must be called every time the topic is changed.
 */
static void set_gc_topic_checksum(GC_TopicInfo *topic_info)
{
    topic_info->checksum = get_gc_topic_checksum(topic_info);
}

/* Check if peer with the public encryption key is in peer list.
 *
 * Returns the peer number if peer is in the peer list.
 * Returns -1 if peer is not in the peer list.
 *
 * If `confirmed` is true the peer number will only be returned if the peer is confirmed.
 */
static int get_peer_number_of_enc_pk(const GC_Chat *chat, const uint8_t *public_enc_key, bool confirmed)
{
    for (uint32_t i = 0; i < chat->numpeers; ++i) {
        const GC_Connection *gconn = &chat->gcc[i];

        if (gconn->pending_delete) {
            continue;
        }

        if (confirmed && !gconn->confirmed) {
            continue;
        }

        if (memcmp(gconn->addr.public_key, public_enc_key, ENC_PUBLIC_KEY_SIZE) == 0) {
            return i;
        }
    }

    return -1;
}

/* Check if peer associated with `public_sig_key` is in peer list.
 *
 * Returns the peer number if peer is in the peer list.
 * Returns -1 if peer is not in the peer list.
 */
static int get_peer_number_of_sig_pk(const GC_Chat *chat, const uint8_t *public_sig_key)
{
    for (uint32_t i = 0; i < chat->numpeers; ++i) {
        if (memcmp(get_sig_pk(chat->gcc[i].addr.public_key), public_sig_key, SIG_PUBLIC_KEY_SIZE) == 0) {
            return i;
        }
    }

    return -1;
}

int gc_get_enc_pk_from_sig_pk(const GC_Chat *chat, uint8_t *public_key, const uint8_t *public_sig_key)
{
    for (uint32_t i = 0; i < chat->numpeers; ++i) {
        const uint8_t *full_pk = chat->gcc[i].addr.public_key;

        if (memcmp(public_sig_key, get_sig_pk(full_pk), SIG_PUBLIC_KEY_SIZE) == 0) {
            memcpy(public_key, get_enc_key(full_pk), ENC_PUBLIC_KEY_SIZE);
            return 0;
        }
    }

    return -1;
}

bool gc_peer_number_is_valid(const GC_Chat *chat, int peer_number)
{
    return peer_number >= 0 && peer_number < chat->numpeers;
}

/* Returns the peer number associated with peer_id.
 * Returns -1 if peer_id is invalid. */
static int get_peer_number_of_peer_id(const GC_Chat *chat, uint32_t peer_id)
{
    for (uint32_t i = 0; i < chat->numpeers; ++i) {
        if (chat->group[i].peer_id == peer_id) {
            return i;
        }
    }

    return -1;
}

/* Returns a unique peer ID.
 * Returns UINT32_MAX if all possible peer ID's are taken.
 *
 * These ID's are permanently assigned to a peer when they join the group and should be
 * considered arbitrary values.
 *
 */
static uint32_t get_new_peer_id(const GC_Chat *chat)
{
    for (uint32_t i = 0; i < UINT32_MAX - 1; ++i) {
        if (get_peer_number_of_peer_id(chat, i) == -1) {
            return i;
        }
    }

    return UINT32_MAX;
}

/* Sets the password for the group (locally only).
 *
 * Returns 0 on success.
 * Returns -1 if the password is too long.
 */
static int set_gc_password_local(GC_Chat *chat, const uint8_t *passwd, uint16_t length)
{
    if (length > MAX_GC_PASSWORD_SIZE) {
        return -1;
    }

    if (passwd == nullptr || length == 0) {
        chat->shared_state.password_length = 0;
        memset(chat->shared_state.password, 0, MAX_GC_PASSWORD_SIZE);
    } else {
        chat->shared_state.password_length = length;
        memcpy(chat->shared_state.password, passwd, length);
        crypto_memlock(chat->shared_state.password, sizeof(chat->shared_state.password));
    }

    return 0;
}

/* Expands the chat_id into the extended chat public key (encryption key + signature key)
 * dest must have room for EXT_PUBLIC_KEY_SIZE bytes.
 *
 * Return 0 on success.
 * Return -1 on failure.
 */
static int expand_chat_id(uint8_t *dest, const uint8_t *chat_id)
{
    int ret = -1;

    if (dest) {
        ret = crypto_sign_ed25519_pk_to_curve25519(dest, chat_id);
        memcpy(dest + ENC_PUBLIC_KEY_SIZE, chat_id, SIG_PUBLIC_KEY_SIZE);
    }

    return ret;
}

/* Copies peer connect info from `gconn` to `addr`. */
static void copy_gc_saved_peer(const GC_Connection *gconn, GC_SavedPeerInfo *addr)
{
    gcc_copy_tcp_relay(&addr->tcp_relay, gconn);
    memcpy(&addr->ip_port, &gconn->addr.ip_port, sizeof(IP_Port));
    memcpy(addr->public_key, gconn->addr.public_key, ENC_PUBLIC_KEY_SIZE);
}

/* Return true if `saved_peer` has either a valid IP_Port or a valid TCP relay. */
static bool saved_peer_is_valid(const GC_SavedPeerInfo *saved_peer)
{
    return ipport_isset(&saved_peer->ip_port) || ipport_isset(&saved_peer->tcp_relay.ip_port);
}

/* Returns the index of the saved peers entry for `public_key`.
 * Returns -1 if key is not found.
 */
static int saved_peer_index(const GC_Chat *chat, const uint8_t *public_key)
{
    for (size_t i = 0; i < GC_MAX_SAVED_PEERS; ++i) {
        const GC_SavedPeerInfo *saved_peer = &chat->saved_peers[i];

        if (memcmp(saved_peer->public_key, public_key, ENC_PUBLIC_KEY_SIZE) == 0) {
            return i;
        }
    }

    return -1;
}

/* Returns the index of the first vacant entry in saved peers list. If `public_key` is non-null
 * and already exists in the list, its index will be returned.
 *
 * A vacant entry is an entry that does not have either an IP_port or tcp relay set (invalid),
 * or an entry containing info on a peer that is not presently online (offline).
 *
 * Invalid entries are given priority over offline entries.
 *
 * Returns -1 if there are no vacant indices.
 */
static int saved_peers_get_new_index(const GC_Chat *chat, const uint8_t *public_key)
{
    if (public_key != nullptr) {
        int idx = saved_peer_index(chat, public_key);

        if (idx != -1) {
            return idx;
        }
    }

    // first check for invalid spots
    for (size_t i = 0; i < GC_MAX_SAVED_PEERS; ++i) {
        const GC_SavedPeerInfo *saved_peer = &chat->saved_peers[i];

        if (!saved_peer_is_valid(saved_peer)) {
            return i;
        }
    }

    // now look for entries with offline peers
    for (size_t i = 0; i < GC_MAX_SAVED_PEERS; ++i) {
        const GC_SavedPeerInfo *saved_peer = &chat->saved_peers[i];

        const int peernumber = get_peer_number_of_enc_pk(chat, saved_peer->public_key, true);

        if (peernumber < 0) {
            return i;
        }
    }

    return -1;
}

/* Attempts to add `gconn` to the saved peer list. If an entry already exists it will
 * be updated.
 *
 * Older peers will only be over-written if the peer is no longer
 * present in the chat. This gives priority to more stable connections.
 *
 * This function should be called every time a new peer joins the group.
 */
static void add_gc_saved_peers(GC_Chat *chat, const GC_Connection *gconn)
{
    const int idx = saved_peers_get_new_index(chat, gconn->addr.public_key);

    if (idx == -1) {
        return;
    }

    GC_SavedPeerInfo *saved_peer = &chat->saved_peers[idx];
    copy_gc_saved_peer(gconn, saved_peer);
}

/* Finds the first vacant spot in the saved peers list and fills it with a present
 * peer who isn't already in the list.
 *
 * This function should be called after a confirmed peer exits the group.
 */
static void refresh_gc_saved_peers(GC_Chat *chat)
{
    const int idx = saved_peers_get_new_index(chat, nullptr);

    if (idx == -1) {
        return;
    }

    for (uint32_t i = 1; i < chat->numpeers; ++i) {
        const GC_Connection *gconn = gcc_get_connection(chat, i);

        if (gconn == nullptr) {
            continue;
        }

        if (!gconn->confirmed) {
            continue;
        }

        if (saved_peer_index(chat, gconn->addr.public_key) == -1) {
            GC_SavedPeerInfo *saved_peer = &chat->saved_peers[idx];
            copy_gc_saved_peer(gconn, saved_peer);
            return;
        }
    }
}

/* Returns the number of confirmed peers in peerlist. */
static uint32_t get_gc_confirmed_numpeers(const GC_Chat *chat)
{
    uint32_t count = 0;

    for (uint32_t i = 0; i < chat->numpeers; ++i) {
        if (chat->gcc[i].confirmed) {
            ++count;
        }
    }

    return count;
}

static int sign_gc_shared_state(GC_Chat *chat);
static int broadcast_gc_mod_list(const GC_Chat *chat);
static int broadcast_gc_shared_state(const GC_Chat *chat);
static int update_gc_sanctions_list(GC_Chat *chat, const uint8_t *public_sig_key);
static int update_gc_topic(GC_Chat *chat, const uint8_t *public_sig_key);
static int send_gc_set_observer(const GC_Chat *chat, const uint8_t *target_pk, const uint8_t *sanction_data,
                                uint32_t length, bool add_obs);

/* Returns true if peer designated by `peer_number` is in the moderator list or is the founder. */
static bool peer_is_moderator(const GC_Chat *chat, uint32_t peer_number)
{
    const GC_Connection *gconn = gcc_get_connection(chat, peer_number);

    if (gconn == nullptr) {
        return false;
    }

    return mod_list_verify_sig_pk(chat, get_sig_pk(gconn->addr.public_key));
}

/* Returns true if peer designated by `peer_number` is in the sanctions list as an observer. */
static bool peer_is_observer(const GC_Chat *chat, uint32_t peer_number)
{
    const GC_Connection *gconn = gcc_get_connection(chat, peer_number);

    if (gconn == nullptr) {
        return false;
    }

    return sanctions_list_is_observer(chat, get_enc_key(gconn->addr.public_key));
}

/* Returns true if peer designated by `peer_number` is the group founder. */
static bool peer_is_founder(const GC_Chat *chat, uint32_t peer_number)
{

    const GC_Connection *gconn = gcc_get_connection(chat, peer_number);

    if (gconn == nullptr) {
        return false;
    }

    return memcmp(chat->shared_state.founder_public_key, gconn->addr.public_key, ENC_PUBLIC_KEY_SIZE) == 0;
}

/* Iterates through the peerlist and updates group roles according to the
 * current group state. This should be called every time the moderator list
 * or sanctions list changes, after the change takes place.
 *
 * Return 0 on success.
 * Return -1 if there are conflicts.
 */
static int update_gc_peer_roles(GC_Chat *chat)
{
    bool conflicts = false;

    for (uint32_t i = 0; i < chat->numpeers; ++i) {
        const GC_Connection *gconn = gcc_get_connection(chat, i);

        if (gconn == nullptr) {
            continue;
        }

        const uint8_t is_founder = peer_is_founder(chat, i);
        const uint8_t is_observer = peer_is_observer(chat, i);
        const uint8_t is_moderator = peer_is_moderator(chat, i) && !is_founder;
        const uint8_t is_user = !(is_founder || is_moderator || is_observer);

        if (is_observer && is_moderator) {
            conflicts = true;
        }

        if (is_user) {
            chat->group[i].role = GR_USER;
            continue;
        }

        if (is_founder) {
            chat->group[i].role = GR_FOUNDER;
            continue;
        }

        // it is possible for these two roles not to be mutually exclusive if we get
        // multiple role changes simultaneously so we prioritize observer because
        // conflicts seem to be resolved better this way
        if (is_moderator && chat->group[i].role != GR_MODERATOR) {
            chat->group[i].role = GR_MODERATOR;
        }

        if (is_observer && chat->group[i].role != GR_OBSERVER) {
            chat->group[i].role = GR_OBSERVER;
        }
    }

    return conflicts ? -1 : 0;
}

/* Removes the first found offline mod from the mod list.
 *
 * Broadcasts the shared state and moderator list on success, as well as the updated
 * sanctions list if necessary.
 *
 * TODO: Make this smarter in who to remove (e.g. the mod who hasn't been seen online in the longest time)
 *
 * Returns 0 on success.
 * Returns -1 on failure or if no mods were removed.
 */
static int prune_gc_mod_list(GC_Chat *chat)
{
    if (chat->moderation.num_mods == 0) {
        return 0;
    }

    uint8_t public_sig_key[SIG_PUBLIC_KEY_SIZE];
    bool pruned_mod = false;

    for (uint16_t i = 0; i < chat->moderation.num_mods; ++i) {
        if (get_peer_number_of_sig_pk(chat, chat->moderation.mod_list[i]) == -1) {
            memcpy(public_sig_key, chat->moderation.mod_list[i], SIG_PUBLIC_KEY_SIZE);

            if (mod_list_remove_index(chat, i) == -1) {
                continue;
            }

            pruned_mod = true;
            break;
        }
    }

    if (!pruned_mod) {
        return -1;
    }

    if (mod_list_make_hash(chat, chat->shared_state.mod_list_hash) == -1) {
        return -1;
    }

    if (sign_gc_shared_state(chat) == -1) {
        return -1;
    }

    if (broadcast_gc_shared_state(chat) == -1) {
        return -1;
    }

    if (broadcast_gc_mod_list(chat) == -1) {
        return -1;
    }

    if (update_gc_sanctions_list(chat, public_sig_key) == -1) {
        return -1;
    }

    if (update_gc_topic(chat, public_sig_key) == -1) {
        return -1;
    }

    return 0;
}

/* Removes the first found offline sanctioned peer from the sanctions list and sends the
 * event to the rest of the group.
 *
 * Returns 0 on success.
 * Returns -1 on failure or if no sanctioned peers were offline.
 */
static int prune_gc_sanctions_list(GC_Chat *chat)
{
    if (chat->moderation.num_sanctions == 0) {
        return 0;
    }

    const GC_Sanction *sanction = nullptr;
    uint8_t target_ext_pk[ENC_PUBLIC_KEY_SIZE + SIG_PUBLIC_KEY_SIZE];

    for (uint16_t i = 0; i < chat->moderation.num_sanctions; ++i) {
        int peer_number = get_peer_number_of_enc_pk(chat, chat->moderation.sanctions[i].info.target_pk, true);

        if (peer_number == -1) {
            sanction = &chat->moderation.sanctions[i];
            memcpy(target_ext_pk, sanction->info.target_pk, ENC_PUBLIC_KEY_SIZE);
            memcpy(target_ext_pk + ENC_PUBLIC_KEY_SIZE, sanction->public_sig_key, SIG_PUBLIC_KEY_SIZE);
            break;
        }
    }

    if (sanction == nullptr) {
        return -1;
    }

    if (sanctions_list_remove_observer(chat, sanction->info.target_pk, nullptr) == -1) {
        LOGGER_WARNING(chat->logger, "Failed to remove entry from observer list");
        return -1;
    }

    sanction = nullptr;

    uint8_t data[GC_SANCTIONS_CREDENTIALS_SIZE];
    const uint16_t length = sanctions_creds_pack(&chat->moderation.sanctions_creds, data, sizeof(data));

    if (length != GC_SANCTIONS_CREDENTIALS_SIZE) {
        LOGGER_ERROR(chat->logger, "Failed to pack credentials (invlaid length: %u)", length);
        return -1;
    }

    if (send_gc_set_observer(chat, target_ext_pk, data, length, false) == -1) {
        LOGGER_WARNING(chat->logger, "Failed to broadcast set observer");
        return -1;
    }

    return 0;
}

/* Size of peer data that we pack for transfer (nick length must be accounted for separately).
 * packed data includes: nick, nick length, status, role
 */
#define PACKED_GC_PEER_SIZE (MAX_GC_NICK_SIZE + sizeof(uint16_t) + sizeof(uint8_t) + sizeof(uint8_t))

/* Packs peer info into data of maxlength length.
 *
 * Return length of packed peer on success.
 * Return -1 on failure.
 */
static int pack_gc_peer(uint8_t *data, uint16_t length, const GC_GroupPeer *peer)
{
    if (PACKED_GC_PEER_SIZE > length) {
        return -1;
    }

    uint32_t packed_len = 0;

    net_pack_u16(data + packed_len, peer->nick_length);
    packed_len += sizeof(uint16_t);
    memcpy(data + packed_len, peer->nick, MAX_GC_NICK_SIZE);
    packed_len += MAX_GC_NICK_SIZE;
    memcpy(data + packed_len, &peer->status, sizeof(uint8_t));
    packed_len += sizeof(uint8_t);
    memcpy(data + packed_len, &peer->role, sizeof(uint8_t));
    packed_len += sizeof(uint8_t);

    return packed_len;
}

/* Unpacks peer info of size length into peer.
 *
 * Returns the length of processed data on success.
 * Returns -1 on failure.
 */
static int unpack_gc_peer(GC_GroupPeer *peer, const uint8_t *data, uint16_t length)
{
    if (PACKED_GC_PEER_SIZE > length) {
        return -1;
    }

    uint32_t len_processed = 0;

    net_unpack_u16(data + len_processed, &peer->nick_length);
    len_processed += sizeof(uint16_t);
    peer->nick_length = min_u16(MAX_GC_NICK_SIZE, peer->nick_length);
    memcpy(peer->nick, data + len_processed, MAX_GC_NICK_SIZE);
    len_processed += MAX_GC_NICK_SIZE;
    memcpy(&peer->status, data + len_processed, sizeof(uint8_t));
    len_processed += sizeof(uint8_t);
    memcpy(&peer->role, data + len_processed, sizeof(uint8_t));
    len_processed += sizeof(uint8_t);

    return len_processed;
}

/* Packs shared_state into data. data must have room for at least GC_PACKED_SHARED_STATE_SIZE bytes.
 *
 * Returns packed data length.
 */
static uint16_t pack_gc_shared_state(uint8_t *data, uint16_t length, const GC_SharedState *shared_state)
{
    if (length < GC_PACKED_SHARED_STATE_SIZE) {
        return 0;
    }

    const uint8_t privacy_state = shared_state->privacy_state;
    uint16_t packed_len = 0;

    // version is always first
    net_pack_u32(data + packed_len, shared_state->version);
    packed_len += sizeof(uint32_t);

    memcpy(data + packed_len, shared_state->founder_public_key, EXT_PUBLIC_KEY_SIZE);
    packed_len += EXT_PUBLIC_KEY_SIZE;
    net_pack_u32(data + packed_len, shared_state->maxpeers);
    packed_len += sizeof(uint32_t);
    net_pack_u16(data + packed_len, shared_state->group_name_len);
    packed_len += sizeof(uint16_t);
    memcpy(data + packed_len, shared_state->group_name, MAX_GC_GROUP_NAME_SIZE);
    packed_len += MAX_GC_GROUP_NAME_SIZE;
    memcpy(data + packed_len, &privacy_state, sizeof(uint8_t));
    packed_len += sizeof(uint8_t);
    net_pack_u16(data + packed_len, shared_state->password_length);
    packed_len += sizeof(uint16_t);
    memcpy(data + packed_len, shared_state->password, MAX_GC_PASSWORD_SIZE);
    packed_len += MAX_GC_PASSWORD_SIZE;
    memcpy(data + packed_len, shared_state->mod_list_hash, GC_MODERATION_HASH_SIZE);
    packed_len += GC_MODERATION_HASH_SIZE;
    net_pack_u32(data + packed_len, shared_state->topic_lock);
    packed_len += sizeof(uint32_t);

    return packed_len;
}

/* Unpacks shared state data into shared_state. data must contain at least GC_PACKED_SHARED_STATE_SIZE bytes.
 *
 * Returns the length of processed data.
 */
static uint16_t unpack_gc_shared_state(GC_SharedState *shared_state, const uint8_t *data, uint16_t length)
{
    if (length < GC_PACKED_SHARED_STATE_SIZE) {
        return 0;
    }

    uint16_t len_processed = 0;

    // version is always first
    net_unpack_u32(data + len_processed, &shared_state->version);
    len_processed += sizeof(uint32_t);

    memcpy(shared_state->founder_public_key, data + len_processed, EXT_PUBLIC_KEY_SIZE);
    len_processed += EXT_PUBLIC_KEY_SIZE;
    net_unpack_u32(data + len_processed, &shared_state->maxpeers);
    len_processed += sizeof(uint32_t);
    net_unpack_u16(data + len_processed, &shared_state->group_name_len);
    shared_state->group_name_len = min_u16(shared_state->group_name_len, MAX_GC_GROUP_NAME_SIZE);
    len_processed += sizeof(uint16_t);
    memcpy(shared_state->group_name, data + len_processed, MAX_GC_GROUP_NAME_SIZE);
    len_processed += MAX_GC_GROUP_NAME_SIZE;

    uint8_t privacy_state;
    memcpy(&privacy_state, data + len_processed, sizeof(uint8_t));
    len_processed += sizeof(uint8_t);

    net_unpack_u16(data + len_processed, &shared_state->password_length);
    len_processed += sizeof(uint16_t);
    memcpy(shared_state->password, data + len_processed, MAX_GC_PASSWORD_SIZE);
    len_processed += MAX_GC_PASSWORD_SIZE;
    memcpy(shared_state->mod_list_hash, data + len_processed, GC_MODERATION_HASH_SIZE);
    len_processed += GC_MODERATION_HASH_SIZE;
    net_unpack_u32(data + len_processed, &shared_state->topic_lock);
    len_processed += sizeof(uint32_t);

    shared_state->privacy_state = (Group_Privacy_State) privacy_state;

    return len_processed;
}

/* Packs topic info into data. data must have room for at least
 * topic length + GC_MIN_PACKED_TOPIC_INFO_SIZE bytes.
 *
 * Returns packed data length.
 */
static uint16_t pack_gc_topic_info(uint8_t *data, uint16_t length, const GC_TopicInfo *topic_info)
{
    if (length < topic_info->length + GC_MIN_PACKED_TOPIC_INFO_SIZE) {
        return 0;
    }

    uint16_t packed_len = 0;

    net_pack_u32(data + packed_len, topic_info->version);
    packed_len += sizeof(uint32_t);
    net_pack_u16(data + packed_len, topic_info->checksum);
    packed_len += sizeof(uint16_t);
    net_pack_u16(data + packed_len, topic_info->length);
    packed_len += sizeof(uint16_t);
    memcpy(data + packed_len, topic_info->topic, topic_info->length);
    packed_len += topic_info->length;
    memcpy(data + packed_len, topic_info->public_sig_key, SIG_PUBLIC_KEY_SIZE);
    packed_len += SIG_PUBLIC_KEY_SIZE;

    return packed_len;
}

/* Unpacks topic info into `topic_info`.
 *
 * Returns -1 on failure.
 * Returns the length of the processed data on success.
 */
static int unpack_gc_topic_info(GC_TopicInfo *topic_info, const uint8_t *data, uint16_t length)
{
    if (length < sizeof(uint16_t) + sizeof(uint16_t) + sizeof(uint32_t)) {
        return -1;
    }

    uint16_t len_processed = 0;

    net_unpack_u32(data + len_processed, &topic_info->version);
    len_processed += sizeof(uint32_t);
    net_unpack_u16(data + len_processed, &topic_info->checksum);
    len_processed += sizeof(uint16_t);
    net_unpack_u16(data + len_processed, &topic_info->length);
    len_processed += sizeof(uint16_t);

    if (topic_info->length > MAX_GC_TOPIC_SIZE) {
        topic_info->length = MAX_GC_TOPIC_SIZE;
    }

    if (length - len_processed < topic_info->length + SIG_PUBLIC_KEY_SIZE) {
        return -1;
    }

    if (topic_info->length > 0) {
        memcpy(topic_info->topic, data + len_processed, topic_info->length);
        len_processed += topic_info->length;
    }

    memcpy(topic_info->public_sig_key, data + len_processed, SIG_PUBLIC_KEY_SIZE);
    len_processed += SIG_PUBLIC_KEY_SIZE;

    return len_processed;
}

/* Creates a shared state packet and puts it in data.
 * Packet includes self pk hash, shared state signature, and packed shared state info.
 * data must have room for at least GC_SHARED_STATE_ENC_PACKET_SIZE bytes.
 *
 * Returns packet length on success.
 * Returns -1 on failure.
 */
static int make_gc_shared_state_packet(const GC_Chat *chat, uint8_t *data, uint16_t length)
{
    if (length < GC_SHARED_STATE_ENC_PACKET_SIZE) {
        return -1;
    }

    memcpy(data, chat->shared_state_sig, SIGNATURE_SIZE);
    size_t header_len = SIGNATURE_SIZE;

    const uint16_t packed_len = pack_gc_shared_state(data + header_len, length - header_len, &chat->shared_state);

    if (packed_len != GC_PACKED_SHARED_STATE_SIZE) {
        return -1;
    }

    return header_len + packed_len;
}

/* Creates a signature for the group's shared state in packed form and increments the version.
 * This should only be called by the founder.
 *
 * Returns 0 on success.
 * Returns -1 on failure.
 */
static int sign_gc_shared_state(GC_Chat *chat)
{
    if (!self_gc_is_founder(chat)) {
        LOGGER_ERROR(chat->logger, "Failed to sign shared state (invalid permission)");
        return -1;
    }

    if (chat->shared_state.version != UINT32_MAX) { /* improbable, but an overflow would break everything */
        ++chat->shared_state.version;
    } else {
        LOGGER_WARNING(chat->logger, "Shared state version wraparound");
    }

    uint8_t shared_state[GC_PACKED_SHARED_STATE_SIZE];
    const uint16_t packed_len = pack_gc_shared_state(shared_state, sizeof(shared_state), &chat->shared_state);

    if (packed_len != GC_PACKED_SHARED_STATE_SIZE) {
        --chat->shared_state.version;
        LOGGER_ERROR(chat->logger, "Failed to pack shared state");
        return -1;
    }

    const int ret = crypto_sign_detached(chat->shared_state_sig, nullptr, shared_state, packed_len,
                                         get_sig_sk(chat->chat_secret_key));

    if (ret != 0) {
        --chat->shared_state.version;
        LOGGER_ERROR(chat->logger, "Failed to sign shared state (%d)", ret);
    }

    return ret;
}

/* Decrypts data using the shared key associated with `gconn`. The packet payload should
 * begin with a nonce.
 *
 * `message_id` should be set to NULL for lossy packets.
 *
 * Returns length of the plaintext data on success.
 * Returns -1 on decryption failure.
 * Returns -2 if length is invalid.
 */
static int group_packet_unwrap(const Logger *logger, const GC_Connection *gconn, uint8_t *data, uint64_t *message_id,
                               uint8_t *packet_type, const uint8_t *packet, uint16_t length)
{
    if (length <= CRYPTO_NONCE_SIZE) {
        LOGGER_FATAL(logger, "Invalid packet length: %u", length);
        return -1;
    }

    uint8_t plain[MAX_GC_PACKET_SIZE];
    int plain_len = decrypt_data_symmetric(gconn->session_shared_key, packet, packet + CRYPTO_NONCE_SIZE,
                                           length - CRYPTO_NONCE_SIZE, plain);

    if (plain_len <= 0) {
        return -1;
    }

    const int min_plain_len = message_id != nullptr ? 1 + GC_MESSAGE_ID_BYTES : 1;

    /* remove padding */
    uint8_t *real_plain = plain;

    while (real_plain[0] == 0) {
        ++real_plain;
        --plain_len;

        if (plain_len < min_plain_len) {
            return -2;
        }
    }

    uint32_t header_len = sizeof(uint8_t);
    *packet_type = real_plain[0];
    plain_len -= sizeof(uint8_t);

    if (message_id != nullptr) {
        net_unpack_u64(real_plain + sizeof(uint8_t), message_id);
        plain_len -= GC_MESSAGE_ID_BYTES;
        header_len += GC_MESSAGE_ID_BYTES;
    }

    memcpy(data, real_plain + header_len, plain_len);

    return plain_len;
}

int group_packet_wrap(const Logger *logger, const uint8_t *self_pk, const uint8_t *shared_key, uint8_t *packet,
                      uint32_t packet_size, const uint8_t *data, uint32_t length, uint64_t message_id,
                      uint8_t gp_packet_type, const uint8_t *target_pk, uint8_t net_packet_type)
{
    const uint16_t padding_len = group_packet_padding_length(length);

    if (length + padding_len + CRYPTO_MAC_SIZE + 1 + ENC_PUBLIC_KEY_SIZE + CRYPTO_NONCE_SIZE > packet_size) {
        return -1;
    }

    uint8_t plain[MAX_GC_PACKET_SIZE] = {0};

    uint32_t enc_header_len = sizeof(uint8_t);
    plain[padding_len] = gp_packet_type;

    if (net_packet_type == NET_PACKET_GC_LOSSLESS) {
        net_pack_u64(plain + padding_len + sizeof(uint8_t), message_id);
        enc_header_len += GC_MESSAGE_ID_BYTES;
    }

    if (length > 0 && data != nullptr) {
        memcpy(plain + padding_len + enc_header_len, data, length);
    }

    uint8_t nonce[CRYPTO_NONCE_SIZE];
    random_nonce(nonce);

    const uint16_t plain_len = padding_len + enc_header_len + length;
    const size_t encrypt_buf_size = plain_len + CRYPTO_MAC_SIZE;

    uint8_t *encrypt = (uint8_t *)malloc(encrypt_buf_size);

    if (encrypt == nullptr) {
        return -1;
    }

    const int enc_len = encrypt_data_symmetric(shared_key, nonce, plain, plain_len, encrypt);

    if (enc_len != encrypt_buf_size) {
        LOGGER_ERROR(logger, "encryption failed. packet type: %d, enc_len: %d", gp_packet_type, enc_len);
        free(encrypt);
        return -1;
    }

    packet[0] = net_packet_type;
    memcpy(packet + 1, self_pk, ENC_PUBLIC_KEY_SIZE);
    memcpy(packet + 1 + ENC_PUBLIC_KEY_SIZE, nonce, CRYPTO_NONCE_SIZE);
    memcpy(packet + 1 + ENC_PUBLIC_KEY_SIZE + CRYPTO_NONCE_SIZE, encrypt, enc_len);

    free(encrypt);

    return 1 + ENC_PUBLIC_KEY_SIZE + CRYPTO_NONCE_SIZE + enc_len;
}

/* Sends a lossy packet to peer_number in chat instance.
 *
 * Returns 0 on success.
 * Returns -1 on failure.
 */
static int send_lossy_group_packet(const GC_Chat *chat, const GC_Connection *gconn, const uint8_t *data,
                                   uint32_t length, uint8_t packet_type)
{
    if (!gconn->handshaked || gconn->pending_delete) {
        return -1;
    }

    if (data == nullptr || length == 0) {
        return -1;
    }

    uint8_t packet[MAX_GC_PACKET_SIZE];
    const int len = group_packet_wrap(chat->logger, chat->self_public_key, gconn->session_shared_key, packet,
                                      sizeof(packet), data, length, 0, packet_type, gconn->addr.public_key,
                                      NET_PACKET_GC_LOSSY);

    if (len == -1) {
        LOGGER_WARNING(chat->logger, "group_packet_wrap failed (type: %u, len: %d)", packet_type, len);
        return -1;
    }

    if (gcc_send_packet(chat, gconn, packet, len) == -1) {
        return -1;
    }

    return 0;
}

/* Sends a lossless packet to peer_number in chat instance.
 *
 * Returns 0 on success.
 * Returns -1 on failure.
 */
static int send_lossless_group_packet(const GC_Chat *chat, GC_Connection *gconn, const uint8_t *data, uint32_t length,
                                      uint8_t packet_type)
{
    if (!gconn->handshaked || gconn->pending_delete) {
        return -1;
    }

    const uint64_t message_id = gconn->send_message_id;

    if (gcc_add_to_send_array(chat->logger, chat->mono_time, gconn, data, length, packet_type) == -1) {
        LOGGER_WARNING(chat->logger, "gcc_add_to_send_array() failed (type: %u, length: %d)", packet_type, length);
        return -1;
    }

    if (gcc_encrypt_and_send_lossless_packet(chat, gconn, data, length, message_id, packet_type) == -1) {
        return -1;
    }

    return 0;
}

/* Sends a group sync request to peer.
 *
 * Returns 0 on success.
 * Returns -1 on failure.
 */
static int send_gc_sync_request(const GC_Chat *chat, GC_Connection *gconn, uint16_t sync_flags)
{
    uint8_t data[(sizeof(uint16_t) * 2) + MAX_GC_PASSWORD_SIZE];
    uint32_t length = sizeof(uint16_t);

    net_pack_u16(data, sync_flags);

    if (chat_is_password_protected(chat)) {
        net_pack_u16(data + length, chat->shared_state.password_length);
        length += sizeof(uint16_t);

        memcpy(data + (sizeof(uint16_t) * 2), chat->shared_state.password, MAX_GC_PASSWORD_SIZE);
        length += MAX_GC_PASSWORD_SIZE;
    }

    return send_lossless_group_packet(chat, gconn, data, length, GP_SYNC_REQUEST);
}

/* Sends a sync response packet to peer desingnated by `gconn`.
 *
 * Return 0 on succes.
 * Return -1 on failure.
 */
static int send_gc_sync_response(const GC_Chat *chat, GC_Connection *gconn, const uint8_t *data, uint32_t length)
{
    return send_lossless_group_packet(chat, gconn, data, length, GP_SYNC_RESPONSE);
}

static int send_gc_peer_exchange(const GC_Session *c, const GC_Chat *chat, GC_Connection *gconn);
static int send_gc_handshake_packet(const GC_Chat *chat, GC_Connection *gconn, uint8_t handshake_type,
                                    uint8_t request_type);
static int send_gc_oob_handshake_request(const GC_Chat *chat, GC_Connection *gconn);

/* Unpacks a sync announce. If the announced peer is not already in our peer list, we attempt to
 * initiate a peer info exchange with them.
 *
 * Return 0 on success (whether or not the peer was added).
 * Return -1 on failure.
 */
static int unpack_gc_sync_announce(const Messenger *m, const GC_Chat *chat, uint32_t group_number, const uint8_t *data,
                                   const uint32_t length)
{
    GC_Announce announce = (GC_Announce) {
        0
    };

    const int unpacked_announces = gca_unpack_announces_list(chat->logger, data, length, &announce, 1);

    if (unpacked_announces <= 0) {
        LOGGER_WARNING(chat->logger, "Failed to unpack announces: %d", unpacked_announces);
        return -1;
    }

    if (memcmp(announce.peer_public_key, chat->self_public_key, ENC_PUBLIC_KEY_SIZE) == 0) {
        LOGGER_WARNING(chat->logger, "Attempted to unpack our own announce");
        return 0;
    }

    if (!gca_is_valid_announce(&announce)) {
        LOGGER_WARNING(chat->logger, "got invalid announce");
        return -1;
    }

    const IP_Port *ip_port = announce.ip_port_is_set ? &announce.ip_port : nullptr;
    const int new_peer_number = peer_add(m, group_number, ip_port, announce.peer_public_key);

    if (new_peer_number == -1) {
        LOGGER_ERROR(chat->logger, "peer_add() failed");
        return -1;
    }

    if (new_peer_number == -2) {  // peer already added
        return 0;
    }

    if (new_peer_number > 0) {
        GC_Connection *new_gconn = gcc_get_connection(chat, new_peer_number);

        if (new_gconn == nullptr) {
            return -1;
        }

        uint32_t added_tcp_relays = 0;

        for (uint8_t i = 0; i < announce.tcp_relays_count; ++i) {
            int add_tcp_result = add_tcp_relay_connection(chat->tcp_conn, new_gconn->tcp_connection_num,
                                 announce.tcp_relays[i].ip_port,
                                 announce.tcp_relays[i].public_key);

            if (add_tcp_result == -1) {
                continue;
            }

            if (gcc_save_tcp_relay(new_gconn, &announce.tcp_relays[i]) == 0) {
                ++added_tcp_relays;
            }
        }

        if (!announce.ip_port_is_set && added_tcp_relays == 0) {
            gcc_mark_for_deletion(new_gconn, chat->tcp_conn, GC_EXIT_TYPE_DISCONNECTED, nullptr, 0);
            LOGGER_WARNING(chat->logger, "Sync error: Invalid peer connection info");
            return -1;
        }

        new_gconn->pending_handshake_type = HS_PEER_INFO_EXCHANGE;

        return 0;
    }

    LOGGER_WARNING(chat->logger, "got impossible return value %d", new_peer_number);

    return -1;
}

/* Handles a sync response packet.
 *
 * Return 0 on success.
 * Return -1 if group number is invalid.
 * Return -2 if peer number is invalid.
 * Return -3 if the group is full and the peer cannot be added to our peer list.
 */
static int handle_gc_sync_response(Messenger *m, int group_number, int peer_number, const uint8_t *data,
                                   uint32_t length, void *userdata)
{
    const GC_Session *c = m->group_handler;
    GC_Chat *chat = gc_get_group(c, group_number);

    if (chat == nullptr) {
        return -1;
    }

    if (chat->connection_state == CS_CONNECTED && get_gc_confirmed_numpeers(chat) >= chat->shared_state.maxpeers) {
        return -3;
    }

    if (length > 0) {
        unpack_gc_sync_announce(m, chat, group_number, data, length);
    }

    GC_Connection *gconn = gcc_get_connection(chat, peer_number);

    if (gconn == nullptr) {
        return -2;
    }

    chat->connection_state = CS_CONNECTED;
    send_gc_peer_exchange(c, chat, gconn);

    if (c->self_join && chat->time_connected == 0) {
        (*c->self_join)(m, group_number, userdata);
        chat->time_connected = mono_time_get(chat->mono_time);
    }

    return 0;
}

static int get_gc_peer_public_key(const GC_Chat *chat, uint32_t peer_number, uint8_t *public_key);
static int send_peer_shared_state(const GC_Chat *chat, GC_Connection *gconn);
static int send_peer_mod_list(const GC_Chat *chat, GC_Connection *gconn);
static int send_peer_sanctions_list(const GC_Chat *chat, GC_Connection *gconn);
static int send_peer_topic(const GC_Chat *chat, GC_Connection *gconn);


/* Creates a sync announce for peer designated by `gconn` and puts it in `announce`.
 *
 * Returns true if announce was successfully created.
 */
static bool create_sync_announce(const GC_Chat *chat, GC_Connection *gconn, uint32_t peer_number, GC_Announce *announce)
{
    if (chat == nullptr || gconn == nullptr) {
        return false;
    }

    if (gconn->tcp_relays_count > 0) {
        if (gcc_copy_tcp_relay(&announce->tcp_relays[0], gconn) == 0) {
            announce->tcp_relays_count = 1;
        }
    }

    get_gc_peer_public_key(chat, peer_number, announce->peer_public_key);

    if (gcc_ip_port_is_set(gconn)) {
        memcpy(&announce->ip_port, &gconn->addr.ip_port, sizeof(IP_Port));
        announce->ip_port_is_set = true;
    } else {
        announce->ip_port_is_set = false;
    }

    return true;
}

static int sync_response_send_peers(const GC_Chat *chat, uint32_t peer_number)
{
    GC_Connection *gconn = gcc_get_connection(chat, peer_number);

    if (gconn == nullptr) {
        return -1;
    }

    uint8_t response[MAX_GC_PACKET_SIZE];
    uint32_t reseponse_len = 0;

    uint32_t num_announces = 0;

    for (uint32_t i = 1; i < chat->numpeers; ++i) {
        GC_Connection *peer_gconn = gcc_get_connection(chat, i);

        if (peer_gconn == nullptr || !peer_gconn->confirmed) {
            continue;
        }

        if (peer_gconn->public_key_hash == gconn->public_key_hash || i == peer_number) {
            continue;
        }

        GC_Announce announce = (GC_Announce) {
            0
        };

        if (!create_sync_announce(chat, peer_gconn, i, &announce)) {
            continue;
        }

        const int packed_length = gca_pack_announce(chat->logger,
                                  response + reseponse_len,
                                  sizeof(response) - reseponse_len,
                                  &announce);

        if (packed_length < 0) {
            LOGGER_WARNING(chat->logger, "Failed to pack announce: %d", packed_length);
            continue;
        }

        reseponse_len += packed_length;

        if (send_gc_sync_response(chat, gconn, response, reseponse_len) == -1) {
            LOGGER_WARNING(chat->logger, "Failed to send peer announce info");
            continue;
        }

        ++num_announces;
    }

    if (num_announces == 0) {
        // we send an empty sync response even if we didn't send any peers as an acknowledgement
        if (send_gc_sync_response(chat, gconn, nullptr, 0) == -1) {
            LOGGER_WARNING(chat->logger, "Failed to send peer announce info");
            return -6;
        }
    }

    return 0;
}

/* Sends group state specified by `sync_flags` peer designated by `peer_number`.
 *
 * Return 0 on success.
 * Return -1 if any one fails.
 */
static int sync_response_send_state(const GC_Chat *chat, uint32_t peer_number, uint16_t sync_flags)
{
    GC_Connection *gconn = gcc_get_connection(chat, peer_number);

    if (gconn == nullptr) {
        return -1;
    }

    /* Do not change the order of these four send calls or else */
    if (sync_flags & GF_STATE) {
        if (send_peer_shared_state(chat, gconn) == -1) {
            LOGGER_WARNING(chat->logger, "Failed to send shared state");
            return -1;
        }

        if (send_peer_mod_list(chat, gconn) == -1) {
            LOGGER_WARNING(chat->logger, "Failed to send mod list");
            return -1;
        }

        if (send_peer_sanctions_list(chat, gconn) == -1) {
            LOGGER_WARNING(chat->logger, "Failed to send sanctions list");
            return -1;
        }

        gconn->last_sync_response = mono_time_get(chat->mono_time);
    }

    if (sync_flags & GF_TOPIC) {
        if (send_peer_topic(chat, gconn) == -1) {
            LOGGER_WARNING(chat->logger, "Failed to send topic");
            return -1;
        }

        gconn->last_sync_response = mono_time_get(chat->mono_time);
    }

    if (sync_flags & GF_PEERS) {
        if (sync_response_send_peers(chat, peer_number) == -1) {
            return -1;
        }

        gconn->last_sync_response = mono_time_get(chat->mono_time);
    }

    return 0;
}

/* Handles a sync request packet and sends a response containing the peer list.
 *
 * May send addition group info in separate packets, including the topic, shared state, mod list,
 * and sanctions list, if respective sync flags are set.
 *
 * If the group is password protected the password in the request data must first be verified.
 *
 * Return 0 if packet is handled correctly.
 * Return -1 if packet is invalid size.
 * Return -2 if group number is invalid.
 * Return -3 if password is invalid.
 * Return -4 if we fail to send a response packet.
 */
static int handle_gc_sync_request(const Messenger *m, int group_number, int peer_number,
                                  GC_Connection *gconn, const uint8_t *data, uint32_t length)
{
    if (length < sizeof(uint16_t)) {
        return -1;
    }

    const GC_Chat *chat = gc_get_group(m->group_handler, group_number);

    if (chat == nullptr) {
        return -2;
    }

    if (chat->numpeers <= 1) {
        LOGGER_DEBUG(m->log, "Got sync request with empty peer list?");
        return 0;
    }

    if (chat->shared_state.version == 0) {
        LOGGER_DEBUG(m->log, "Got sync request with uninitialized state");
        return 0;
    }

    if (!mono_time_is_timeout(chat->mono_time, gconn->last_sync_response, GC_SYNC_REQUEST_LIMIT)) {
        LOGGER_DEBUG(m->log, "sync request rate limit for peer %d", peer_number);
        return 0;
    }

    uint16_t sync_flags;
    net_unpack_u16(data, &sync_flags);

    if (chat_is_password_protected(chat)) {
        if (length < (sizeof(uint16_t) * 2) + MAX_GC_PASSWORD_SIZE) {
            return -3;
        }

        uint16_t password_length;
        net_unpack_u16(data + sizeof(uint16_t), &password_length);

        if (!validate_password(chat, data + (sizeof(uint16_t) * 2), password_length)) {
            LOGGER_WARNING(m->log, "Invalid password");
            return -3;
        }
    }

    if (sync_response_send_state(chat, peer_number, sync_flags) == -1) {
        return -4;
    }

    return 0;
}

static void copy_self(const GC_Chat *chat, GC_GroupPeer *peer);
static int send_gc_peer_info_request(const GC_Chat *chat, GC_Connection *gconn);


/* Shares our TCP relays with peer and adds shared relays to our connection with them.
 *
 * Returns 0 on success.
 * Returns -1 on failure.
 */
static int send_gc_tcp_relays(const Mono_Time *mono_time, const GC_Chat *chat, GC_Connection *gconn)
{
    Node_format tcp_relays[GCC_MAX_TCP_SHARED_RELAYS];
    const uint32_t num_tcp_relays = tcp_copy_connected_relays(chat->tcp_conn, tcp_relays, GCC_MAX_TCP_SHARED_RELAYS);

    if (num_tcp_relays == 0) {
        return 0;
    }

    uint8_t data[sizeof(tcp_relays)];
    uint32_t length = 0;

    for (uint32_t i = 0; i < num_tcp_relays; ++i) {
        add_tcp_relay_connection(chat->tcp_conn, gconn->tcp_connection_num, tcp_relays[i].ip_port, tcp_relays[i].public_key);
    }

    const int nodes_len = pack_nodes(data + length, sizeof(data) - length, tcp_relays, num_tcp_relays);

    if (nodes_len <= 0) {
        return -1;
    }

    length += nodes_len;

    if (send_lossless_group_packet(chat, gconn, data, length, GP_TCP_RELAYS) == -1) {
        LOGGER_ERROR(chat->logger, "Failed to send tcp relays");
        return -1;
    }

    return 0;
}

/* Adds a peer's shared TCP relays to our connection with them.
 *
 * Return 0 if packet is handled correctly.
 * Return -1 if packet is invalid size.
 * Return -2 if group number is invalid.
 * Return -3 if packet contained invalid data.
 */
static int handle_gc_tcp_relays(const Messenger *m, int group_number, GC_Connection *gconn, const uint8_t *data,
                                uint32_t length)
{
    if (length == 0) {
        return -1;
    }

    const GC_Session *c = m->group_handler;
    GC_Chat *chat = gc_get_group(c, group_number);

    if (chat == nullptr) {
        return -2;
    }

    Node_format tcp_relays[GCC_MAX_TCP_SHARED_RELAYS];
    const int num_nodes = unpack_nodes(tcp_relays, GCC_MAX_TCP_SHARED_RELAYS, nullptr, data, length, 1);

    if (num_nodes <= 0) {
        return -3;
    }

    for (size_t i = 0; i < num_nodes; ++i) {
        Node_format *tcp_node = &tcp_relays[i];

        if (add_tcp_relay_connection(chat->tcp_conn, gconn->tcp_connection_num, tcp_node->ip_port,
                                     tcp_node->public_key) == 0) {
            gcc_save_tcp_relay(gconn, tcp_node);

            if (gconn->tcp_relays_count == 1) {
                add_gc_saved_peers(chat, gconn);  // make sure we save at least one tcp relay
            }
        }
    }

    return 0;
}

/* Send invite request to peer_number. If the group requires a password, the packet will
 * contain the password supplied by the invite requestor.
 *
 * Return 0 on success.
 * Return -1 on failure.
 */
static int send_gc_invite_request(const GC_Chat *chat, GC_Connection *gconn)
{
    uint16_t length = 0;
    uint8_t data[sizeof(uint16_t) + MAX_GC_PASSWORD_SIZE];

    if (chat_is_password_protected(chat)) {
        net_pack_u16(data, chat->shared_state.password_length);
        length += sizeof(uint16_t);

        memcpy(data + length, chat->shared_state.password, MAX_GC_PASSWORD_SIZE);
        length += MAX_GC_PASSWORD_SIZE;
    }

    return send_lossless_group_packet(chat, gconn, data, length, GP_INVITE_REQUEST);
}

/* Return 0 on success.
 * Return -1 on failure.
 */
static int send_gc_invite_response(const GC_Chat *chat, GC_Connection *gconn)
{
    return send_lossless_group_packet(chat, gconn, nullptr, 0, GP_INVITE_RESPONSE);
}

/* Handles an invite response packet.
 *
 * Return 0 if packet is correctly handled.
 * Return -1 if group number is invalid.
 * Return -2 if we fail to send a sync request.
 */
static int handle_gc_invite_response(const Messenger *m, int group_number, GC_Connection *gconn, const uint8_t *data,
                                     uint32_t length)
{
    const GC_Session *c = m->group_handler;
    GC_Chat *chat = gc_get_group(c, group_number);

    if (chat == nullptr) {
        return -1;
    }

    uint16_t sync_flags = GF_PEERS;

    if (mono_time_is_timeout(chat->mono_time, chat->last_sync_request, GC_SYNC_REQUEST_LIMIT)) {
        chat->last_sync_request = mono_time_get(chat->mono_time);
        sync_flags = 0xffff;
    }

    if (send_gc_sync_request(chat, gconn, sync_flags) != 0) {
        return -2;
    }

    return 0;
}

/*
 * Handles an invite response reject packet.
 *
 * Return 0 if packet is handled correctly.
 * Return -1 if packet is invalid size.
 * Return -2 if group number is invalid.
 */
static int handle_gc_invite_response_reject(Messenger *m, int group_number, const uint8_t *data, uint32_t length,
        void *userdata)
{
    if (length != sizeof(uint8_t)) {
        return -1;
    }

    const GC_Session *c = m->group_handler;
    GC_Chat *chat = gc_get_group(c, group_number);

    if (chat == nullptr) {
        return -2;
    }

    if (chat->connection_state == CS_CONNECTED) {
        return 0;
    }

    if (gc_get_self_role(chat) == GR_FOUNDER) {
        return 0;
    }

    uint8_t type = data[0];

    if (type > GJ_INVITE_FAILED) {
        type = GJ_INVITE_FAILED;
    }

    chat->connection_state = CS_DISCONNECTED;

    if (c->rejected) {
        (*c->rejected)(m, group_number, type, userdata);
    }

    return 0;
}

/* Sends an invite response rejection packet to peer designated by `gconn`.
 *
 * Return 0 on success.
 * Return -1 on failure.
 */
static int send_gc_invite_response_reject(const GC_Chat *chat, GC_Connection *gconn, uint8_t type)
{
    if (type > GJ_INVITE_FAILED) {
        type = GJ_INVITE_FAILED;
    }

    uint8_t data[1];
    data[0] = type;
    const size_t length = 1;

    return send_lossy_group_packet(chat, gconn, data, length, GP_INVITE_RESPONSE_REJECT);
}

/* Handles an invite request and verifies that the correct password has been supplied
 * if the group is password protected.
 *
 * Return 0 if invite request is successfully handled.
 * Return -1 if packet is invalid size.
 * Return -2 if group number is invalid.
 * Return -3 if peer number is invalid.
 * Return -4 if the group is full.
 * Return -5 if the supplied password is invalid.
 * Return -6 if we fail to send an invite response.
 */
static int handle_gc_invite_request(Messenger *m, int group_number, uint32_t peer_number, const uint8_t *data,
                                    uint32_t length)
{
    const GC_Session *c = m->group_handler;
    const GC_Chat *chat = gc_get_group(c, group_number);

    if (chat == nullptr) {
        return -2;
    }

    GC_Connection *gconn = gcc_get_connection(chat, peer_number);

    if (gconn == nullptr) {
        return -3;
    }

    if (chat->shared_state.version == 0) {  // we aren't synced yet; ignore request
        return 0;
    }

    int ret = -4;

    uint8_t invite_error;

    if (get_gc_confirmed_numpeers(chat) >= chat->shared_state.maxpeers) {
        invite_error = GJ_GROUP_FULL;
        goto FAILED_INVITE;
    }

    if (chat_is_password_protected(chat)) {
        invite_error = GJ_INVALID_PASSWORD;
        ret = -5;

        if (length != sizeof(uint16_t) + MAX_GC_PASSWORD_SIZE) {
            goto FAILED_INVITE;
        }

        uint16_t password_length;
        net_unpack_u16(data, &password_length);

        if (!validate_password(chat, data + sizeof(uint16_t), password_length)) {
            goto FAILED_INVITE;
        }
    }

    if (send_gc_invite_response(chat, gconn) != 0) {
        return -6;
    }

    return 0;

FAILED_INVITE:
    send_gc_invite_response_reject(chat, gconn, invite_error);
    gcc_mark_for_deletion(gconn, chat->tcp_conn, GC_EXIT_TYPE_DISCONNECTED, nullptr, 0);

    return ret;
}

/* Sends a lossless packet of type and length to all confirmed peers. */
static void send_gc_lossless_packet_all_peers(const GC_Chat *chat, const uint8_t *data, uint32_t length, uint8_t type)
{
    for (uint32_t i = 1; i < chat->numpeers; ++i) {
        if (chat->gcc[i].confirmed) {
            send_lossless_group_packet(chat, &chat->gcc[i], data, length, type);
        }
    }
}

/* Sends a lossy packet of type and length to all confirmed peers. */
static void send_gc_lossy_packet_all_peers(const GC_Chat *chat, const uint8_t *data, uint32_t length, uint8_t type)
{
    for (uint32_t i = 1; i < chat->numpeers; ++i) {
        if (chat->gcc[i].confirmed) {
            send_lossy_group_packet(chat, &chat->gcc[i], data, length, type);
        }
    }
}

/* Creates packet with broadcast header info followed by data of length.
 *
 * Returns length of packet including header.
 */
static uint32_t make_gc_broadcast_header(const GC_Chat *chat, const uint8_t *data, uint32_t length, uint8_t *packet,
        uint8_t bc_type)
{
    packet[0] = bc_type;
    const uint32_t header_len = sizeof(uint8_t);

    if (data != nullptr && length > 0) {
        memcpy(packet + header_len, data, length);
    }

    return length + header_len;
}

/* sends a group broadcast packet to all confirmed peers.
 *
 * Returns 0 on success.
 * Returns -1 on failure.
 */
static int send_gc_broadcast_message(const GC_Chat *chat, const uint8_t *data, uint32_t length, uint8_t bc_type)
{
    if (length + GC_BROADCAST_ENC_HEADER_SIZE > MAX_GC_PACKET_SIZE) {
        LOGGER_ERROR(chat->logger, "Failed to broadcast message: invalid length %u", length);
        return -1;
    }

    uint8_t *packet = (uint8_t *)malloc(length + GC_BROADCAST_ENC_HEADER_SIZE);

    if (packet == nullptr) {
        return -1;
    }

    const uint32_t packet_len = make_gc_broadcast_header(chat, data, length, packet, bc_type);

    send_gc_lossless_packet_all_peers(chat, packet, packet_len, GP_BROADCAST);

    free(packet);

    return 0;
}

static bool group_topic_lock_enabled(const GC_Chat *chat);

/* Compares the supplied values with our own state and returns the appropriate
 * sync flags for a sync request.
 */
static uint16_t get_sync_flags(const GC_Chat *chat, uint16_t peers_checksum, uint16_t peer_count,
                               uint32_t sstate_version, uint32_t screds_version, uint16_t screds_checksum,
                               uint32_t topic_version, uint16_t topic_checksum)
{
    uint16_t sync_flags = 0;

    if (peers_checksum != chat->peers_checksum && peer_count >= (uint16_t) get_gc_confirmed_numpeers(chat)) {
        sync_flags |= GF_PEERS;
    }

    if ((sstate_version > chat->shared_state.version || screds_version > chat->moderation.sanctions_creds.version)
            || (screds_version == chat->moderation.sanctions_creds.version
                && screds_checksum > chat->moderation.sanctions_creds.checksum)) {
        sync_flags |= GF_STATE;
    }

    if (group_topic_lock_enabled(chat)) {
        if (topic_version > chat->topic_info.version ||
                (topic_version == chat->topic_info.version && topic_checksum > chat->topic_info.checksum)) {
            sync_flags |= GF_TOPIC;
        }
    } else if (topic_checksum > chat->topic_info.checksum) {
        sync_flags |= GF_TOPIC;
    }

    return sync_flags;
}

/* Compares a peer's group sync info that we received in a ping packet to our own. If their info appears
 * to be more recent than ours we send them a sync request.
 *
 * This function should only be called from handle_gc_ping().
 *
 * Returns true if a sync request packet is successfully sent.
 */
static bool do_gc_peer_state_sync(GC_Chat *chat, GC_Connection *gconn, const uint8_t *sync_data, const uint32_t length)
{
    if (length < GC_PING_PACKET_MIN_DATA_SIZE) {
        return false;
    }

    uint16_t peers_checksum;
    uint16_t peer_count;
    uint32_t sstate_version;
    uint32_t screds_version;
    uint16_t screds_checksum;
    uint32_t topic_version;
    uint16_t topic_checksum;

    size_t unpacked_len = 0;

    net_unpack_u16(sync_data, &peers_checksum);
    unpacked_len += sizeof(uint16_t);

    net_unpack_u16(sync_data + unpacked_len, &peer_count);
    unpacked_len += sizeof(uint16_t);

    net_unpack_u32(sync_data + unpacked_len, &sstate_version);
    unpacked_len += sizeof(uint32_t);

    net_unpack_u32(sync_data + unpacked_len, &screds_version);
    unpacked_len += sizeof(uint32_t);

    net_unpack_u16(sync_data + unpacked_len, &screds_checksum);
    unpacked_len += sizeof(uint16_t);

    net_unpack_u32(sync_data + unpacked_len, &topic_version);
    unpacked_len += sizeof(uint32_t);

    net_unpack_u16(sync_data + unpacked_len, &topic_checksum);
    unpacked_len += sizeof(uint16_t);

    if (unpacked_len != GC_PING_PACKET_MIN_DATA_SIZE) {
        LOGGER_FATAL(chat->logger, "Unpacked length is impossible (%zu)", unpacked_len);
        return false;
    }

    uint16_t sync_flags = get_sync_flags(chat, peers_checksum, peer_count, sstate_version, screds_version,
                                         screds_checksum, topic_version, topic_checksum);

    if (sync_flags > 0) {
        if (send_gc_sync_request(chat, gconn, sync_flags) == 0) {
            return true;
        }
    }

    return false;
}

/* Handles a ping packet.
 *
 * The packet contains sync information including peer's peer list checksum,
 * shared state version, topic version, and sanction credentials version.
 *
 * Return 0 if packet is handled correctly.
 * Return -1 if packet is invalid size.
 * Return -2 if group number is invalid.
 */
static int handle_gc_ping(const Messenger *m, int group_number, GC_Connection *gconn, const uint8_t *data,
                          const uint32_t length)
{
    if (length < GC_PING_PACKET_MIN_DATA_SIZE) {
        return -1;
    }

    GC_Chat *chat = gc_get_group(m->group_handler, group_number);

    if (chat == nullptr) {
        return -2;
    }

    if (!gconn->confirmed) {
        return 0;
    }

    uint64_t tm = mono_time_get(chat->mono_time);

    gconn->last_received_ping_time = tm;

    if (mono_time_is_timeout(chat->mono_time, chat->last_sync_request, GC_SYNC_REQUEST_LIMIT)) {
        if (do_gc_peer_state_sync(chat, gconn, data, length)) {
            chat->last_sync_request = tm;
        }
    }

    if (length > GC_PING_PACKET_MIN_DATA_SIZE) {
        IP_Port ip_port = {0};

        if (unpack_ip_port(&ip_port, data + GC_PING_PACKET_MIN_DATA_SIZE,
                           length - GC_PING_PACKET_MIN_DATA_SIZE, false) > 0) {
            gcc_set_ip_port(gconn, &ip_port);
            add_gc_saved_peers(chat, gconn);
        }
    }

    return 0;
}

int gc_set_self_status(const Messenger *m, int group_number, Group_Peer_Status status)
{
    const GC_Session *c = m->group_handler;
    GC_Chat *chat = gc_get_group(c, group_number);

    if (chat == nullptr) {
        return -1;
    }

    self_gc_set_status(chat, status);

    uint8_t data[1];
    data[0] = gc_get_self_status(chat);

    if (send_gc_broadcast_message(chat, data, 1, GM_STATUS) == -1) {
        return -3;
    }

    return 0;
}

/* Handles a status broadcast.
 *
 * Return 0 if packet is handled correctly.
 * Return -1 if packet is invalid length.
 * Return -2 if group number is invalid.
 */
static int handle_gc_status(Messenger *m, int group_number, uint32_t peer_number, const uint8_t *data, uint32_t length,
                            void *userdata)
{
    if (length != sizeof(uint8_t)) {
        return -1;
    }

    const GC_Session *c = m->group_handler;
    GC_Chat *chat = gc_get_group(c, group_number);

    if (chat == nullptr) {
        return -2;
    }

    Group_Peer_Status status = (Group_Peer_Status) data[0];

    if (status > GS_BUSY) {
        LOGGER_WARNING(chat->logger, "Received invalid status %u", status);
        return 0;
    }

    chat->group[peer_number].status = status;

    if (c->status_change) {
        (*c->status_change)(m, group_number, chat->group[peer_number].peer_id, status, userdata);
    }

    return 0;
}

uint8_t gc_get_status(const GC_Chat *chat, uint32_t peer_id)
{
    int peer_number = get_peer_number_of_peer_id(chat, peer_id);

    if (!gc_peer_number_is_valid(chat, peer_number)) {
        return (uint8_t) -1;
    }

    return chat->group[peer_number].status;
}

uint8_t gc_get_role(const GC_Chat *chat, uint32_t peer_id)
{
    int peer_number = get_peer_number_of_peer_id(chat, peer_id);

    if (!gc_peer_number_is_valid(chat, peer_number)) {
        return (uint8_t) -1;
    }

    return chat->group[peer_number].role;
}

void gc_get_chat_id(const GC_Chat *chat, uint8_t *dest)
{
    if (dest != nullptr) {
        memcpy(dest, get_chat_id(chat->chat_public_key), CHAT_ID_SIZE);
    }
}

/* Sends self peer info to peer_number. If the group is password protected the request
 * will contain the group password, which the recipient will validate in the respective
 * group message handler.
 *
 * Returns 0 on sucess.
 * Returns -1 on failure.
 */
static int send_self_to_peer(const GC_Session *c, const GC_Chat *chat, GC_Connection *gconn)
{
    GC_GroupPeer self;
    copy_self(chat, &self);

    uint8_t data[MAX_GC_PACKET_SIZE];

    uint32_t length = 0;

    if (chat_is_password_protected(chat)) {
        net_pack_u16(data, chat->shared_state.password_length);
        length += sizeof(uint16_t);

        memcpy(data + sizeof(uint16_t), chat->shared_state.password, MAX_GC_PASSWORD_SIZE);
        length += MAX_GC_PASSWORD_SIZE;
    }

    const int packed_len = pack_gc_peer(data + length, sizeof(data) - length, &self);
    length += packed_len;

    if (packed_len <= 0) {
        LOGGER_DEBUG(chat->logger, "pack_gc_peer failed in handle_gc_peer_info_request_request %d", packed_len);
        return -1;
    }

    return send_lossless_group_packet(chat, gconn, data, length, GP_PEER_INFO_RESPONSE);
}

/* Handles a peer info request packet.
 *
 * Return 0 on succss.
 * Return -1 if group number is invalid.
 * Return -2 if unconfirmed peer is trying to join a full group.
 * Return -3 if response fails.
 */
static int handle_gc_peer_info_request(const Messenger *m, int group_number, GC_Connection *gconn)
{
    const GC_Session *c = m->group_handler;
    const GC_Chat *chat = gc_get_group(c, group_number);

    if (chat == nullptr) {
        return -1;
    }

    if (!gconn->confirmed && get_gc_confirmed_numpeers(chat) >= chat->shared_state.maxpeers) {
        return -2;
    }

    if (send_self_to_peer(c, chat, gconn) != 0) {
        return -3;
    }

    return 0;
}

/* Sends a peer info request to peer designated by `gconn`.
 *
 * Return 0 on success.
 * Return -1 on failure.
 */
static int send_gc_peer_info_request(const GC_Chat *chat, GC_Connection *gconn)
{
    return send_lossless_group_packet(chat, gconn, nullptr, 0, GP_PEER_INFO_REQUEST);
}

/* Do peer info exchange with peer designated by `gconn`.
 *
 * This function sends two packets to a peer. The first packet is a peer info response containing our own info,
 * and the second packet is a peer info request.
 *
 * Return 0 on success.
 * Return -1 if either packet fails to send.
 */
static int send_gc_peer_exchange(const GC_Session *c, const GC_Chat *chat, GC_Connection *gconn)
{
    const int ret1 = send_self_to_peer(c, chat, gconn);
    const int ret2 = send_gc_peer_info_request(chat, gconn);
    return (ret1 == -1 || ret2 == -1) ? -1 : 0;
}

/* Updates peer's info, validates their group role, and sets them as a confirmed peer.
 * If the group is password protected the password must first be validated.
 *
 * Return 0 if packet is handled correctly.
 * Return -1 if packet is invalid size.
 * Return -2 if group number is invalid.
 * Return -3 if peer number is invalid.
 * Return -4 if unconfirmed peer is trying to join a full group.
 * Return -5 if supplied group password is invalid.
 * Return -6 if we fail to add the peer to the peer list.
 * Return -7 if peer's role cannot be validated.
 */
static int handle_gc_peer_info_response(Messenger *m, int group_number, uint32_t peer_number,
                                        const uint8_t *data, uint32_t length, void *userdata)
{
    if (length < PACKED_GC_PEER_SIZE) {
        return -1;
    }

    const GC_Session *c = m->group_handler;
    GC_Chat *chat = gc_get_group(c, group_number);

    if (chat == nullptr) {
        return -2;
    }

    GC_Connection *gconn = gcc_get_connection(chat, peer_number);

    if (gconn == nullptr) {
        return -3;
    }

    if (!gconn->confirmed && get_gc_confirmed_numpeers(chat) >= chat->shared_state.maxpeers) {
        return -4;
    }

    uint16_t unpacked_len = 0;

    if (chat_is_password_protected(chat)) {
        if (length < sizeof(uint16_t) + MAX_GC_PASSWORD_SIZE) {
            return -5;
        }

        uint16_t password_length;
        net_unpack_u16(data, &password_length);
        unpacked_len += sizeof(uint16_t);

        if (!validate_password(chat, data + unpacked_len, password_length)) {
            return -5;
        }

        unpacked_len += MAX_GC_PASSWORD_SIZE;
    }

    GC_GroupPeer peer;
    memset(&peer, 0, sizeof(GC_GroupPeer));

    if (length <= unpacked_len) {
        return -1;
    }

    if (unpack_gc_peer(&peer, data + unpacked_len, length - unpacked_len) == -1) {
        LOGGER_WARNING(m->log, "unpack_gc_peer() failed");
        return -6;
    }

    if (peer_update(m, group_number, &peer, peer_number) == -1) {
        LOGGER_WARNING(m->log, "peer_update() failed");
        return -6;
    }

    if (update_gc_peer_roles(chat) != 0) {
        LOGGER_WARNING(m->log, "failed to validate peer role");
        gcc_mark_for_deletion(gconn, chat->tcp_conn, GC_EXIT_TYPE_SYNC_ERR, nullptr, 0);
        return -7;
    }

    if (c->peer_join && !gconn->confirmed) {
        (*c->peer_join)(m, group_number, chat->group[peer_number].peer_id, userdata);
    }

    gconn->confirmed = true;

    add_gc_saved_peers(chat, gconn);

    set_gc_peerlist_checksum(chat);

    return 0;
}

/* Sends the group shared state and its signature to peer_number.
 *
 * Returns a non-negative integer on success.
 * Returns -1 on failure.
 */
static int send_peer_shared_state(const GC_Chat *chat, GC_Connection *gconn)
{
    if (chat->shared_state.version == 0) {
        return -1;
    }

    uint8_t packet[GC_SHARED_STATE_ENC_PACKET_SIZE];
    const int length = make_gc_shared_state_packet(chat, packet, sizeof(packet));

    if (length != GC_SHARED_STATE_ENC_PACKET_SIZE) {
        return -1;
    }

    return send_lossless_group_packet(chat, gconn, packet, length, GP_SHARED_STATE);
}

/* Sends the group shared state and signature to all confirmed peers.
 *
 * Returns 0 on success.
 * Returns -1 on failure
 */
static int broadcast_gc_shared_state(const GC_Chat *chat)
{
    uint8_t packet[GC_SHARED_STATE_ENC_PACKET_SIZE];
    const int packet_len = make_gc_shared_state_packet(chat, packet, sizeof(packet));

    if (packet_len != GC_SHARED_STATE_ENC_PACKET_SIZE) {
        return -1;
    }

    send_gc_lossless_packet_all_peers(chat, packet, packet_len, GP_SHARED_STATE);

    return 0;
}

/* Compares old_shared_state with the chat instance's current shared state and triggers the
 * appropriate callback depending on what piece of state information changed. Also
 * handles DHT announcement/removal if the privacy state changed.
 *
 * The initial retrieval of the shared state on group join will be ignored by this function.
 */
static void do_gc_shared_state_changes(const GC_Session *c, GC_Chat *chat, const GC_SharedState *old_shared_state,
                                       void *userdata)
{
    /* Max peers changed */
    if (chat->shared_state.maxpeers != old_shared_state->maxpeers) {
        if (c->peer_limit) {
            (*c->peer_limit)(c->messenger, chat->group_number, chat->shared_state.maxpeers, userdata);
        }
    }

    /* privacy state changed */
    if (chat->shared_state.privacy_state != old_shared_state->privacy_state) {
        if (c->privacy_state) {
            (*c->privacy_state)(c->messenger, chat->group_number, chat->shared_state.privacy_state, userdata);
        }

        if (is_public_chat(chat)) {
            if (m_create_group_connection(c->messenger, chat) == -1) {
                LOGGER_ERROR(chat->logger, "Failed to initialize group friend connection");
            } else {
                chat->update_self_announces = true;
            }
        } else {
            m_kill_group_connection(c->messenger, chat);
            cleanup_gca(c->announces_list, get_chat_id(chat->chat_public_key));
        }
    }

    /* password changed */
    if (chat->shared_state.password_length != old_shared_state->password_length
            || memcmp(chat->shared_state.password, old_shared_state->password, old_shared_state->password_length) != 0) {

        if (c->password) {
            (*c->password)(c->messenger, chat->group_number, chat->shared_state.password,
                           chat->shared_state.password_length, userdata);
        }
    }

    /* topic lock state changed */
    if (chat->shared_state.topic_lock != old_shared_state->topic_lock) {
        if (c->topic_lock) {
            const Group_Topic_Lock lock_state = group_topic_lock_enabled(chat) ? TL_ENABLED : TL_DISABLED;
            (*c->topic_lock)(c->messenger, chat->group_number, lock_state, userdata);
        }
    }
}

/* Sends a sync request to a random peer in the group with the specificed sync flags.
 *
 * Return 0 on success.
 * Return -1 on failure.
 */
static int send_gc_random_sync_request(GC_Chat *chat, uint16_t sync_flags)
{

    if (!mono_time_is_timeout(chat->mono_time, chat->last_sync_request, GC_SYNC_REQUEST_LIMIT)) {
        return 0;
    }

    GC_Connection *rand_gconn = gcc_random_connection(chat);

    if (rand_gconn == nullptr) {
        return -1;
    }

    if (send_gc_sync_request(chat, rand_gconn, sync_flags) != 0) {
        return -1;
    }

    chat->last_sync_request = mono_time_get(chat->mono_time);

    return 0;
}

/* Checks that all shared state values are legal.
 *
 * Returns 0 on success.
 * Returns -1 on failure.
 */
static int validate_gc_shared_state(const GC_SharedState *state)
{
    if (state->maxpeers == 0) {
        return -1;
    }

    if (state->password_length > MAX_GC_PASSWORD_SIZE) {
        return -1;
    }

    if (state->group_name_len == 0 || state->group_name_len > MAX_GC_GROUP_NAME_SIZE) {
        return -1;
    }

    if (state->privacy_state > GI_PRIVATE) {
        return -1;
    }

    return 0;
}

/* Handles a shared state error and attempts to send a sync request to a random peer.
 *
 * Return 0 if error is currectly handled.
 * Return -1 on failure.
 */
static int handle_gc_shared_state_error(Messenger *m, int group_number, uint32_t peer_number, GC_Chat *chat)
{
    GC_Connection *gconn = gcc_get_connection(chat, peer_number);

    if (gconn != nullptr) {
        gcc_mark_for_deletion(gconn, chat->tcp_conn, GC_EXIT_TYPE_SYNC_ERR, nullptr, 0);
    }

    if (chat->shared_state.version == 0) {
        chat->connection_state = CS_CONNECTING;
        return 0;
    }

    if (chat->numpeers <= 1) {
        return 0;
    }

    if (!mono_time_is_timeout(chat->mono_time, chat->last_sync_request, GC_SYNC_REQUEST_LIMIT)) {
        return 0;
    }

    if (send_gc_random_sync_request(chat, GF_STATE) == -1) {
        return -1;
    }

    return 0;
}

/* Handles a shared state packet and validates the new shared state.
 *
 * Return 0 if packet is successfully handled.
 * Return -1 on error.
 */
static int handle_gc_shared_state(Messenger *m, int group_number, uint32_t peer_number, const uint8_t *data,
                                  uint32_t length, void *userdata)
{
    const GC_Session *c = m->group_handler;
    GC_Chat *chat = gc_get_group(c, group_number);

    if (chat == nullptr) {
        return -1;
    }

    if (length != GC_SHARED_STATE_ENC_PACKET_SIZE) {
        return handle_gc_shared_state_error(m, group_number, peer_number, chat);
    }

    const uint8_t *signature = data;
    const uint8_t *ss_data = data + SIGNATURE_SIZE;
    const uint16_t ss_length = length - SIGNATURE_SIZE;

    if (crypto_sign_verify_detached(signature, ss_data, GC_PACKED_SHARED_STATE_SIZE,
                                    get_sig_pk(chat->chat_public_key)) == -1) {
        LOGGER_WARNING(m->log, "Failed to validate shared state signature");
        return handle_gc_shared_state_error(m, group_number, peer_number, chat);
    }

    uint32_t version;
    net_unpack_u32(ss_data, &version);  // version is the first 4 bytes of shared state data payload

    if (version == 0 || version < chat->shared_state.version) {
        LOGGER_DEBUG(m->log, "Invalid shared state version (got %u, expected >= %u)", version, chat->shared_state.version);
        return 0;
    }

    GC_SharedState old_shared_state;
    GC_SharedState new_shared_state;
    memcpy(&old_shared_state, &chat->shared_state, sizeof(GC_SharedState));

    if (unpack_gc_shared_state(&new_shared_state, ss_data, ss_length) == 0) {
        LOGGER_WARNING(m->log, "Failed to unpack shared state");
        return 0;
    }

    if (validate_gc_shared_state(&new_shared_state) == -1) {
        LOGGER_WARNING(m->log, "Failed to validate shared state");
        return 0;
    }

    memcpy(&chat->shared_state, &new_shared_state, sizeof(GC_SharedState));
    memcpy(chat->shared_state_sig, signature, sizeof(chat->shared_state_sig));

    do_gc_shared_state_changes(c, chat, &old_shared_state, userdata);

    return 0;
}

/* Validates `data` containing a moderation list and unpacks it into the
 * shared state of `chat`.
 *
 * Return 1 if data is valid and we already have the same mod list.
 * Return 0 if data is valid.
 * Return -1 if data is invalid.
 */
static int validate_unpack_mod_list(GC_Chat *chat, const uint8_t *data, uint32_t length, uint16_t num_mods)
{
    if (num_mods > MAX_GC_MODERATORS) {
        return -1;
    }

    uint8_t mod_list_hash[GC_MODERATION_HASH_SIZE] = {0};

    if (length > 0) {
        crypto_hash_sha256(mod_list_hash, data, length);
    }

    // we make sure that this mod list's hash matches the one we got in our last shared state update
    if (memcmp(mod_list_hash, chat->shared_state.mod_list_hash, GC_MODERATION_HASH_SIZE) != 0) {
        LOGGER_WARNING(chat->logger, "failed to validate mod list hash");
        return -1;
    }

    // we already had this mod list so we don't need to do anything else
    if (memcmp(mod_list_hash, chat->shared_state.mod_list_hash, GC_MODERATION_HASH_SIZE) == 0) {
        LOGGER_DEBUG(chat->logger, "got duplicate mod list");
        return 1;
    }

    if (mod_list_unpack(chat, data, length, num_mods) == -1) {
        LOGGER_WARNING(chat->logger, "failed to unpack mod list");
        return -1;
    }

    return 0;
}

/* Handles new mod_list and compares its hash against the mod_list_hash in the shared state.
 *
 * If the new list fails validation, we attempt to send a sync request to a random peer.
 *
 * Return 0 if packet is handled correctly.
 * Return -1 if packet is invalid size.
 * Return -2 if group number is invalid.
 * Return -3 if packet contained invalid data or validation failed.
 */
static int handle_gc_mod_list(Messenger *m, int group_number, uint32_t peer_number, const uint8_t *data,
                              uint32_t length, void *userdata)
{
    if (length < sizeof(uint16_t)) {
        return -1;
    }

    const GC_Session *c = m->group_handler;
    GC_Chat *chat = gc_get_group(c, group_number);

    if (chat == nullptr) {
        return -2;
    }

    // only the founder can modify the list so he can never be out of sync
    if (self_gc_is_founder(chat)) {
        return 0;
    }

    uint16_t num_mods;
    net_unpack_u16(data, &num_mods);

    const int unpack_ret = validate_unpack_mod_list(chat, data + sizeof(uint16_t), length - sizeof(uint16_t), num_mods);

    if (update_gc_peer_roles(chat) != 0) {
        LOGGER_WARNING(chat->logger, "Peer role update has conflicts");
        send_gc_random_sync_request(chat, GF_STATE);
        return 0;
    }

    if (unpack_ret == 0) {
        if (chat->connection_state == CS_CONNECTED && c->moderation) {
            (*c->moderation)(m, group_number, (uint32_t) -1, (uint32_t) -1, MV_MOD, userdata);
        }

        return 0;
    }

    if (unpack_ret == 1) {
        return 0;
    }

    // unpack/validation failed: handle error

    if (chat->shared_state.version == 0) {
        chat->connection_state = CS_CONNECTING;
        return -3;
    }

    if (chat->numpeers <= 1 || !mono_time_is_timeout(chat->mono_time, chat->last_sync_request, GC_SYNC_REQUEST_LIMIT)) {
        return 0;
    }

    if (send_gc_random_sync_request(chat, GF_STATE) == -1) {
        return -1;
    }

    return 0;
}

/* Handles a sanctions list validation error and attempts to send a sync request to a random peer.
 *
 * Return 0 on success.
 * Return -1 on failure.
 */
static int handle_gc_sanctions_list_error(Messenger *m, int group_number, uint32_t peer_number, GC_Chat *chat)
{
    if (chat->moderation.sanctions_creds.version > 0) {
        return 0;
    }

    if (chat->shared_state.version == 0) {
        chat->connection_state = CS_CONNECTING;
        return 0;
    }

    if (chat->numpeers <= 1) {
        return 0;
    }

    if (!mono_time_is_timeout(chat->mono_time, chat->last_sync_request, GC_SYNC_REQUEST_LIMIT)) {
        return 0;
    }

    if (send_gc_random_sync_request(chat, GF_STATE) == -1) {
        return -1;
    }

    return 0;
}

/* Handles a sanctions list packet.
 *
 * Return 0 if packet is handled correctly.
 * Return -1 if we failed to gracefully handle a sanctions list error.
 * Return -2 if packet is invalid size.
 * Return -3 if group number is invalid.
 */
static int handle_gc_sanctions_list(Messenger *m, int group_number, uint32_t peer_number, const uint8_t *data,
                                    uint32_t length, void *userdata)
{
    if (length < sizeof(uint32_t)) {
        return -2;
    }

    const GC_Session *c = m->group_handler;
    GC_Chat *chat = gc_get_group(c, group_number);

    if (chat == nullptr) {
        return -3;
    }

    uint16_t num_sanctions;
    net_unpack_u16(data, &num_sanctions);

    if (num_sanctions > MAX_GC_SANCTIONS) {
        LOGGER_WARNING(chat->logger, "num_sanctions: %u exceeds maximum: %d", num_sanctions, MAX_GC_SANCTIONS);
        return handle_gc_sanctions_list_error(m, group_number, peer_number, chat);
    }

    struct GC_Sanction_Creds creds;

    struct GC_Sanction *sanctions = (struct GC_Sanction *)malloc(num_sanctions * sizeof(struct GC_Sanction));

    if (sanctions == nullptr) {
        return -1;
    }

    const int unpacked_num = sanctions_list_unpack(sanctions, &creds, num_sanctions, data + sizeof(uint16_t),
                             length - sizeof(uint16_t), nullptr);

    if (unpacked_num != num_sanctions) {
        LOGGER_WARNING(m->log, "Failed to unpack sanctions list: %d", unpacked_num);
        free(sanctions);
        return handle_gc_sanctions_list_error(m, group_number, peer_number, chat);
    }

    if (sanctions_list_check_integrity(chat, &creds, sanctions, num_sanctions) == -1) {
        LOGGER_WARNING(m->log, "Sanctions list failed integrity check");
        free(sanctions);
        return handle_gc_sanctions_list_error(m, group_number, peer_number, chat);
    }

    if (creds.version < chat->moderation.sanctions_creds.version) {
        return 0;
    }

    // this may occur if two mods change the sanctions list at the exact same time
    if (creds.version == chat->moderation.sanctions_creds.version
            && creds.checksum == chat->moderation.sanctions_creds.checksum) {
        free(sanctions);
        return 0;
    }

    sanctions_list_cleanup(chat);

    memcpy(&chat->moderation.sanctions_creds, &creds, sizeof(struct GC_Sanction_Creds));
    chat->moderation.sanctions = sanctions;
    chat->moderation.num_sanctions = num_sanctions;

    if (update_gc_peer_roles(chat) != 0) {
        LOGGER_WARNING(chat->logger, "peer role update had conflicts");
        send_gc_random_sync_request(chat, GF_STATE);
        return 0;
    }

    if (chat->connection_state == CS_CONNECTED) {
        if (c->moderation) {
            (*c->moderation)(m, group_number, (uint32_t) -1, (uint32_t) -1, MV_OBSERVER, userdata);
        }
    }

    return 0;
}

/* Makes a mod_list packet.
 *
 * Returns length of packet data on success.
 * Returns -1 on failure.
 */
static int make_gc_mod_list_packet(const GC_Chat *chat, uint8_t *data, uint32_t maxlen, size_t mod_list_size)
{
    if (maxlen < sizeof(uint16_t) + mod_list_size) {
        return -1;
    }

    net_pack_u16(data, chat->moderation.num_mods);
    const uint16_t length = sizeof(uint16_t) + mod_list_size;

    if (mod_list_size > 0) {
        uint8_t *packed_mod_list = (uint8_t *)malloc(mod_list_size);

        if (packed_mod_list == nullptr) {
            return -1;
        }

        mod_list_pack(chat, packed_mod_list);
        memcpy(data + sizeof(uint16_t), packed_mod_list, mod_list_size);

        free(packed_mod_list);
    }

    return length;
}

/* Sends the moderator list to peer.
 *
 * Returns a non-negative value on success.
 * Returns -1 on failure.
 */
static int send_peer_mod_list(const GC_Chat *chat, GC_Connection *gconn)
{
    const size_t mod_list_size = chat->moderation.num_mods * GC_MOD_LIST_ENTRY_SIZE;
    const uint32_t length = sizeof(uint16_t) + mod_list_size;
    uint8_t *packet = (uint8_t *)malloc(length);

    if (packet == nullptr) {
        return -1;
    }

    const int packet_len = make_gc_mod_list_packet(chat, packet, length, mod_list_size);

    if (packet_len != length) {
        free(packet);
        return -1;
    }

    const int ret = send_lossless_group_packet(chat, gconn, packet, length, GP_MOD_LIST);

    free(packet);

    return ret;
}

/* Makes a sanctions list packet.
 *
 * Returns packet length on success.
 * Returns -1 on failure.
 */
static int make_gc_sanctions_list_packet(const GC_Chat *chat, uint8_t *data, uint32_t maxlen)
{
    if (maxlen < sizeof(uint16_t)) {
        return -1;
    }

    net_pack_u16(data, chat->moderation.num_sanctions);
    const uint32_t length = sizeof(uint16_t);

    const int packed_len = sanctions_list_pack(data + length, maxlen - length, chat->moderation.sanctions,
                           &chat->moderation.sanctions_creds, chat->moderation.num_sanctions);

    if (packed_len < 0) {
        return -1;
    }

    return length + packed_len;
}

/* Sends the sanctions list to peer.
 *
 * Returns non-negative value on success.
 * Returns -1 on failure.
 */
static int send_peer_sanctions_list(const GC_Chat *chat, GC_Connection *gconn)
{
    if (chat->moderation.sanctions_creds.version == 0) {
        return 0;
    }

    uint8_t packet[MAX_GC_PACKET_SIZE];
    const int packet_len = make_gc_sanctions_list_packet(chat, packet, sizeof(packet));

    if (packet_len == -1) {
        return -1;
    }

    return send_lossless_group_packet(chat, gconn, packet, packet_len, GP_SANCTIONS_LIST);
}

/* Sends the sanctions list to all peers in group.
 *
 * Returns 0 on success.
 * Returns -1 on failure.
 */
static int broadcast_gc_sanctions_list(const GC_Chat *chat)
{
    uint8_t packet[MAX_GC_PACKET_SIZE];
    const int packet_len = make_gc_sanctions_list_packet(chat, packet, sizeof(packet));

    if (packet_len == -1) {
        return -1;
    }

    send_gc_lossless_packet_all_peers(chat, packet, packet_len, GP_SANCTIONS_LIST);
    return 0;
}

/* Re-signs all sanctions list entries signed by public_sig_key and broadcasts
 * the updated sanctions list to all group peers.
 *
 * Returns the number of updated entries on success.
 * Returns -1 on failure.
 */
static int update_gc_sanctions_list(GC_Chat *chat, const uint8_t *public_sig_key)
{
    const uint32_t num_replaced = sanctions_list_replace_sig(chat, public_sig_key);

    if (num_replaced == 0) {
        return 0;
    }

    if (broadcast_gc_sanctions_list(chat) == -1) {
        return -1;
    }

    return num_replaced;
}

/* Sends mod_list to all peers in group.
 *
 * Returns 0 on success.
 * Returns -1 on failure.
 */
static int broadcast_gc_mod_list(const GC_Chat *chat)
{
    size_t mod_list_size = chat->moderation.num_mods * GC_MOD_LIST_ENTRY_SIZE;
    const uint32_t length = sizeof(uint16_t) + mod_list_size;
    uint8_t *packet = (uint8_t *)malloc(length);

    if (packet == nullptr) {
        return -1;
    }

    const int packet_len = make_gc_mod_list_packet(chat, packet, length, mod_list_size);

    if (packet_len != length) {
        free(packet);
        return -1;
    }

    send_gc_lossless_packet_all_peers(chat, packet, packet_len, GP_MOD_LIST);

    free(packet);

    return 0;
}

/* Sends a parting signal to the group.
 *
 * Returns 0 on success.
 * Returns -1 if the message is too long.
 * Returns -2 if the packet failed to send.
 */
static int send_gc_self_exit(const GC_Chat *chat, const uint8_t *partmessage, uint32_t length)
{
    if (length > MAX_GC_PART_MESSAGE_SIZE) {
        return -1;
    }

    if (send_gc_broadcast_message(chat, partmessage, length, GM_PEER_EXIT) == -1) {
        return -2;
    }

    return 0;
}

/* Handles a peer exit broadcast.
 *
 * Return 0 if packet is handled correctly.
 * Return -1 if group number is invalid.
 * Return -2 if peer number is invalid.
 */
static int handle_gc_peer_exit(Messenger *m, int group_number, uint32_t peer_number, const uint8_t *data,
                               uint32_t length)
{
    if (length > MAX_GC_PART_MESSAGE_SIZE) {
        length = MAX_GC_PART_MESSAGE_SIZE;
    }

    const GC_Session *c = m->group_handler;
    const GC_Chat *chat = gc_get_group(c, group_number);

    if (chat == nullptr) {
        return -1;
    }

    GC_Connection *gconn = gcc_get_connection(chat, peer_number);

    if (gconn == nullptr) {
        return -2;
    }

    gcc_mark_for_deletion(gconn, chat->tcp_conn, GC_EXIT_TYPE_QUIT, data, length);

    return 0;
}

int gc_set_self_nick(const Messenger *m, int group_number, const uint8_t *nick, uint16_t length)
{
    const GC_Session *c = m->group_handler;
    const GC_Chat *chat = gc_get_group(c, group_number);

    if (chat == nullptr) {
        return -1;
    }

    if (length > MAX_GC_NICK_SIZE) {
        return -2;
    }

    if (length == 0 || nick == nullptr) {
        return -3;
    }

    if (self_gc_set_nick(chat, nick, length) == -1) {
        return -2;
    }

    if (send_gc_broadcast_message(chat, nick, length, GM_NICK) == -1) {
        return -5;
    }

    return 0;
}

int gc_get_peer_nick(const GC_Chat *chat, uint32_t peer_id, uint8_t *name)
{
    const int peer_number = get_peer_number_of_peer_id(chat, peer_id);

    if (!gc_peer_number_is_valid(chat, peer_number)) {
        return -1;
    }

    if (name != nullptr) {
        memcpy(name, chat->group[peer_number].nick, chat->group[peer_number].nick_length);
    }

    return 0;
}

int gc_get_peer_nick_size(const GC_Chat *chat, uint32_t peer_id)
{
    const int peer_number = get_peer_number_of_peer_id(chat, peer_id);

    if (!gc_peer_number_is_valid(chat, peer_number)) {
        return -1;
    }

    return chat->group[peer_number].nick_length;
}

/* Handles a nick change broadcast.
 *
 * Return 0 if packet is handled correctly.
 * Return -1 on failure.
 */
static int handle_gc_nick(Messenger *m, int group_number, uint32_t peer_number, const uint8_t *nick,
                          uint32_t length,  void *userdata)
{
    const GC_Session *c = m->group_handler;
    const GC_Chat *chat = gc_get_group(c, group_number);

    if (chat == nullptr) {
        return -1;
    }

    /* If this happens malicious behaviour is highly suspect */
    if (length == 0 || length > MAX_GC_NICK_SIZE) {
        gcc_mark_for_deletion(&chat->gcc[peer_number], chat->tcp_conn, GC_EXIT_TYPE_SYNC_ERR, nullptr, 0);
        LOGGER_WARNING(chat->logger, "Invalid nick length for nick: %s (%u)", nick, length);
        return 0;
    }

    // callback should come before we change the nick so a nick query returns the old nick instead of
    // the new one. TODO (jfreegman): should this behaviour be uniform for all callbacks?
    if (c->nick_change) {
        (*c->nick_change)(m, group_number, chat->group[peer_number].peer_id, nick, length, userdata);
    }

    memcpy(chat->group[peer_number].nick, nick, length);
    chat->group[peer_number].nick_length = length;

    return 0;
}

/* Copies peer_number's public key to `public_key`.
 *
 * Returns 0 on success.
 * Returns -1 if peer_number is invalid.
 * Returns -2 if `public_key` is null.
 */
static int get_gc_peer_public_key(const GC_Chat *chat, uint32_t peer_number, uint8_t *public_key)
{
    GC_Connection *gconn = gcc_get_connection(chat, peer_number);

    if (gconn == nullptr) {
        return -1;
    }

    if (public_key == nullptr) {
        return -2;
    }

    memcpy(public_key, gconn->addr.public_key, ENC_PUBLIC_KEY_SIZE);

    return 0;
}

int gc_get_peer_public_key_by_peer_id(const GC_Chat *chat, uint32_t peer_id, uint8_t *public_key)
{
    const int peer_number = get_peer_number_of_peer_id(chat, peer_id);

    if (peer_number < 0) {
        return -1;
    }

    const GC_Connection *gconn = gcc_get_connection(chat, peer_number);

    if (gconn == nullptr) {
        return -1;
    }

    if (public_key == nullptr) {
        return -2;
    }

    memcpy(public_key, gconn->addr.public_key, ENC_PUBLIC_KEY_SIZE);

    return 0;
}

unsigned int gc_get_peer_connection_status(const GC_Chat *chat, uint32_t peer_id)
{
    const int peer_number = get_peer_number_of_peer_id(chat, peer_id);

    if (peer_number < 0) {
        return 0;
    }

    if (peer_number_is_self(peer_number)) {  // we cannot have a connection with ourselves
        return 0;
    }

    const GC_Connection *gconn = gcc_get_connection(chat, peer_number);

    if (gconn == nullptr) {
        return 0;
    }

    if (gcc_conn_is_direct(chat->mono_time, gconn)) {
        return 2;
    }

    return 1;
}

/* Creates a topic packet and puts it in data. Packet includes the topic, topic length,
 * public signature key of the setter, topic version, and the signature.
 *
 * Returns packet length on success.
 * Returns -1 on failure.
 */
static int make_gc_topic_packet(const GC_Chat *chat, uint8_t *data, uint16_t length)
{
    if (length < SIGNATURE_SIZE + chat->topic_info.length + GC_MIN_PACKED_TOPIC_INFO_SIZE) {
        return -1;
    }

    memcpy(data, chat->topic_sig, SIGNATURE_SIZE);
    uint16_t data_length = SIGNATURE_SIZE;

    const uint16_t packed_len = pack_gc_topic_info(data + data_length, length - data_length, &chat->topic_info);
    data_length += packed_len;

    if (packed_len != chat->topic_info.length + GC_MIN_PACKED_TOPIC_INFO_SIZE) {
        return -1;
    }

    return data_length;
}

/* Sends the group topic to peer.
 *
 * Returns 0 on success.
 * Returns -1 on failure.
 */
static int send_peer_topic(const GC_Chat *chat, GC_Connection *gconn)
{
    const size_t packet_buf_size = SIGNATURE_SIZE + chat->topic_info.length + GC_MIN_PACKED_TOPIC_INFO_SIZE;
    uint8_t *packet = (uint8_t *)malloc(packet_buf_size);

    if (packet == nullptr) {
        return -1;
    }

    const int packet_len = make_gc_topic_packet(chat, packet, packet_buf_size);

    if (packet_len != packet_buf_size) {
        free(packet);
        return -1;
    }

    if (send_lossless_group_packet(chat, gconn, packet, packet_len, GP_TOPIC) == -1) {
        free(packet);
        return -1;
    }

    free(packet);

    return 0;
}

/*
 * Initiates a session key rotation with peer designated by `gconn`.
 *
 * Return 0 on success.
 * Return -1 on failure.
 */
static int send_peer_key_rotation_request(const GC_Chat *chat, GC_Connection *gconn)
{
    // Only the peer closest to the chat_id sends requests. This is to prevent both peers from sending
    // requests at the same time and ending up with a different resulting shared key
    if (!gconn->self_is_closer) {
        // if this peer hasn't sent us a rotation request in a reasonable timeframe we drop their connection
        if (mono_time_is_timeout(chat->mono_time, gconn->last_key_rotation, GC_KEY_ROTATION_TIMEOUT + GC_PING_TIMEOUT)) {
            gcc_mark_for_deletion(gconn, chat->tcp_conn, GC_EXIT_TYPE_TIMEOUT, nullptr, 0);
        }

        return 0;
    }

    uint8_t packet[1 + ENC_PUBLIC_KEY_SIZE];
    packet[0] = 0;  // request type

    if (create_gc_session_keypair(gconn->session_public_key, gconn->session_secret_key) != 0) {
        LOGGER_FATAL(chat->logger, "Failed to create session keypair");
        return -1;
    }

    // copy new session public key to packet
    memcpy(packet + 1, gconn->session_public_key, ENC_PUBLIC_KEY_SIZE);

    if (send_lossless_group_packet(chat, gconn, packet, sizeof(packet), GP_KEY_ROTATION) != 0) {
        return -1;
    }

    gconn->pending_key_rotation_request = true;

    return 0;
}

/* Sends the group topic to all group members.
 *
 * Returns 0 on success.
 * Returns -1 on failure.
 */
static int broadcast_gc_topic(const GC_Chat *chat)
{
    const size_t packet_buf_size = SIGNATURE_SIZE + chat->topic_info.length + GC_MIN_PACKED_TOPIC_INFO_SIZE;
    uint8_t *packet = (uint8_t *)malloc(packet_buf_size);

    if (packet == nullptr) {
        return -1;
    }

    const int packet_len = make_gc_topic_packet(chat, packet, packet_buf_size);

    if (packet_len != packet_buf_size) {
        free(packet);
        return -1;
    }

    send_gc_lossless_packet_all_peers(chat, packet, packet_len, GP_TOPIC);

    free(packet);

    return 0;
}

int gc_set_topic(GC_Chat *chat, const uint8_t *topic, uint16_t length)
{
    if (length > MAX_GC_TOPIC_SIZE) {
        return -1;
    }

    const bool topic_lock_enabled = group_topic_lock_enabled(chat);

    if (topic_lock_enabled && gc_get_self_role(chat) > GR_MODERATOR) {
        return -2;
    }

    if (gc_get_self_role(chat) > GR_USER) {
        return -2;
    }

    GC_TopicInfo old_topic_info;
    uint8_t old_topic_sig[SIGNATURE_SIZE];

    memcpy(&old_topic_info, &chat->topic_info, sizeof(GC_TopicInfo));
    memcpy(old_topic_sig, chat->topic_sig, SIGNATURE_SIZE);

    // TODO (jfreegman) improbable, but an overflow would break everything
    if (chat->topic_info.version == UINT32_MAX) {
        return -3;
    }

    // only increment topic version when lock is enabled
    if (topic_lock_enabled) {
        ++chat->topic_info.version;
    }

    chat->topic_info.length = length;

    if (length > 0) {
        memcpy(chat->topic_info.topic, topic, length);
    } else {
        memset(chat->topic_info.topic, 0, sizeof(chat->topic_info.topic));
    }

    memcpy(chat->topic_info.public_sig_key, get_sig_pk(chat->self_public_key), SIG_PUBLIC_KEY_SIZE);

    set_gc_topic_checksum(&chat->topic_info);

    const size_t packet_buf_size = length + GC_MIN_PACKED_TOPIC_INFO_SIZE;
    uint8_t *packed_topic = (uint8_t *)malloc(packet_buf_size);

    if (packed_topic == nullptr) {
        return -3;
    }

    const uint16_t packed_len = pack_gc_topic_info(packed_topic, packet_buf_size, &chat->topic_info);

    int err = -3;

    if (packed_len != packet_buf_size) {
        goto ON_ERROR;
    }

    if (crypto_sign_detached(chat->topic_sig, nullptr, packed_topic, packed_len, get_sig_sk(chat->self_secret_key)) == -1) {
        goto ON_ERROR;
    }

    if (broadcast_gc_topic(chat) == -1) {
        err = -4;
        goto ON_ERROR;
    }

    free(packed_topic);
    return 0;

ON_ERROR:
    memcpy(&chat->topic_info, &old_topic_info, sizeof(GC_TopicInfo));
    memcpy(chat->topic_sig, old_topic_sig, SIGNATURE_SIZE);
    free(packed_topic);
    return err;
}

void gc_get_topic(const GC_Chat *chat, uint8_t *topic)
{
    if (topic != nullptr) {
        memcpy(topic, chat->topic_info.topic, chat->topic_info.length);
    }
}

uint16_t gc_get_topic_size(const GC_Chat *chat)
{
    return chat->topic_info.length;
}

/* If public_sig_key is equal to the key of the topic setter, replaces topic credentials
 * and re-broadcast the updated topic info to the group.
 *
 * Returns 0 on success
 * Returns -1 on failure.
 */
static int update_gc_topic(GC_Chat *chat, const uint8_t *public_sig_key)
{
    if (memcmp(public_sig_key, chat->topic_info.public_sig_key, SIG_PUBLIC_KEY_SIZE) != 0) {
        return 0;
    }

    if (gc_set_topic(chat, chat->topic_info.topic, chat->topic_info.length) != 0) {
        return -1;
    }

    return 0;
}

/* Validates `topic_info`.
 *
 * Return true if topic info is valid.
 */
static bool handle_gc_topic_validate(const GC_Chat *chat, uint32_t peer_number, const GC_TopicInfo *topic_info,
                                     bool topic_lock_enabled)
{
    if (topic_info->checksum != get_gc_topic_checksum(topic_info)) {
        LOGGER_WARNING(chat->logger, "received invalid topic checksum");
        return false;
    }

    if (topic_lock_enabled) {
        if (!mod_list_verify_sig_pk(chat, topic_info->public_sig_key)) {
            LOGGER_WARNING(chat->logger, "Invalid topic signature (bad credentials)");
            return false;
        }

        if (topic_info->version < chat->topic_info.version) {
            return false;
        }
    } else {
        if (sanctions_list_is_observer_sig(chat, topic_info->public_sig_key)) {
            LOGGER_WARNING(chat->logger, "Invalid topic signature (sanctioned peeer attempted to change topic)");
            return false;
        }

        // the topic version should never change when the topic lock is disabled except when
        // the founder changes the topic prior to enabling the lock
        if (topic_info->version == chat->shared_state.topic_lock) {
            return true;
        }

        const Group_Role role = chat->group[peer_number].role;

        if (!(role == GR_FOUNDER && topic_info->version == chat->shared_state.topic_lock + 1)) {
            LOGGER_ERROR(chat->logger, "topic version %u differs from topic lock %u", topic_info->version,
                         chat->shared_state.topic_lock);
            return false;
        }
    }

    return true;
}

/* Handles a topic packet.
 *
 * Return 0 if packet is correctly handled.
 * Return -1 if packet is invalid size.
 * Return -2 if group number is invalid.
 */
static int handle_gc_topic(Messenger *m, int group_number, uint32_t peer_number, const uint8_t *data,
                           uint32_t length, void *userdata)
{
    if (length > SIGNATURE_SIZE + MAX_GC_TOPIC_SIZE + GC_MIN_PACKED_TOPIC_INFO_SIZE) {
        return -1;
    }

    if (length < SIGNATURE_SIZE + GC_MIN_PACKED_TOPIC_INFO_SIZE) {
        return -1;
    }

    const GC_Session *c = m->group_handler;
    GC_Chat *chat = gc_get_group(c, group_number);

    if (chat == nullptr) {
        return -2;
    }

    GC_TopicInfo topic_info;

    if (unpack_gc_topic_info(&topic_info, data + SIGNATURE_SIZE, length - SIGNATURE_SIZE) == -1) {
        LOGGER_WARNING(chat->logger, "failed to unpack topic");
        return 0;
    }

    const uint8_t *signature = data;

    if (crypto_sign_verify_detached(signature, data + SIGNATURE_SIZE, length - SIGNATURE_SIZE,
                                    topic_info.public_sig_key) == -1) {
        LOGGER_WARNING(chat->logger, "failed to verify topic signature");
        return -4;
    }

    const bool topic_lock_enabled = group_topic_lock_enabled(chat);

    if (!handle_gc_topic_validate(chat, peer_number, &topic_info, topic_lock_enabled)) {
        return 0;
    }

    // prevents sync issues from triggering the callback needlessly
    const bool skip_callback = chat->topic_info.length == topic_info.length
                               && memcmp(chat->topic_info.topic, topic_info.topic, topic_info.length) == 0;

    memcpy(&chat->topic_info, &topic_info, sizeof(GC_TopicInfo));
    memcpy(chat->topic_sig, signature, SIGNATURE_SIZE);

    if (!skip_callback && chat->connection_state == CS_CONNECTED && c->topic_change) {
        const int setter_peer_number = get_peer_number_of_sig_pk(chat, topic_info.public_sig_key);
        const uint32_t peer_id = setter_peer_number >= 0 ? chat->group[setter_peer_number].peer_id : 0;

        (*c->topic_change)(m, group_number, peer_id, topic_info.topic, topic_info.length, userdata);
    }

    return 0;
}

/* Handles a key exchange packet.
 *
 * Return 0 if packet is handled correctly.
 * Return -1 if length is invalid.
 * Return -2 if group_number is invalid.
 * Return -3 if response packet fails to send.
 */
static int handle_gc_key_exchange(Messenger *m, int group_number, GC_Connection *gconn, const uint8_t *data,
                                  uint32_t length)
{
    if (length != 1 + ENC_PUBLIC_KEY_SIZE) {
        return -1;
    }

    const GC_Session *c = m->group_handler;
    GC_Chat *chat = gc_get_group(c, group_number);

    if (chat == nullptr) {
        return -2;
    }

    const uint8_t is_response = data[0];

    if (is_response > 1) {
        return 0;
    }

    const uint8_t *sender_public_session_key = data + 1;

    if (is_response) {
        if (!gconn->pending_key_rotation_request) {
            LOGGER_WARNING(m->log, "got unsolicited key rotation response from peer %u", gconn->public_key_hash);
            return 0;
        }

        // now that we have response we can compute our new shared key and begin using it
        gcc_make_session_shared_key(gconn, sender_public_session_key);

        gconn->pending_key_rotation_request = false;

        return 0;
    }

    // key generation is pretty cpu intensive so we make sure a peer can't DOS us by spamming requests
    if (!mono_time_is_timeout(m->mono_time, gconn->last_key_rotation, GC_KEY_ROTATION_TIMEOUT / 2)) {
        return 0;
    }

    uint8_t response[1 + ENC_PUBLIC_KEY_SIZE];
    uint8_t new_session_pk[ENC_PUBLIC_KEY_SIZE];
    uint8_t new_session_sk[ENC_SECRET_KEY_SIZE];

    response[0] = 1;

    if (create_gc_session_keypair(new_session_pk, new_session_sk) != 0) {
        LOGGER_FATAL(chat->logger, "Failed to create session keypair");
        return -3;
    }

    crypto_memlock(new_session_sk, sizeof(new_session_sk));

    memcpy(response + 1, new_session_pk, ENC_PUBLIC_KEY_SIZE);

    if (send_lossless_group_packet(chat, gconn, response, sizeof(response), GP_KEY_ROTATION) != 0) {
        return -3;
    }

    // save new keys and compute new shared key AFTER sending reponse packet with old key
    memcpy(gconn->session_public_key, new_session_pk, sizeof(gconn->session_public_key));
    memcpy(gconn->session_secret_key, new_session_sk, sizeof(gconn->session_secret_key));

    gcc_make_session_shared_key(gconn, sender_public_session_key);

    crypto_memunlock(new_session_sk, sizeof(new_session_sk));

    gconn->last_key_rotation = mono_time_get(chat->mono_time);

    return 0;
}

void gc_get_group_name(const GC_Chat *chat, uint8_t *group_name)
{
    if (group_name) {
        memcpy(group_name, chat->shared_state.group_name, chat->shared_state.group_name_len);
    }
}

uint16_t gc_get_group_name_size(const GC_Chat *chat)
{
    return chat->shared_state.group_name_len;
}

void gc_get_password(const GC_Chat *chat, uint8_t *password)
{
    if (password) {
        memcpy(password, chat->shared_state.password, chat->shared_state.password_length);
    }
}

uint16_t gc_get_password_size(const GC_Chat *chat)
{
    return chat->shared_state.password_length;
}

int gc_founder_set_password(GC_Chat *chat, const uint8_t *password, uint16_t password_length)
{
    if (!self_gc_is_founder(chat)) {
        return -1;
    }

    uint8_t *oldpasswd = nullptr;
    const uint16_t oldlen = chat->shared_state.password_length;

    if (oldlen > 0) {
        oldpasswd = (uint8_t *)malloc(oldlen);

        if (oldpasswd == nullptr) {
            return -4;
        }

        memcpy(oldpasswd, chat->shared_state.password, oldlen);
    }

    if (set_gc_password_local(chat, password, password_length) == -1) {
        free(oldpasswd);
        return -2;
    }

    if (sign_gc_shared_state(chat) == -1) {
        set_gc_password_local(chat, oldpasswd, oldlen);
        free(oldpasswd);
        return -2;
    }

    free(oldpasswd);

    if (broadcast_gc_shared_state(chat) == -1) {
        return -3;
    }

    return 0;
}

/* Validates change to moderator list and either adds or removes peer from our moderator list.
 *
 * Return target's peer number on success.
 * Return -1 on packet handle failure.
 * Return -2 if target peer is not online.
 * Return -3 if target peer is not a valid role (probably indicates sync issues).
 * Return -4 on validation failure.
 */
static int validate_unpack_gc_set_mod(GC_Chat *chat, uint32_t peer_number, const uint8_t *data, size_t length,
                                      bool add_mod)
{
    int target_peer_number;
    uint8_t mod_data[GC_MOD_LIST_ENTRY_SIZE];

    if (add_mod) {
        if (length < 1 + GC_MOD_LIST_ENTRY_SIZE) {
            return -1;
        }

        memcpy(mod_data, data + 1, GC_MODERATION_HASH_SIZE);
        target_peer_number = get_peer_number_of_sig_pk(chat, mod_data);

        if (!gc_peer_number_is_valid(chat, target_peer_number)) {
            return -2;
        }

        if (chat->group[target_peer_number].role == GR_FOUNDER
                || peer_is_moderator(chat, target_peer_number)
                || peer_is_observer(chat, target_peer_number)) {
            return -3;
        }

        if (peer_number == target_peer_number) {
            return -1;
        }

        if (mod_list_add_entry(chat, mod_data) == -1) {
            return -4;
        }
    } else {
        memcpy(mod_data, data + 1, SIG_PUBLIC_KEY_SIZE);
        target_peer_number = get_peer_number_of_sig_pk(chat, mod_data);

        if (!gc_peer_number_is_valid(chat, target_peer_number)) {
            return -2;
        }

        if (chat->group[target_peer_number].role == GR_FOUNDER
                || !peer_is_moderator(chat, target_peer_number)
                || peer_is_observer(chat, target_peer_number)) {
            return -3;
        }

        if (peer_number == target_peer_number) {
            return -1;
        }

        if (mod_list_remove_entry(chat, mod_data) == -1) {
            return -4;
        }
    }

    if (update_gc_peer_roles(chat) == -1) {
        return -3;
    }

    return target_peer_number;
}

/* Handles a moderator set broadcast.
 *
 * Return 0 if packet is handled correctly.
 * Return -1 if packet is invalid size.
 * Return -2 if group number is invalid.
 * Return -3 if the packet contains invalid data.
 */
static int handle_gc_set_mod(Messenger *m, int group_number, uint32_t peer_number, const uint8_t *data,
                             uint32_t length, void *userdata)
{
    if (length < 1 + SIG_PUBLIC_KEY_SIZE) {
        return -1;
    }

    const GC_Session *c = m->group_handler;
    GC_Chat *chat = gc_get_group(c, group_number);

    if (chat == nullptr) {
        return -2;
    }

    if (!peer_is_founder(chat, peer_number)) {
        return 0;
    }

    const bool add_mod = data[0] != 0;

    int target_peer_number = validate_unpack_gc_set_mod(chat, peer_number, data, length, add_mod);

    if (target_peer_number == -1) {
        return -3;
    }

    if (target_peer_number < 0) {
        return 0;
    }

    if (update_gc_peer_roles(chat) != 0) {
        LOGGER_WARNING(chat->logger, "Failed to update peer roles");
        return send_gc_random_sync_request(chat, GF_STATE);
    }

    if (c->moderation) {
        (*c->moderation)(m, group_number, chat->group[peer_number].peer_id, chat->group[target_peer_number].peer_id,
                         add_mod ? MV_MOD : MV_USER, userdata);
    }

    return 0;
}

/* Sends a set mod broadcast to the group.
 *
 * Return 0 on success.
 * Return -1 on failure.
 */
static int send_gc_set_mod(const GC_Chat *chat, GC_Connection *gconn, bool add_mod)
{
    const uint32_t length = 1 + SIG_PUBLIC_KEY_SIZE;
    uint8_t *data = (uint8_t *)malloc(length);

    if (data == nullptr) {
        return -1;
    }

    data[0] = add_mod ? 1 : 0;
    memcpy(data + 1, get_sig_pk(gconn->addr.public_key), SIG_PUBLIC_KEY_SIZE);

    if (send_gc_broadcast_message(chat, data, length, GM_SET_MOD) == -1) {
        free(data);
        return -1;
    }

    free(data);

    return 0;
}

/* Adds or removes the peer designated by gconn from moderator list if `add_mod` is true or false respectively.
 * Re-signs and re-distributes an updated mod_list hash.
 *
 * Returns 0 on success.
 * Returns -1 on failure.
 */
static int founder_gc_set_moderator(GC_Chat *chat, GC_Connection *gconn, bool add_mod)
{
    if (!self_gc_is_founder(chat)) {
        return -1;
    }

    if (add_mod) {
        if (chat->moderation.num_mods >= MAX_GC_MODERATORS) {
            if (prune_gc_mod_list(chat) != 0) {
                return -1;
            }
        }

        if (mod_list_add_entry(chat, get_sig_pk(gconn->addr.public_key)) == -1) {
            return -1;
        }
    } else {
        if (mod_list_remove_entry(chat, get_sig_pk(gconn->addr.public_key)) == -1) {
            return -1;
        }

        if (update_gc_sanctions_list(chat,  get_sig_pk(gconn->addr.public_key)) == -1) {
            return -1;
        }

        if (update_gc_topic(chat, get_sig_pk(gconn->addr.public_key)) == -1) {
            return -1;
        }
    }

    uint8_t old_hash[GC_MODERATION_HASH_SIZE];
    memcpy(old_hash, chat->shared_state.mod_list_hash, GC_MODERATION_HASH_SIZE);

    if (mod_list_make_hash(chat, chat->shared_state.mod_list_hash) == -1) {
        return -1;
    }

    if (sign_gc_shared_state(chat) == -1) {
        memcpy(chat->shared_state.mod_list_hash, old_hash, GC_MODERATION_HASH_SIZE);
        return -1;
    }

    if (broadcast_gc_shared_state(chat) == -1) {
        memcpy(chat->shared_state.mod_list_hash, old_hash, GC_MODERATION_HASH_SIZE);
        return -1;
    }

    if (send_gc_set_mod(chat, gconn, add_mod) == -1) {
        return -1;
    }

    return 0;
}

/* Validates `data` containing a changes for the sanction list and unpacks it
 * into the sanctions list for `chat`.
 *
 * if `add_obs` is true we're adding an observer to the list.
 *
 * Return 1 if sanctions list is not modified.
 * Return 0 if data is valid and sanctions list is successfully modified.
 * Return -1 if data is invalid format.
 */
static int validate_unpack_observer_entry(GC_Chat *chat, const uint8_t *data, uint32_t length,
        const uint8_t *public_key,
        bool add_obs)
{
    struct GC_Sanction_Creds creds;

    if (add_obs) {
        struct GC_Sanction sanction;

        if (sanctions_list_unpack(&sanction, &creds, 1, data, length, nullptr) != 1) {
            return -1;
        }

        // this may occur if two mods change the sanctions list at the exact same time
        if (creds.version == chat->moderation.sanctions_creds.version
                && creds.checksum <= chat->moderation.sanctions_creds.checksum) {
            return 1;
        }

        if (sanctions_list_entry_exists(chat, &sanction)) {
            return 1;
        }

        if (sanctions_list_add_entry(chat, &sanction, &creds) == -1) {
            return 1;
        }
    } else {
        if (sanctions_creds_unpack(&creds, data, length) != GC_SANCTIONS_CREDENTIALS_SIZE) {
            return -1;
        }

        if (creds.version == chat->moderation.sanctions_creds.version
                && creds.checksum <= chat->moderation.sanctions_creds.checksum) {
            return 1;
        }

        if (!sanctions_list_is_observer(chat, public_key)) {
            return 1;
        }

        if (sanctions_list_remove_observer(chat, public_key, &creds) == -1) {
            return 1;
        }
    }

    return 0;
}

/* Handles a set observer broadcast.
 *
 * Return 0 if packet is handled correctly.
 * Return -1 if packet is an invalid size.
 * Return -2 if group number is invalid.
 * Return -3 if the packet contains invalid data.
 */
static int handle_gc_set_observer(Messenger *m, int group_number, uint32_t peer_number, const uint8_t *data,
                                  uint32_t length, void *userdata)
{
    if (length <= 1 + EXT_PUBLIC_KEY_SIZE) {
        return -1;
    }

    const GC_Session *c = m->group_handler;
    GC_Chat *chat = gc_get_group(c, group_number);

    if (chat == nullptr) {
        return -2;
    }

    if (!peer_is_moderator(chat, peer_number)) {
        LOGGER_DEBUG(chat->logger, "peer with insufficient permissions tried to modify sanctions list");
        return 0;
    }

    const bool add_obs = data[0] != 0;

    const uint8_t *public_key = data + 1;

    if (mod_list_verify_sig_pk(chat, get_sig_pk(public_key))) {
        LOGGER_WARNING(chat->logger, "peer with moderator role is not in moderator list");
        return 0;
    }

    const int target_peer_number = get_peer_number_of_enc_pk(chat, public_key, false);

    if (target_peer_number == peer_number) {
        return -3;
    }

    if (peer_is_founder(chat, target_peer_number) || peer_is_moderator(chat, target_peer_number)) {
        return 0;
    }

    const bool is_observer = peer_is_observer(chat, target_peer_number);

    if ((add_obs && is_observer) || (!add_obs && !is_observer)) {
        return 0;
    }

    const int ret = validate_unpack_observer_entry(chat,
                    data + 1 + EXT_PUBLIC_KEY_SIZE,
                    length - 1 - EXT_PUBLIC_KEY_SIZE,
                    public_key, add_obs);

    if (ret == -1) {
        return -3;
    }

    if (ret == 1) {
        return 0;
    }

    if (update_gc_peer_roles(chat) != 0) {
        LOGGER_WARNING(chat->logger, "Failed to update peer roles");
        send_gc_random_sync_request(chat, GF_STATE);
        return 0;
    }

    const GC_Connection *target_gconn = gcc_get_connection(chat, target_peer_number);

    if (target_gconn != nullptr) {
        if (c->moderation) {
            (*c->moderation)(m, group_number, chat->group[peer_number].peer_id,
                             chat->group[target_peer_number].peer_id,
                             add_obs ? MV_OBSERVER : MV_USER, userdata);
        }
    }

    return 0;
}

/* Broadcasts observer role data to the group.
 *
 * Returns 0 on success.
 * Returns -1 on failure.
 */
static int send_gc_set_observer(const GC_Chat *chat, const uint8_t *target_ext_pk, const uint8_t *sanction_data,
                                uint32_t length, bool add_obs)
{
    const uint32_t packet_len = 1 + EXT_PUBLIC_KEY_SIZE + length;
    uint8_t *packet = (uint8_t *)malloc(packet_len);

    if (packet == nullptr) {
        return -1;
    }

    packet[0] = add_obs ? 1 : 0;
    memcpy(packet + 1, target_ext_pk, EXT_PUBLIC_KEY_SIZE);
    memcpy(packet + 1 + EXT_PUBLIC_KEY_SIZE, sanction_data, length);

    if (send_gc_broadcast_message(chat, packet, packet_len, GM_SET_OBSERVER) == -1) {
        free(packet);
        return -1;
    }

    free(packet);

    return 0;
}

/* Adds or removes peer_number from the observer list if add_obs is true or false respectively.
 * Broadcasts this change to the entire group.
 *
 * Returns 0 on success.
 * Returns -1 on failure.
 */
static int mod_gc_set_observer(GC_Chat *chat, uint32_t peer_number, bool add_obs)
{
    GC_Connection *gconn = gcc_get_connection(chat, peer_number);

    if (gconn == nullptr) {
        return -1;
    }

    if (gc_get_self_role(chat) >= GR_USER) {
        return -1;
    }

    uint8_t sanction_data[sizeof(struct GC_Sanction) + sizeof(struct GC_Sanction_Creds)];
    uint32_t length = 0;

    if (add_obs) {
        if (chat->moderation.num_sanctions >= MAX_GC_SANCTIONS) {
            if (prune_gc_sanctions_list(chat) != 0) {
                return -1;
            }
        }

        // if sanctioned peer set the topic we need to overwrite his signature and redistribute topic info
        const int setter_peer_number = get_peer_number_of_sig_pk(chat, chat->topic_info.public_sig_key);

        if (setter_peer_number == peer_number) {
            if (gc_set_topic(chat, chat->topic_info.topic, chat->topic_info.length) != 0) {
                return -1;
            }
        }

        struct GC_Sanction sanction;

        if (sanctions_list_make_entry(chat, peer_number, &sanction, SA_OBSERVER) == -1) {
            LOGGER_WARNING(chat->logger, "sanctions_list_make_entry failed in mod_gc_set_observer");
            return -1;
        }

        const int packed_len = sanctions_list_pack(sanction_data, sizeof(sanction_data), &sanction,
                               &chat->moderation.sanctions_creds, 1);

        if (packed_len == -1) {
            return -1;
        }

        length += packed_len;
    } else {
        if (sanctions_list_remove_observer(chat, gconn->addr.public_key, nullptr) == -1) {
            LOGGER_WARNING(chat->logger, "failed to remove sanction");
            return -1;
        }

        const uint16_t packed_len = sanctions_creds_pack(&chat->moderation.sanctions_creds, sanction_data,
                                    sizeof(sanction_data));

        if (packed_len != GC_SANCTIONS_CREDENTIALS_SIZE) {
            return -1;
        }

        length += packed_len;
    }

    if (update_gc_peer_roles(chat) == -1) {
        send_gc_random_sync_request(chat, GF_STATE);
        return -1;
    }

    if (send_gc_set_observer(chat, gconn->addr.public_key, sanction_data, length, add_obs) == -1) {
        return -1;
    }

    return 0;
}

/* Sets the role of `peer_number` to `new_role`. If necessary this function will first
 * remove the peer's current role before applying the new one.
 *
 * Return 0 on success.
 * Return -1 on failure.
 */
static int apply_new_gc_role(GC_Chat *chat, uint32_t peer_number, Group_Role current_role, Group_Role new_role)
{
    GC_Connection *gconn = gcc_get_connection(chat, peer_number);

    if (gconn == nullptr) {
        return -1;
    }

    switch (current_role) {
        case GR_MODERATOR: {
            if (founder_gc_set_moderator(chat, gconn, false) == -1) {
                return -1;
            }

            if (update_gc_peer_roles(chat) == -1) {
                send_gc_random_sync_request(chat, GF_STATE);
                return -1;
            }

            if (new_role == GR_OBSERVER) {
                return mod_gc_set_observer(chat, peer_number, true);
            }

            break;
        }

        case GR_OBSERVER: {
            if (mod_gc_set_observer(chat, peer_number, false) == -1) {
                return -1;
            }

            if (update_gc_peer_roles(chat) == -1) {
                send_gc_random_sync_request(chat, GF_STATE);
                return -1;
            }

            if (new_role == GR_MODERATOR) {
                return founder_gc_set_moderator(chat, gconn, true);
            }

            break;
        }

        case GR_USER: {
            if (new_role == GR_MODERATOR) {
                return founder_gc_set_moderator(chat, gconn, true);
            } else if (new_role == GR_OBSERVER) {
                return mod_gc_set_observer(chat, peer_number, true);
            }

            break;
        }

        case GR_FOUNDER:

        // Intentional fallthrough
        default: {
            return -1;
        }
    }

    return 0;
}

int gc_set_peer_role(const Messenger *m, int group_number, uint32_t peer_id, Group_Role new_role)
{
    const GC_Session *c = m->group_handler;
    GC_Chat *chat = gc_get_group(c, group_number);

    if (chat == nullptr) {
        return -1;
    }

    const int peer_number = get_peer_number_of_peer_id(chat, peer_id);

    GC_Connection *gconn = gcc_get_connection(chat, peer_number);

    if (gconn == nullptr) {
        return -2;
    }

    if (!gconn->confirmed) {
        return -2;
    }

    const Group_Role current_role = chat->group[peer_number].role;

    if (new_role == GR_FOUNDER || chat->group[peer_number].role == new_role) {
        return -4;
    }

    if (peer_number_is_self(peer_number)) {
        return -6;
    }

    if (current_role == GR_FOUNDER || gc_get_self_role(chat) >= GR_USER) {
        return -3;
    }

    // moderators can't demote moderators or promote peers to moderator
    if (!self_gc_is_founder(chat) && (new_role == GR_MODERATOR || current_role == GR_MODERATOR)) {
        return -3;
    }

    if (apply_new_gc_role(chat, peer_number, current_role, new_role) == -1) {
        return -5;
    }

    if (update_gc_peer_roles(chat) == -1) {
        send_gc_random_sync_request(chat, GF_STATE);
        return -5;
    }

    return 0;
}

/* Return true if topic lock is enabled */
static bool group_topic_lock_enabled(const GC_Chat *chat)
{
    return chat->shared_state.topic_lock == 0;
}

Group_Privacy_State gc_get_privacy_state(const GC_Chat *chat)
{
    return (Group_Privacy_State) chat->shared_state.privacy_state;
}

Group_Topic_Lock gc_get_topic_lock_state(const GC_Chat *chat)
{
    return group_topic_lock_enabled(chat) ? TL_ENABLED : TL_DISABLED;
}

int gc_founder_set_topic_lock(Messenger *m, int group_number, Group_Topic_Lock new_lock_state)
{
    const GC_Session *c = m->group_handler;
    GC_Chat *chat = gc_get_group(c, group_number);

    if (chat == nullptr) {
        return -1;
    }

    if (!self_gc_is_founder(chat)) {
        return -3;
    }

    if (chat->connection_state <= CS_DISCONNECTED) {
        return -4;
    }

    const Group_Topic_Lock old_lock_state = gc_get_topic_lock_state(chat);

    if (new_lock_state == old_lock_state) {
        return 0;
    }

    const uint32_t old_topic_lock = chat->shared_state.topic_lock;

    // If we're enabling the lock the founder needs to sign the current topic and re-broadcast
    // it with a new verison. This needs to happen before we re-broadcast the shared state because
    // if it fails we don't want to enable the topic lock with an invalid topic signature or version.
    if (new_lock_state == TL_ENABLED) {
        chat->shared_state.topic_lock = 0;

        if (gc_set_topic(chat, chat->topic_info.topic, chat->topic_info.length) != 0) {
            return -6;
        }
    } else {
        chat->shared_state.topic_lock = chat->topic_info.version;
    }

    if (sign_gc_shared_state(chat) == -1) {
        chat->shared_state.topic_lock = old_topic_lock;
        return -5;
    }

    // TODO(Jfreegman): handle this failure properly
    if (broadcast_gc_shared_state(chat) == -1) {
        return -6;
    }

    return 0;
}

int gc_founder_set_privacy_state(Messenger *m, int group_number, Group_Privacy_State new_privacy_state)
{
    const GC_Session *c = m->group_handler;
    GC_Chat *chat = gc_get_group(c, group_number);

    if (chat == nullptr) {
        return -1;
    }

    if (!self_gc_is_founder(chat)) {
        return -2;
    }

    if (chat->connection_state == CS_DISCONNECTED || chat->connection_state == CS_NONE) {
        return -3;
    }

    const Group_Privacy_State old_privacy_state = chat->shared_state.privacy_state;

    if (new_privacy_state == old_privacy_state) {
        return 0;
    }

    chat->shared_state.privacy_state = new_privacy_state;

    if (sign_gc_shared_state(chat) == -1) {
        chat->shared_state.privacy_state = old_privacy_state;
        return -4;
    }

    if (new_privacy_state == GI_PRIVATE) {
        cleanup_gca(c->announces_list, get_chat_id(chat->chat_public_key));
        m_kill_group_connection(c->messenger, chat);
    } else {
        if (m_create_group_connection(c->messenger, chat) == -1) {
            LOGGER_ERROR(chat->logger, "Failed to initialize group friend connection");
        } else {
            chat->update_self_announces = true;
        }
    }

    if (broadcast_gc_shared_state(chat) == -1) {
        return -5;
    }

    return 0;
}

/* Returns the group peer limit. */
uint32_t gc_get_max_peers(const GC_Chat *chat)
{
    return chat->shared_state.maxpeers;
}

int gc_founder_set_max_peers(GC_Chat *chat, uint32_t max_peers)
{
    if (!self_gc_is_founder(chat)) {
        return -1;
    }

    const uint32_t old_maxpeers = chat->shared_state.maxpeers;

    if (max_peers == chat->shared_state.maxpeers) {
        return 0;
    }

    chat->shared_state.maxpeers = max_peers;

    if (sign_gc_shared_state(chat) == -1) {
        chat->shared_state.maxpeers = old_maxpeers;
        return -2;
    }

    if (broadcast_gc_shared_state(chat) == -1) {
        return -3;
    }

    return 0;
}

int gc_send_message(const GC_Chat *chat, const uint8_t *message, uint16_t length, uint8_t type)
{
    if (length > MAX_GC_MESSAGE_SIZE) {
        return -1;
    }

    if (message == nullptr || length == 0) {
        return -2;
    }

    if (type != GC_MESSAGE_TYPE_NORMAL && type != GC_MESSAGE_TYPE_ACTION) {
        return -3;
    }

    if (gc_get_self_role(chat) >= GR_OBSERVER) {
        return -4;
    }

    const uint8_t packet_type = type == GC_MESSAGE_TYPE_NORMAL ? GM_PLAIN_MESSAGE : GM_ACTION_MESSAGE;

    if (send_gc_broadcast_message(chat, message, length, packet_type) == -1) {
        return -5;
    }

    return 0;
}

/* Handles a message broadcast.
 *
 * Return 0 if packet is handled correctly.
 * Return -1 if packet is invalid size.
 * Return -2 if group number is invalid.
 */
static int handle_gc_message(Messenger *m, int group_number, uint32_t peer_number, const uint8_t *data, uint32_t length,
                             uint8_t type, void *userdata)
{
    if (data == nullptr || length > MAX_GC_MESSAGE_SIZE || length == 0) {
        return -1;
    }

    const GC_Session *c = m->group_handler;
    const GC_Chat *chat = gc_get_group(c, group_number);

    if (chat == nullptr) {
        return -2;
    }

    if (chat->group[peer_number].ignore || chat->group[peer_number].role >= GR_OBSERVER) {
        return 0;
    }

    if (type != GM_PLAIN_MESSAGE && type != GM_ACTION_MESSAGE) {
        LOGGER_WARNING(chat->logger, "received invalid message type: %u", type);
        return 0;
    }

    const uint8_t cb_type = (type == GM_PLAIN_MESSAGE) ? MESSAGE_NORMAL : MESSAGE_ACTION;

    if (c->message) {
        (*c->message)(m, group_number, chat->group[peer_number].peer_id, cb_type, data, length, userdata);
    }

    return 0;
}

int gc_send_private_message(const GC_Chat *chat, uint32_t peer_id, uint8_t type, const uint8_t *message,
                            uint16_t length)
{
    if (length > MAX_GC_MESSAGE_SIZE) {
        return -1;
    }

    if (message == nullptr || length == 0) {
        return -2;
    }

    const int peer_number = get_peer_number_of_peer_id(chat, peer_id);

    GC_Connection *gconn = gcc_get_connection(chat, peer_number);

    if (gconn == nullptr) {
        return -3;
    }

    if (type > MESSAGE_ACTION) {
        return -4;
    }

    if (gc_get_self_role(chat) >= GR_OBSERVER) {
        return -5;
    }

    uint8_t *message_with_type = (uint8_t *)malloc(length + 1);

    if (message_with_type == nullptr) {
        return -6;
    }

    message_with_type[0] = type;
    memcpy(message_with_type + 1, message, length);

    uint8_t *packet = (uint8_t *)malloc(length + 1 + GC_BROADCAST_ENC_HEADER_SIZE);

    if (packet == nullptr) {
        free(message_with_type);
        return -6;
    }

    const uint32_t packet_len = make_gc_broadcast_header(chat, message_with_type, length + 1, packet, GM_PRIVATE_MESSAGE);

    free(message_with_type);

    if (send_lossless_group_packet(chat, gconn, packet, packet_len, GP_BROADCAST) == -1) {
        free(packet);
        return -6;
    }

    free(packet);

    return 0;
}

/* Handles a private message.
 *
 * Return 0 if packet is handled correctly.
 * Return -1 if packet is invalid size.
 * Reutrn -2 if group number is invalid.
 */
static int handle_gc_private_message(Messenger *m, int group_number, uint32_t peer_number, const uint8_t *data,
                                     uint32_t length, void *userdata)
{
    if (data == nullptr || length > MAX_GC_MESSAGE_SIZE || length <= 1) {
        return -1;
    }

    const GC_Session *c = m->group_handler;
    const GC_Chat *chat = gc_get_group(c, group_number);

    if (chat == nullptr) {
        return -2;
    }

    if (chat->group[peer_number].ignore || chat->group[peer_number].role >= GR_OBSERVER) {
        return 0;
    }

    const uint8_t message_type = data[0];

    if (message_type > MESSAGE_ACTION) {
        LOGGER_WARNING(chat->logger, "Received invalid private message type: %u", message_type);
        return 0;
    }

    if (c->private_message) {
        (*c->private_message)(m, group_number, chat->group[peer_number].peer_id, message_type, data + 1, length - 1, userdata);
    }

    return 0;
}

int gc_send_custom_packet(const GC_Chat *chat, bool lossless, const uint8_t *data, uint32_t length)
{
    if (length > MAX_GC_MESSAGE_SIZE) {
        return -1;
    }

    if (data == nullptr || length == 0) {
        return -2;
    }

    if (gc_get_self_role(chat) >= GR_OBSERVER) {
        return -3;
    }

    if (lossless) {
        send_gc_lossless_packet_all_peers(chat, data, length, GP_CUSTOM_PACKET);
    } else {
        send_gc_lossy_packet_all_peers(chat, data, length, GP_CUSTOM_PACKET);
    }

    return 0;
}

/* Handles a custom packet.
 *
 * Return 0 if packet is handled correctly.
 * Return -1 if packet is invalid size.
 * Return -2 if group number is invalid.
 */
static int handle_gc_custom_packet(Messenger *m, int group_number, uint32_t peer_number, const uint8_t *data,
                                   uint32_t length, void *userdata)
{
    if (data == nullptr || length == 0 || length > MAX_GC_MESSAGE_SIZE) {
        return -1;
    }

    const GC_Session *c = m->group_handler;
    const GC_Chat *chat = gc_get_group(c, group_number);

    if (chat == nullptr) {
        return -2;
    }

    if (chat->group[peer_number].ignore || chat->group[peer_number].role >= GR_OBSERVER) {
        return 0;
    }

    if (c->custom_packet) {
        (*c->custom_packet)(m, group_number, chat->group[peer_number].peer_id, data, length, userdata);
    }

    return 0;
}

/* Handles a peer kick broadcast.
 *
 * Return 0 if packet is handled correctly.
 * Return -1 if packet is invalid size.
 * Return -2 if group number is invalid.
 * Return -3 if the kicker does not have a privileged group role.
 * Return -4 if the target peer is not the User role (the kicker should first set target to User role).
 */
static int handle_gc_kick_peer(Messenger *m, int group_number, uint32_t peer_number, const uint8_t *data,
                               uint32_t length, void *userdata)
{
    if (length != ENC_PUBLIC_KEY_SIZE) {
        return -1;
    }

    const GC_Session *c = m->group_handler;
    GC_Chat *chat = gc_get_group(m->group_handler, group_number);

    if (chat == nullptr) {
        return -2;
    }

    if (chat->group[peer_number].role >= GR_USER) {
        return 0;
    }

    const uint8_t *target_pk = data;

    const int target_peer_number = get_peer_number_of_enc_pk(chat, target_pk, false);
    const bool peer_number_valid = gc_peer_number_is_valid(chat, target_peer_number);

    if (peer_number_valid) {
        if (chat->group[target_peer_number].role != GR_USER) {
            return -4;
        }
    }

    if (peer_number_is_self(target_peer_number)) {
        if (c->moderation) {
            (*c->moderation)(m, group_number, chat->group[peer_number].peer_id,
                             chat->group[target_peer_number].peer_id, MV_KICK, userdata);
        }

        for (uint32_t i = 1; i < chat->numpeers; ++i) {
            gcc_mark_for_deletion(&chat->gcc[i], chat->tcp_conn, GC_EXIT_TYPE_SELF_DISCONNECTED, nullptr, 0);
        }

        chat->connection_state = CS_DISCONNECTED;

        return 0;
    }

    if (!peer_number_valid) {   /* we don't need to/can't kick a peer that isn't in our peerlist */
        return 0;
    }

    if (c->moderation) {
        (*c->moderation)(m, group_number, chat->group[peer_number].peer_id, chat->group[target_peer_number].peer_id,
                         MV_KICK, userdata);
    }

    gcc_mark_for_deletion(&chat->gcc[target_peer_number], chat->tcp_conn, GC_EXIT_TYPE_KICKED, nullptr, 0);

    return 0;
}

/* Sends a packet to instruct all peers to remove gconn from their peerlist.
 *
 * Returns 0 on success.
 * Returns -1 on failure.
 */
static int send_gc_kick_peer(const GC_Chat *chat, GC_Connection *gconn)
{
    uint8_t packet[ENC_PUBLIC_KEY_SIZE];
    memcpy(packet, gconn->addr.public_key, ENC_PUBLIC_KEY_SIZE);

    return send_gc_broadcast_message(chat, packet, ENC_PUBLIC_KEY_SIZE, GM_KICK_PEER);
}

int gc_kick_peer(Messenger *m, int group_number, uint32_t peer_id)
{
    const GC_Session *c = m->group_handler;
    GC_Chat *chat = gc_get_group(c, group_number);

    if (chat == nullptr) {
        return -1;
    }

    const int peer_number = get_peer_number_of_peer_id(chat, peer_id);

    if (peer_number_is_self(peer_number)) {
        return -6;
    }

    GC_Connection *gconn = gcc_get_connection(chat, peer_number);

    if (gconn == nullptr) {
        return -2;
    }

    if (!gconn->confirmed) {
        return -2;
    }

    if (gc_get_self_role(chat) >= GR_USER || chat->group[peer_number].role == GR_FOUNDER) {
        return -3;
    }

    if (!self_gc_is_founder(chat) && chat->group[peer_number].role == GR_MODERATOR) {
        return -3;
    }

    if (chat->group[peer_number].role == GR_MODERATOR || chat->group[peer_number].role == GR_OBSERVER) {
        /* this first removes peer from any lists they're on and broadcasts new lists to group */
        if (gc_set_peer_role(m, group_number, peer_id, GR_USER) < 0) {
            return -4;
        }
    }

    if (send_gc_kick_peer(chat, gconn) == -1) {
        return -5;
    }

    gcc_mark_for_deletion(gconn, chat->tcp_conn, GC_EXIT_TYPE_NO_CALLBACK, nullptr, 0);

    return 0;
}

/* Sends a lossless message acknowledgement to peer associated with `gconn`.
 *
 * If `type` is GR_ACK_RECV we send a read-receipt for read_id's packet. If `type` is GR_ACK_REQ
 * we send a request for the respective id's packet.
 *
 * requests are limited to one per second per peer.
 *
 * Return 0 on success.
 * Return -1 on failure.
 */
int gc_send_message_ack(const GC_Chat *chat, GC_Connection *gconn, uint64_t message_id, Group_Message_Ack_Type type)
{
    if (gconn->pending_delete) {
        return 0;
    }

    if (type == GR_ACK_REQ) {
        const uint64_t tm = mono_time_get(chat->mono_time);

        if (gconn->last_requested_packet_time == tm) {
            return 0;
        }

        gconn->last_requested_packet_time = tm;
    } else if (type == GR_ACK_RECV) {
        uint8_t data[GC_LOSSLESS_ACK_PACKET_SIZE];

        data[0] = (uint8_t) type;
        net_pack_u64(data + 1, message_id);

        return send_lossy_group_packet(chat, gconn, data, GC_LOSSLESS_ACK_PACKET_SIZE, GP_MESSAGE_ACK);
    }

    return -1;
}

/* Handles a lossless message acknowledgement. If the type is of GR_ACK_RECV we remove the packet from our
 * send array. If the type is of GR_ACK_REQ we re-send the packet associated with the requested message_id.
 *
 * Returns 0 if packet is handled correctly.
 * Return -1 if packet is invalid size.
 * Return -2 if we failed to handle the ack (may be caused by connection issues).
 * Return -3 if we failed to re-send a requested packet.
 */
static int handle_gc_message_ack(const GC_Chat *chat, GC_Connection *gconn, const uint8_t *data, uint32_t length)
{
    if (length != GC_LOSSLESS_ACK_PACKET_SIZE) {
        return -1;
    }

    uint64_t message_id;
    net_unpack_u64(data + 1, &message_id);

    const Group_Message_Ack_Type type = (Group_Message_Ack_Type) data[0];

    if (type == GR_ACK_RECV) {
        if (gcc_handle_ack(gconn, message_id) != 0) {
            return -2;
        }

        return 0;
    }

    if (type != GR_ACK_REQ) {
        return 0;
    }

    const uint64_t tm = mono_time_get(chat->mono_time);
    const uint16_t idx = gcc_get_array_index(message_id);

    /* re-send requested packet */
    if (gconn->send_array[idx].message_id == message_id) {
        if (gcc_encrypt_and_send_lossless_packet(chat, gconn, gconn->send_array[idx].data,
                gconn->send_array[idx].data_length,
                gconn->send_array[idx].message_id,
                gconn->send_array[idx].packet_type) == 0) {
            gconn->send_array[idx].last_send_try = tm;
            LOGGER_DEBUG(chat->logger, "Re-sent requested packet %llu", (unsigned long long)message_id);
        } else {
            return -3;
        }
    }

    return 0;
}

/* Sends a handshake response ack to peer.
 *
 * Returns non-negative value on success.
 * Returns -1 on failure.
 */
static int send_gc_hs_response_ack(const GC_Chat *chat, GC_Connection *gconn)
{
    return send_lossless_group_packet(chat, gconn, nullptr, 0, GP_HS_RESPONSE_ACK);
}

/* Handles a handshake response ack.
 *
 * Return 0 if packet is handled correctly.
 * Return -1 if group number is invalid.
 * Return -2 if we failed to respond with an invite request.
 */
static int handle_gc_hs_response_ack(Messenger *m, int group_number, GC_Connection *gconn)
{
    GC_Chat *chat = gc_get_group(m->group_handler, group_number);

    if (chat == nullptr) {
        return -1;
    }

    gconn->handshaked = true;  // has to be true before we can send a lossless packet

    if (send_gc_invite_request(chat, gconn) == -1) {
        gconn->handshaked = false;
        return -2;
    }

    return 0;
}

int gc_toggle_ignore(GC_Chat *chat, uint32_t peer_id, bool ignore)
{
    const int peer_number = get_peer_number_of_peer_id(chat, peer_id);

    if (!gc_peer_number_is_valid(chat, peer_number)) {
        return -1;
    }

    if (peer_number_is_self(peer_number)) {
        return -2;
    }

    chat->group[peer_number].ignore = ignore;

    return 0;
}

/* Handles a broadcast packet.
 *
 * Returns 0 if packet is handled correctly.
 * Returns -1 on failure.
 */
static int handle_gc_broadcast(Messenger *m, int group_number, uint32_t peer_number, const uint8_t *data,
                               uint32_t length, void *userdata)
{
    if (length < GC_BROADCAST_ENC_HEADER_SIZE) {
        return -1;
    }

    const GC_Session *c = m->group_handler;
    const GC_Chat *chat = gc_get_group(c, group_number);

    if (chat == nullptr) {
        return -1;
    }

    GC_Connection *gconn = gcc_get_connection(chat, peer_number);

    if (gconn == nullptr) {
        return -1;
    }

    if (!gconn->confirmed) {
        return -1;
    }

    uint8_t broadcast_type = data[0];

    const uint32_t m_len = length - 1;
    const uint8_t *message = data + 1;

    int ret = 0;

    switch (broadcast_type) {
        case GM_STATUS: {
            ret = handle_gc_status(m, group_number, peer_number, message, m_len, userdata);
            break;
        }

        case GM_NICK: {
            ret = handle_gc_nick(m, group_number, peer_number, message, m_len, userdata);
            break;
        }

        case GM_ACTION_MESSAGE:

        // intentional fallthrough
        case GM_PLAIN_MESSAGE: {
            ret = handle_gc_message(m, group_number, peer_number, message, m_len, broadcast_type, userdata);
            break;
        }

        case GM_PRIVATE_MESSAGE: {
            ret = handle_gc_private_message(m, group_number, peer_number, message, m_len, userdata);
            break;
        }

        case GM_PEER_EXIT: {
            ret = handle_gc_peer_exit(m, group_number, peer_number, message, m_len);
            break;
        }

        case GM_KICK_PEER: {
            ret = handle_gc_kick_peer(m, group_number, peer_number, message, m_len, userdata);
            break;
        }

        case GM_SET_MOD: {
            ret = handle_gc_set_mod(m, group_number, peer_number, message, m_len, userdata);
            break;
        }

        case GM_SET_OBSERVER: {
            ret = handle_gc_set_observer(m, group_number, peer_number, message, m_len, userdata);
            break;
        }

        default: {
            LOGGER_DEBUG(m->log, "Received an invalid broadcast type %u", broadcast_type);
            break;
        }
    }

    if (ret < 0) {
        LOGGER_WARNING(m->log, "Broadcast handle error %d: type: %u, peernumber: %u", ret, broadcast_type, peer_number);
        return -1;
    }

    return 0;
}

/* Decrypts data of size `length` using self secret key and sender's public key.
 *
 * The packet payload should begin with a nonce.
 *
 * Returns length of plaintext data on success.
 * Returns -1 on failure.
 */
static int unwrap_group_handshake_packet(const Logger *logger, const uint8_t *self_sk, const uint8_t *sender_pk,
        uint8_t *plain, size_t plain_size, const uint8_t *packet, uint16_t length)
{
    if (length <= CRYPTO_NONCE_SIZE) {
        LOGGER_FATAL(logger, "Invalid packet length %u", length);
        return -1;
    }

    const int plain_len = decrypt_data(sender_pk, self_sk, packet, packet + CRYPTO_NONCE_SIZE,
                                       length - CRYPTO_NONCE_SIZE, plain);

    if (plain_len != plain_size) {
        LOGGER_WARNING(logger, "decrypt handshake request failed: len: %d, size: %zu", plain_len, plain_size);
        return -1;
    }

    return plain_len;
}

/* Encrypts data of length using the peer's shared key a new nonce.
 *
 * Adds plaintext header consisting of: packet identifier, target public encryption key,
 * self public encryption key, nonce.
 *
 * Returns length of encrypted packet on success.
 * Returns -1 on failure.
 */
static int wrap_group_handshake_packet(const Logger *logger, const uint8_t *self_pk, const uint8_t *self_sk,
                                       const uint8_t *target_pk, uint8_t *packet, uint32_t packet_size,
                                       const uint8_t *data, uint16_t length)
{
    if (packet_size != GC_MIN_ENCRYPTED_HS_PAYLOAD_SIZE + sizeof(Node_format)) {
        LOGGER_FATAL(logger, "Invalid packet size: %u", packet_size);
        return -1;
    }

    uint8_t nonce[CRYPTO_NONCE_SIZE];
    random_nonce(nonce);

    const size_t encrypt_buf_size = length + CRYPTO_MAC_SIZE;
    uint8_t *encrypt = (uint8_t *)malloc(encrypt_buf_size);

    if (encrypt == nullptr) {
        return -1;
    }

    const int enc_len = encrypt_data(target_pk, self_sk, nonce, data, length, encrypt);

    if (enc_len != encrypt_buf_size) {
        LOGGER_ERROR(logger, "Failed to encrypt group handshake packet (len: %d)", enc_len);
        free(encrypt);
        return -1;
    }

    packet[0] = NET_PACKET_GC_HANDSHAKE;
    memcpy(packet + 1, self_pk, ENC_PUBLIC_KEY_SIZE);
    memcpy(packet + 1 + ENC_PUBLIC_KEY_SIZE, target_pk, ENC_PUBLIC_KEY_SIZE);
    memcpy(packet + 1 + ENC_PUBLIC_KEY_SIZE + ENC_PUBLIC_KEY_SIZE, nonce, CRYPTO_NONCE_SIZE);
    memcpy(packet + 1 + ENC_PUBLIC_KEY_SIZE + ENC_PUBLIC_KEY_SIZE + CRYPTO_NONCE_SIZE, encrypt, enc_len);

    free(encrypt);

    return 1 + ENC_PUBLIC_KEY_SIZE + ENC_PUBLIC_KEY_SIZE + CRYPTO_NONCE_SIZE + enc_len;
}

/* Makes, wraps and encrypts a group handshake packet (both request and response are the same format).
 *
 * Packet contains the packet header, handshake type, self public encryption key, self public signature key,
 * request type, join type, and a single TCP relay node.
 *
 * Returns length of encrypted packet on success.
 * Returns -1 on failure.
 */
static int make_gc_handshake_packet(const GC_Chat *chat, GC_Connection *gconn, uint8_t handshake_type,
                                    uint8_t request_type, uint8_t *packet, size_t packet_size,
                                    Node_format *node)
{
    if (packet_size != GC_MIN_ENCRYPTED_HS_PAYLOAD_SIZE + sizeof(Node_format)) {
        LOGGER_FATAL(chat->logger, "invlaid packet size: %zu", packet_size);
        return -1;
    }

    if (chat == nullptr || gconn == nullptr || node == nullptr) {
        return -1;
    }

    uint8_t data[GC_MIN_HS_PACKET_PAYLOAD_SIZE + sizeof(Node_format)];

    uint16_t length = sizeof(uint8_t);

    data[0] = handshake_type;
    memcpy(data + length, gconn->session_public_key, ENC_PUBLIC_KEY_SIZE);
    length += ENC_PUBLIC_KEY_SIZE;
    memcpy(data + length, get_sig_pk(chat->self_public_key), SIG_PUBLIC_KEY_SIZE);
    length += SIG_PUBLIC_KEY_SIZE;
    memcpy(data + length, &request_type, sizeof(uint8_t));
    length += sizeof(uint8_t);

    int nodes_size = pack_nodes(data + length, sizeof(Node_format), node, MAX_SENT_GC_NODES);

    if (nodes_size > 0) {
        length += nodes_size;
    } else {
        nodes_size = 0;
    }

    const int enc_len = wrap_group_handshake_packet(chat->logger, chat->self_public_key, chat->self_secret_key,
                        gconn->addr.public_key, packet, packet_size, data, length);

    if (enc_len != GC_MIN_ENCRYPTED_HS_PAYLOAD_SIZE + nodes_size) {
        return -1;
    }

    return enc_len;
}

/* Sends a handshake packet to `gconn`.
 *
 * Handshake_type should be is GH_REQUEST or GH_RESPONSE.
 *
 * Returns 0 on success.
 * Returns -1 on failure.
 */
static int send_gc_handshake_packet(const GC_Chat *chat, GC_Connection *gconn, uint8_t handshake_type,
                                    uint8_t request_type)
{
    if (gconn == nullptr) {
        return -1;
    }

    Node_format node[GCA_MAX_ANNOUNCED_TCP_RELAYS] = {0};

    gcc_copy_tcp_relay(node, gconn);

    uint8_t packet[GC_MIN_ENCRYPTED_HS_PAYLOAD_SIZE + sizeof(Node_format)];
    const int length = make_gc_handshake_packet(chat, gconn, handshake_type, request_type, packet,
                       sizeof(packet), node);

    if (length < 0) {
        return -1;
    }

    int ret = -1;

    if (gcc_direct_conn_is_possible(chat, gconn)) {
        ret = sendpacket(chat->net, gconn->addr.ip_port, packet, length);
    }

    if (ret != length) {
        if (send_packet_tcp_connection(chat->tcp_conn, gconn->tcp_connection_num, packet, length) == -1) {
            LOGGER_WARNING(chat->logger, "Send handshake packet failed. Type %u", request_type);
            return -1;
        }
    }


    if (request_type == HS_PEER_INFO_EXCHANGE) {
        gconn->handshaked = true;
    }

    if (gconn->is_pending_handshake_response) {
        gcc_set_send_message_id(gconn, 3);  // handshake response is always second packet
    }  else {
        gcc_set_send_message_id(gconn, 2);  // handshake request is always first packet
    }

    return 0;
}

/* Sends an out-of-band TCP handshake request packet to `gconn`.
 *
 * Return 0 on success.
 * Return -1 on failure.
 */
static int send_gc_oob_handshake_request(const GC_Chat *chat, GC_Connection *gconn)
{
    if (gconn == nullptr) {
        return -1;
    }

    Node_format node[1] = {0};

    if (gcc_copy_tcp_relay(node, gconn) == -1) {
        LOGGER_WARNING(chat->logger, "Failed to copy TCP relay");
        return -1;
    }

    uint8_t packet[GC_MIN_ENCRYPTED_HS_PAYLOAD_SIZE + sizeof(Node_format)];
    const int length = make_gc_handshake_packet(chat, gconn, GH_REQUEST, gconn->pending_handshake_type,
                       packet, sizeof(packet), node);

    if (length < 0) {
        LOGGER_WARNING(chat->logger, "Failed to make handshake packet");
        return -1;
    }

    return tcp_send_oob_packet_using_relay(chat->tcp_conn, gconn->oob_relay_pk, gconn->addr.public_key, packet, length);
}

/* Handles a handshake response packet and takes appropriate action depending on the value of request_type.
 *
 * This function assumes the length has already been validated.
 *
 * Returns peer_number of new connected peer on success.
 * Returns -1 on failure.
 */
static int handle_gc_handshake_response(const Messenger *m, int group_number, const uint8_t *sender_pk,
                                        const uint8_t *data, uint16_t length)
{
    const GC_Chat *chat = gc_get_group(m->group_handler, group_number);

    if (chat == nullptr) {
        return -1;
    }

    if (length < ENC_PUBLIC_KEY_SIZE + SIG_PUBLIC_KEY_SIZE + 1) {  // should be checked at lower level
        LOGGER_FATAL(chat->logger, "Invlaid handshake response size (%u)", length);
        return -1;
    }

    const int peer_number = get_peer_number_of_enc_pk(chat, sender_pk, false);

    if (peer_number == -1) {
        return -1;
    }

    GC_Connection *gconn = gcc_get_connection(chat, peer_number);

    if (gconn == nullptr) {
        return -1;
    }

    const uint8_t *sender_session_pk = data;

    gcc_make_session_shared_key(gconn, sender_session_pk);

    set_sig_pk(gconn->addr.public_key, data + ENC_PUBLIC_KEY_SIZE);

    gcc_set_recv_message_id(gconn, 2);  // handshake response is always second packet

    gconn->handshaked = true;

    send_gc_hs_response_ack(chat, gconn);

    const uint8_t request_type = data[ENC_PUBLIC_KEY_SIZE + SIG_PUBLIC_KEY_SIZE];

    switch (request_type) {
        case HS_INVITE_REQUEST: {
            if (send_gc_invite_request(chat, gconn) == -1) {
                return -1;
            }

            break;
        }

        case HS_PEER_INFO_EXCHANGE: {
            if (send_gc_peer_exchange(m->group_handler, chat, gconn) == -1) {
                return -1;
            }

            break;
        }

        default: {
            return -1;
        }
    }

    return peer_number;
}

/* Sends a handshake response packet of type `request_type` to `gconn`.
 *
 * Return 0 on success.
 * Return -1 on failure.
 */
static int send_gc_handshake_response(const GC_Chat *chat, GC_Connection *gconn)
{
    if (send_gc_handshake_packet(chat, gconn, GH_RESPONSE, gconn->pending_handshake_type) == -1) {
        return -1;
    }

    return 0;
}

/* Handles handshake request packets.
 *
 * Peer is added to peerlist and a lossless connection is established.
 *
 * This function assumes the length has already been validated.
 *
 * Return new peer's peer_number on success.
 * Return -1 on failure.
 */
#define GC_NEW_PEER_CONNECTION_LIMIT 10
static int handle_gc_handshake_request(Messenger *m, int group_number, const IP_Port *ipp, const uint8_t *sender_pk,
                                       const uint8_t *data, uint32_t length)
{
    GC_Chat *chat = gc_get_group(m->group_handler, group_number);

    if (chat == nullptr) {
        return -1;
    }

    if (length < ENC_PUBLIC_KEY_SIZE + SIG_PUBLIC_KEY_SIZE + 1) {  // should be checked at lower level
        LOGGER_FATAL(chat->logger, "Invalid length (%u)", length);
        return -1;
    }

    if (chat->connection_state <= CS_DISCONNECTED) {
        return -1;
    }

    if (chat->connection_O_metre >= GC_NEW_PEER_CONNECTION_LIMIT) {
        chat->block_handshakes = true;
        LOGGER_DEBUG(m->log, "Handshake overflow. Blocking handshakes.");
        return -1;
    }

    ++chat->connection_O_metre;

    const uint8_t *public_sig_key = data + ENC_PUBLIC_KEY_SIZE;

    const uint8_t request_type = data[ENC_PUBLIC_KEY_SIZE + SIG_PUBLIC_KEY_SIZE];

    int peer_number = get_peer_number_of_enc_pk(chat, sender_pk, false);
    const bool is_new_peer = peer_number < 0;

    if (is_new_peer) {
        peer_number = peer_add(m, chat->group_number, ipp, sender_pk);

        if (peer_number < 0) {
            LOGGER_WARNING(chat->logger, "Failed to add peer during handshake request");
            return -1;
        }
    } else  {
        GC_Connection *gconn = gcc_get_connection(chat, peer_number);

        if (gconn == nullptr) {
            return -1;
        }

        if (gconn->handshaked) {
            gconn->handshaked = false;
            LOGGER_DEBUG(chat->logger, "Handshaked peer sent a handshake request");
            return -1;
        }

        // peers sent handshake request at same time so the closer peer becomes the requestor
        // and ignores the request packet while further peer continues on with the response
        if (gconn->self_is_closer) {
            return 0;
        }
    }

    GC_Connection *gconn = gcc_get_connection(chat, peer_number);

    if (gconn == nullptr) {
        return -1;
    }

    gcc_set_ip_port(gconn, ipp);

    Node_format node[GCA_MAX_ANNOUNCED_TCP_RELAYS];
    const int processed = ENC_PUBLIC_KEY_SIZE + SIG_PUBLIC_KEY_SIZE + 1;

    const int nodes_count = unpack_nodes(node, GCA_MAX_ANNOUNCED_TCP_RELAYS, nullptr,
                                         data + processed, length - processed, 1);

    if (nodes_count <= 0 && ipp == nullptr) {
        if (is_new_peer) {
            LOGGER_WARNING(m->log, "broken tcp relay for new peer");
            gcc_mark_for_deletion(gconn, chat->tcp_conn, GC_EXIT_TYPE_DISCONNECTED, nullptr, 0);
        }

        return -1;
    }

    if (nodes_count > 0) {
        const int add_tcp_result = add_tcp_relay_connection(chat->tcp_conn, gconn->tcp_connection_num,
                                   node->ip_port, node->public_key);

        if (add_tcp_result < 0 && is_new_peer && ipp == nullptr) {
            LOGGER_WARNING(m->log, "broken tcp relay for new peer");
            gcc_mark_for_deletion(gconn, chat->tcp_conn, GC_EXIT_TYPE_DISCONNECTED, nullptr, 0);
            return -1;
        }

        if (add_tcp_result == 0) {
            gcc_save_tcp_relay(gconn, node);
        }
    }

    const uint8_t *sender_session_pk = data;

    gcc_make_session_shared_key(gconn, sender_session_pk);

    set_sig_pk(gconn->addr.public_key, public_sig_key);

    gcc_set_recv_message_id(gconn, 1);  // handshake request is always first packet

    gconn->is_pending_handshake_response = true;
    gconn->pending_handshake_type = request_type;

    return peer_number;
}

/* Handles handshake request and handshake response packets.
 *
 * Returns the peer_number of the connecting peer on success.
 * Returns -1 on failure.
 */
static int handle_gc_handshake_packet(Messenger *m, const GC_Chat *chat, const uint8_t *sender_pk, const IP_Port *ipp,
                                      const uint8_t *packet, uint16_t length, bool direct_conn, void *userdata)
{

    if (length < GC_MIN_HS_PACKET_PAYLOAD_SIZE + CRYPTO_MAC_SIZE + CRYPTO_NONCE_SIZE) {
        return -1;
    }

    const size_t data_buf_size = length - CRYPTO_NONCE_SIZE - CRYPTO_MAC_SIZE;
    uint8_t *data = (uint8_t *)malloc(data_buf_size);

    if (data == nullptr) {
        return -1;
    }

    const int plain_len = unwrap_group_handshake_packet(m->log, chat->self_secret_key, sender_pk, data, data_buf_size,
                          packet, length);

    if (plain_len < GC_MIN_HS_PACKET_PAYLOAD_SIZE)  {
        LOGGER_WARNING(m->log, "Got malformed handshake packet");
        free(data);
        return -1;
    }

    uint8_t handshake_type = data[0];

    const uint8_t *real_data = data + 1;
    const uint16_t real_len = plain_len - 1;

    int peer_number = -1;

    if (handshake_type == GH_REQUEST) {
        peer_number = handle_gc_handshake_request(m, chat->group_number, ipp, sender_pk, real_data, real_len);
    } else if (handshake_type == GH_RESPONSE) {
        peer_number = handle_gc_handshake_response(m, chat->group_number, sender_pk, real_data, real_len);
    } else {
        free(data);
        return -1;
    }

    free(data);

    GC_Connection *gconn = gcc_get_connection(chat, peer_number);

    if (gconn == nullptr) {
        return -1;
    }

    if (direct_conn) {
        gconn->last_received_direct_time = mono_time_get(chat->mono_time);
    }

    return peer_number;
}

/* Helper function for handle_gc_lossless_packet().
 *
 * Return 0 and send message ack if packet is successfully handled.
 * Return -1 on failure.
 */
int handle_gc_lossless_helper(Messenger *m, int group_number, uint32_t peer_number, const uint8_t *data,
                              uint16_t length, uint64_t message_id, uint8_t packet_type, void *userdata)
{
    const GC_Session *c = m->group_handler;
    const GC_Chat *chat = gc_get_group(c, group_number);

    if (chat == nullptr) {
        return -1;
    }

    GC_Connection *gconn = gcc_get_connection(chat, peer_number);

    if (gconn == nullptr) {
        return -1;
    }

    int ret = -1;

    switch (packet_type) {
        case GP_BROADCAST: {
            ret = handle_gc_broadcast(m, group_number, peer_number, data, length, userdata);
            break;
        }

        case GP_PEER_INFO_REQUEST: {
            ret = handle_gc_peer_info_request(m, group_number, gconn);
            break;
        }

        case GP_PEER_INFO_RESPONSE: {
            ret = handle_gc_peer_info_response(m, group_number, peer_number, data, length, userdata);
            break;
        }

        case GP_SYNC_REQUEST: {
            ret = handle_gc_sync_request(m, group_number, peer_number, gconn, data, length);
            break;
        }

        case GP_SYNC_RESPONSE: {
            ret = handle_gc_sync_response(m, group_number, peer_number, data, length, userdata);
            break;
        }

        case GP_INVITE_REQUEST: {
            ret = handle_gc_invite_request(m, group_number, peer_number, data, length);
            break;
        }

        case GP_INVITE_RESPONSE: {
            ret = handle_gc_invite_response(m, group_number, gconn, data, length);
            break;
        }

        case GP_TOPIC: {
            ret = handle_gc_topic(m, group_number, peer_number, data, length, userdata);
            break;
        }

        case GP_SHARED_STATE: {
            ret = handle_gc_shared_state(m, group_number, peer_number, data, length, userdata);
            break;
        }

        case GP_MOD_LIST: {
            ret = handle_gc_mod_list(m, group_number, peer_number, data, length, userdata);
            break;
        }

        case GP_SANCTIONS_LIST: {
            ret = handle_gc_sanctions_list(m, group_number, peer_number, data, length, userdata);
            break;
        }

        case GP_HS_RESPONSE_ACK: {
            ret = handle_gc_hs_response_ack(m, group_number, gconn);
            break;
        }

        case GP_TCP_RELAYS: {
            ret = handle_gc_tcp_relays(m, group_number, gconn, data, length);
            break;
        }

        case GP_KEY_ROTATION: {
            ret = handle_gc_key_exchange(m, group_number, gconn, data, length);
            break;
        }

        case GP_CUSTOM_PACKET: {
            ret = handle_gc_custom_packet(m, group_number, peer_number, data, length, userdata);
            break;
        }

        default: {
            LOGGER_DEBUG(m->log, "Handling invalid lossless group packet type %u", packet_type);
            return -1;
        }
    }

    if (ret < 0) {
        LOGGER_DEBUG(m->log, "Lossless packet handle error %d: type %d, peernumber: %d",
                     ret, packet_type, peer_number);
        return -1;
    }

    return 0;
}

/* Handles lossless groupchat packets.
 *
 * This function assumes the length has already been validated.
 *
 * Returns 0 if packet is successfully handled.
 * Returns -1 on failure.
 */
static int handle_gc_lossless_packet(Messenger *m, const GC_Chat *chat, const uint8_t *sender_pk,
                                     const uint8_t *packet, uint16_t length, bool direct_conn, void *userdata)
{
    if (length < GC_MIN_LOSSLESS_PAYLOAD_SIZE) {
        return -1;
    }

    int peer_number = get_peer_number_of_enc_pk(chat, sender_pk, false);

    GC_Connection *gconn = gcc_get_connection(chat, peer_number);

    if (gconn == nullptr) {
        return -1;
    }

    if (gconn->pending_delete) {
        return 0;
    }

    uint8_t data[MAX_GC_PACKET_SIZE];
    uint8_t packet_type;
    uint64_t message_id;

    const int len = group_packet_unwrap(m->log, gconn, data, &message_id, &packet_type, packet, length);

    if (len < 0) {
        LOGGER_DEBUG(m->log, "Failed to unwrap lossless packet: %d", len);
        return -1;
    }

    if (!gconn->handshaked && (packet_type != GP_HS_RESPONSE_ACK && packet_type != GP_INVITE_REQUEST)) {
        LOGGER_DEBUG(m->log, "Got lossless packet type %d from unconfirmed peer", packet_type);
        return -1;
    }

    const bool is_invite_packet = packet_type == GP_INVITE_REQUEST || packet_type == GP_INVITE_RESPONSE
                                  || packet_type == GP_INVITE_RESPONSE_REJECT;

    if (message_id == 3 && is_invite_packet && gconn->received_message_id <= 1) {
        // we missed initial handshake request. Drop this packet and wait for another handshake request.
        LOGGER_WARNING(m->log, "Missed handshake packet, type: %d", packet_type);
        return -1;
    }

    const int lossless_ret = gcc_handle_received_message(chat, peer_number, data, len, packet_type, message_id,
                             direct_conn);

    if (packet_type == GP_INVITE_REQUEST && !gconn->handshaked) {  // Both peers sent request at same time
        return 0;
    }

    if (lossless_ret < 0) {
        LOGGER_WARNING(m->log, "failed to handle packet %llu (type %u, id %llu)",
                       (unsigned long long)message_id, packet_type, (unsigned long long)message_id);
        return -1;
    }

    /* Duplicate packet */
    if (lossless_ret == 0) {
        // LOGGER_DEBUG(m->log, "got duplicate packet from peer %u. ID: %lu, type: %u)",
        //              peer_number, message_id, packet_type);
        return gc_send_message_ack(chat, gconn, message_id, GR_ACK_RECV);
    }

    /* request missing packet */
    if (lossless_ret == 1) {
        LOGGER_DEBUG(m->log, "received out of order packet from peer %u. expected %llu, got %llu", peer_number,
                     (unsigned long long)gconn->received_message_id + 1, (unsigned long long)message_id);
        return gc_send_message_ack(chat, gconn, gconn->received_message_id + 1, GR_ACK_REQ);
    }

    const int ret = handle_gc_lossless_helper(m, chat->group_number, peer_number, data, len, message_id, packet_type,
                    userdata);

    if (ret < 0) {
        return -1;
    }

    /* peer number can change from peer add operations in packet handlers */
    peer_number = get_peer_number_of_enc_pk(chat, sender_pk, false);
    gconn = gcc_get_connection(chat, peer_number);

    if (gconn != nullptr && lossless_ret == 2) {
        gc_send_message_ack(chat, gconn, message_id, GR_ACK_RECV);
    }

    return 0;
}

/* Handles lossy groupchat message packets.
 *
 * This function assumes the length has already been validated.
 *
 * return 0 if packet is handled successfully.
 * return -1 on failure.
 */
static int handle_gc_lossy_packet(Messenger *m, const GC_Chat *chat, const uint8_t *sender_pk, const uint8_t *packet,
                                  uint16_t length, bool direct_conn, void *userdata)
{
    if (length < GC_MIN_LOSSY_PAYLOAD_SIZE) {
        return -1;
    }

    const int peer_number = get_peer_number_of_enc_pk(chat, sender_pk, false);

    GC_Connection *gconn = gcc_get_connection(chat, peer_number);

    if (gconn == nullptr) {
        return -1;
    }

    if (!gconn->handshaked || gconn->pending_delete) {
        LOGGER_WARNING(m->log, "Got lossy packet from invalid peer");
        return -1;
    }

    uint8_t data[MAX_GC_PACKET_SIZE];
    uint8_t packet_type;

    const int len = group_packet_unwrap(m->log, gconn, data, nullptr, &packet_type, packet, length);

    if (len <= 0) {
        LOGGER_DEBUG(m->log, "Failed to unwrap lossy packet");
        return -1;
    }

    int ret = -1;

    switch (packet_type) {
        case GP_MESSAGE_ACK: {
            ret = handle_gc_message_ack(chat, gconn, data, len);
            break;
        }

        case GP_PING: {
            ret = handle_gc_ping(m, chat->group_number, gconn, data, len);
            break;
        }

        case GP_INVITE_RESPONSE_REJECT: {
            ret = handle_gc_invite_response_reject(m, chat->group_number, data, len, userdata);
            break;
        }

        case GP_CUSTOM_PACKET: {
            ret = handle_gc_custom_packet(m, chat->group_number, peer_number, data, len, userdata);
            break;
        }

        default: {
            LOGGER_WARNING(m->log, "Warning: handling invalid lossy group packet type %u", packet_type);
            return -1;
        }
    }

    if (ret >= 0 && direct_conn) {
        gconn->last_received_direct_time = mono_time_get(m->mono_time);
    }

    if (ret < 0) {
        LOGGER_WARNING(m->log, "Lossy packet handle error %d: type %d, peernumber %d", ret, packet_type, peer_number);
        return -1;
    }

    return 0;
}

/* Return true if group is either connected or attempting to connect. */
static bool group_can_handle_packets(const GC_Chat *chat)
{
    const GC_Conn_State state = chat->connection_state;
    return state == CS_CONNECTING || state == CS_CONNECTED;
}

/* Sends a group packet to appropriate handler function.
 *
 * Returns non-negative value on success.
 * Returns -1 on failure.
 */
static int handle_gc_tcp_packet(void *object, int id, const uint8_t *packet, uint16_t length, void *userdata)
{
    if (length <= 1 + ENC_PUBLIC_KEY_SIZE + CRYPTO_NONCE_SIZE + CRYPTO_MAC_SIZE || length > MAX_GC_PACKET_SIZE) {
        return -1;
    }

    Messenger *m = (Messenger *)object;

    if (m == nullptr) {
        return -1;
    }

    const uint8_t packet_type = packet[0];

    const uint8_t *sender_pk = packet + 1;

    const GC_Session *c = m->group_handler;
    const GC_Chat *chat = nullptr;

    if (packet_type == NET_PACKET_GC_HANDSHAKE) {
        chat = get_chat_by_id(c, packet + 1 + ENC_PUBLIC_KEY_SIZE);
    } else {
        chat = get_chat_by_id(c, sender_pk);
    }

    if (chat == nullptr) {
        return -1;
    }

    if (!group_can_handle_packets(chat)) {
        return -1;
    }

    const uint8_t *payload = packet + 1 + ENC_PUBLIC_KEY_SIZE;
    size_t payload_len = length - 1 - ENC_PUBLIC_KEY_SIZE;

    switch (packet_type) {
        case NET_PACKET_GC_LOSSLESS: {
            return handle_gc_lossless_packet(m, chat, sender_pk, payload, payload_len, false, userdata);
        }

        case NET_PACKET_GC_LOSSY: {
            return handle_gc_lossy_packet(m, chat, sender_pk, payload, payload_len, false, userdata);
        }

        case NET_PACKET_GC_HANDSHAKE: {
            // handshake packets have an extra public key in plaintext header
            if (length <= 1 + ENC_PUBLIC_KEY_SIZE + ENC_PUBLIC_KEY_SIZE + CRYPTO_NONCE_SIZE + CRYPTO_MAC_SIZE) {
                return -1;
            }

            payload_len = payload_len - ENC_PUBLIC_KEY_SIZE;
            payload = payload + ENC_PUBLIC_KEY_SIZE;

            return handle_gc_handshake_packet(m, chat, sender_pk, nullptr, payload, payload_len, false, userdata);
        }

        default: {
            return -1;
        }
    }
}

static int handle_gc_tcp_oob_packet(void *object, const uint8_t *public_key, unsigned int tcp_connections_number,
                                    const uint8_t *packet, uint16_t length, void *userdata)
{
    if (length <= 1 + ENC_PUBLIC_KEY_SIZE + ENC_PUBLIC_KEY_SIZE + CRYPTO_NONCE_SIZE + CRYPTO_MAC_SIZE) {
        return -1;
    }

    if (length > MAX_GC_PACKET_SIZE) {
        return -1;
    }

    Messenger *m = (Messenger *)object;

    if (m == nullptr) {
        return -1;
    }

    const GC_Session *c = m->group_handler;
    const GC_Chat *chat = get_chat_by_id(c, packet + 1 + ENC_PUBLIC_KEY_SIZE);

    if (chat == nullptr) {
        return -1;
    }

    if (!group_can_handle_packets(chat)) {
        return -1;
    }

    const uint8_t packet_type = packet[0];

    if (packet_type != NET_PACKET_GC_HANDSHAKE) {
        return -1;
    }

    const uint8_t *sender_pk = packet + 1;

    const uint8_t *payload = packet + 1 + ENC_PUBLIC_KEY_SIZE + ENC_PUBLIC_KEY_SIZE;
    const size_t payload_len = length - 1 - ENC_PUBLIC_KEY_SIZE - ENC_PUBLIC_KEY_SIZE;

    if (payload_len < GC_MIN_HS_PACKET_PAYLOAD_SIZE + CRYPTO_MAC_SIZE + CRYPTO_NONCE_SIZE) {
        return -1;
    }

    if (handle_gc_handshake_packet(m, chat, sender_pk, nullptr, payload, payload_len, false, userdata) == -1) {
        return -1;
    }

    return 0;
}

static int handle_gc_udp_packet(void *object, IP_Port ipp, const uint8_t *packet, uint16_t length, void *userdata)
{
    if (length <= 1 + ENC_PUBLIC_KEY_SIZE + CRYPTO_NONCE_SIZE + CRYPTO_MAC_SIZE || length > MAX_GC_PACKET_SIZE) {
        return -1;
    }

    Messenger *m = (Messenger *)object;

    if (m == nullptr) {
        return -1;
    }

    const uint8_t packet_type = packet[0];

    const uint8_t *sender_pk = packet + 1;

    const GC_Session *c = m->group_handler;
    const GC_Chat *chat = nullptr;

    if (packet_type == NET_PACKET_GC_HANDSHAKE) {
        chat = get_chat_by_id(c, packet + 1 + ENC_PUBLIC_KEY_SIZE);
    } else {
        chat = get_chat_by_id(c, sender_pk);
    }

    if (chat == nullptr) {
        return -1;
    }

    if (!group_can_handle_packets(chat)) {
        return -1;
    }

    const uint8_t *payload = packet + 1 + ENC_PUBLIC_KEY_SIZE;
    size_t payload_len = length - 1 - ENC_PUBLIC_KEY_SIZE;

    switch (packet_type) {
        case NET_PACKET_GC_LOSSLESS: {
            return handle_gc_lossless_packet(m, chat, sender_pk, payload, payload_len, true, userdata);
        }

        case NET_PACKET_GC_LOSSY: {
            return handle_gc_lossy_packet(m, chat, sender_pk, payload, payload_len, true, userdata);
        }

        case NET_PACKET_GC_HANDSHAKE: {
            // handshake packets have an extra public key in plaintext header
            if (length <= 1 + ENC_PUBLIC_KEY_SIZE + ENC_PUBLIC_KEY_SIZE + CRYPTO_NONCE_SIZE + CRYPTO_MAC_SIZE) {
                return -1;
            }

            payload_len = payload_len - ENC_PUBLIC_KEY_SIZE;
            payload = payload + ENC_PUBLIC_KEY_SIZE;

            return handle_gc_handshake_packet(m, chat, sender_pk, &ipp, payload, payload_len, true, userdata);
        }

        default: {
            return -1;
        }
    }
}

void gc_callback_message(Messenger *m, gc_message_cb *function)
{
    GC_Session *c = m->group_handler;
    c->message = function;
}

void gc_callback_private_message(Messenger *m, gc_private_message_cb *function)
{
    GC_Session *c = m->group_handler;
    c->private_message = function;
}

void gc_callback_custom_packet(Messenger *m, gc_custom_packet_cb *function)
{
    GC_Session *c = m->group_handler;
    c->custom_packet = function;
}

void gc_callback_moderation(Messenger *m, gc_moderation_cb *function)
{
    GC_Session *c = m->group_handler;
    c->moderation = function;
}

void gc_callback_nick_change(Messenger *m, gc_nick_change_cb *function)
{
    GC_Session *c = m->group_handler;
    c->nick_change = function;
}

void gc_callback_status_change(Messenger *m, gc_status_change_cb *function)
{
    GC_Session *c = m->group_handler;
    c->status_change = function;
}

void gc_callback_topic_change(Messenger *m, gc_topic_change_cb *function)
{
    GC_Session *c = m->group_handler;
    c->topic_change = function;
}

void gc_callback_topic_lock(Messenger *m, gc_topic_lock_cb *function)
{
    GC_Session *c = m->group_handler;
    c->topic_lock = function;
}

void gc_callback_peer_limit(Messenger *m, gc_peer_limit_cb *function)
{
    GC_Session *c = m->group_handler;
    c->peer_limit = function;
}

void gc_callback_privacy_state(Messenger *m, gc_privacy_state_cb *function)
{
    GC_Session *c = m->group_handler;
    c->privacy_state = function;
}

void gc_callback_password(Messenger *m, gc_password_cb *function)
{
    GC_Session *c = m->group_handler;
    c->password = function;
}

void gc_callback_peer_join(Messenger *m, gc_peer_join_cb *function)
{
    GC_Session *c = m->group_handler;
    c->peer_join = function;
}

void gc_callback_peer_exit(Messenger *m, gc_peer_exit_cb *function)
{
    GC_Session *c = m->group_handler;
    c->peer_exit = function;
}

void gc_callback_self_join(Messenger *m, gc_self_join_cb *function)
{
    GC_Session *c = m->group_handler;
    c->self_join = function;
}

void gc_callback_rejected(Messenger *m, gc_rejected_cb *function)
{
    GC_Session *c = m->group_handler;
    c->rejected = function;
}

/* Deletes peer_number from group. `no_callback` should be set to true if the `peer_exit` callback
 * should not be triggered.
 *
 * Return 0 on success.
 * Return -1 on failure.
 */
static int peer_delete(Messenger *m, int group_number, uint32_t peer_number, Group_Exit_Type exit_type,
                       const uint8_t *data, uint16_t length, void *userdata)
{
    const GC_Session *c = m->group_handler;
    GC_Chat *chat = gc_get_group(c, group_number);

    if (chat == nullptr) {
        return -1;
    }

    GC_Connection *gconn = gcc_get_connection(chat, peer_number);

    if (gconn == nullptr) {
        return -1;
    }

    const bool peer_confirmed = gconn->confirmed;

    /* Needs to occur before peer is removed */
    if (exit_type != GC_EXIT_TYPE_NO_CALLBACK && c->peer_exit && peer_confirmed) {
        (*c->peer_exit)(m, group_number, chat->group[peer_number].peer_id, exit_type, chat->group[peer_number].nick,
                        chat->group[peer_number].nick_length, data, length, userdata);
    }

    gcc_peer_cleanup(gconn);

    --chat->numpeers;

    if (chat->numpeers != peer_number) {
        memcpy(&chat->group[peer_number], &chat->group[chat->numpeers], sizeof(GC_GroupPeer));
        memcpy(&chat->gcc[peer_number], &chat->gcc[chat->numpeers], sizeof(GC_Connection));
    }

    memset(&chat->group[chat->numpeers], 0, sizeof(GC_GroupPeer));
    memset(&chat->gcc[chat->numpeers], 0, sizeof(GC_Connection));

    GC_GroupPeer *tmp_group = (GC_GroupPeer *)realloc(chat->group, sizeof(GC_GroupPeer) * chat->numpeers);

    if (tmp_group == nullptr) {
        return -1;
    }

    chat->group = tmp_group;

    GC_Connection *tmp_gcc = (GC_Connection *)realloc(chat->gcc, sizeof(GC_Connection) * chat->numpeers);

    if (tmp_gcc == nullptr) {
        return -1;
    }

    chat->gcc = tmp_gcc;
    set_gc_peerlist_checksum(chat);

    if (peer_confirmed) {
        refresh_gc_saved_peers(chat);
    }

    return 0;
}

/* Updates peer_number with info from `peer` and validates peer data.
 *
 * Returns peer_number on success.
 * Returns -1 on failure.
 */
static int peer_update(Messenger *m, int group_number, GC_GroupPeer *peer, uint32_t peer_number)
{
    const GC_Session *c = m->group_handler;
    const GC_Chat *chat = gc_get_group(c, group_number);

    if (chat == nullptr) {
        return -1;
    }

    if (peer->nick_length == 0) {
        return -1;
    }

    if (peer->status > GS_BUSY) {
        return -1;
    }

    if (peer->role > GR_OBSERVER) {
        return -1;
    }

    GC_GroupPeer *curr_peer = &chat->group[peer_number];

    curr_peer->role = peer->role;
    curr_peer->status = peer->status;
    curr_peer->nick_length = peer->nick_length;

    memcpy(curr_peer->nick, peer->nick, peer->nick_length);

    return peer_number;
}

/* Adds a new peer to group_number's peer list.
 *
 * Return peer_number if success.
 * Return -1 on failure.
 * Return -2 if a peer with public_key is already in our peerlist.
 */
static int peer_add(const Messenger *m, int group_number, const IP_Port *ipp, const uint8_t *public_key)
{
    const GC_Session *c = m->group_handler;
    GC_Chat *chat = gc_get_group(c, group_number);

    if (chat == nullptr) {
        return -1;
    }

    if (get_peer_number_of_enc_pk(chat, public_key, false) != -1) {
        return -2;
    }

    const uint32_t peer_id = get_new_peer_id(chat);

    if (peer_id == UINT32_MAX) {
        LOGGER_WARNING(chat->logger, "Failed to add peer: all peer ID's are taken?");
        return -1;
    }

    const int peer_number = chat->numpeers;
    int tcp_connection_num = -1;

    if (peer_number > 0) {  // we don't need a connection to ourself
        tcp_connection_num = new_tcp_connection_to(chat->tcp_conn, public_key, 0);

        if (tcp_connection_num == -1) {
            LOGGER_WARNING(m->log, "Failed to init tcp connection for peer %d", peer_number);
        }
    }

    GC_Connection *tmp_gcc = (GC_Connection *)realloc(chat->gcc, sizeof(GC_Connection) * (chat->numpeers + 1));

    if (tmp_gcc == nullptr) {
        kill_tcp_connection_to(chat->tcp_conn, tcp_connection_num);
        return -1;
    }

    memset(&tmp_gcc[peer_number], 0, sizeof(GC_Connection));

    chat->gcc = tmp_gcc;

    GC_GroupPeer *tmp_group = (GC_GroupPeer *)realloc(chat->group, sizeof(GC_GroupPeer) * (chat->numpeers + 1));

    if (tmp_group == nullptr) {
        kill_tcp_connection_to(chat->tcp_conn, tcp_connection_num);
        return -1;
    }

    ++chat->numpeers;

    memset(&tmp_group[peer_number], 0, sizeof(GC_GroupPeer));

    chat->group = tmp_group;

    GC_Connection *gconn = &chat->gcc[peer_number];

    gcc_set_ip_port(gconn, ipp);
    chat->group[peer_number].role = GR_USER;
    chat->group[peer_number].peer_id = peer_id;
    chat->group[peer_number].ignore = false;

    if (create_gc_session_keypair(gconn->session_public_key, gconn->session_secret_key) != 0) {
        LOGGER_FATAL(chat->logger, "Failed to create session keypair");
        return -1;
    }

    crypto_memlock(gconn->session_secret_key, sizeof(gconn->session_secret_key));

    if (peer_number > 0) {
        memcpy(gconn->addr.public_key, public_key, ENC_PUBLIC_KEY_SIZE);  /* we get the sig key in the handshake */
    } else {
        memcpy(gconn->addr.public_key, chat->self_public_key, EXT_PUBLIC_KEY_SIZE);
    }

    const uint64_t tm = mono_time_get(chat->mono_time);

    gcc_set_send_message_id(gconn, 1);
    gconn->public_key_hash = gc_get_pk_jenkins_hash(public_key);
    gconn->last_received_ping_time = tm;
    gconn->last_key_rotation = tm;
    gconn->tcp_connection_num = tcp_connection_num;
    gconn->last_sent_ip_time = tm;
    gconn->last_sent_ping_time = tm - (GC_PING_TIMEOUT / 2) + (peer_number % (GC_PING_TIMEOUT / 2));
    gconn->self_is_closer = id_closest(get_chat_id(chat->chat_public_key),
                                       get_enc_key(chat->self_public_key),
                                       get_enc_key(gconn->addr.public_key)) == 1;

    return peer_number;
}

/* Copies own peer data to `peer`. */
static void copy_self(const GC_Chat *chat, GC_GroupPeer *peer)
{
    memset(peer, 0, sizeof(GC_GroupPeer));

    peer->status = gc_get_self_status(chat);
    gc_get_self_nick(chat, peer->nick);
    peer->nick_length = gc_get_self_nick_size(chat);
    peer->role = gc_get_self_role(chat);
}

/* Returns true if we haven't received a ping from this peer after n seconds.
 * n depends on whether or not the peer has been confirmed.
 */
static bool peer_timed_out(const Mono_Time *mono_time, const GC_Chat *chat, const GC_Connection *gconn)
{
    return mono_time_is_timeout(mono_time, gconn->last_received_ping_time, gconn->confirmed
                                ? GC_CONFIRMED_PEER_TIMEOUT
                                : GC_UNCONFIRMED_PEER_TIMEOUT);
}

/* Attempts to send pending handshake packets to peer designated by `gconn`.
 *
 * One request of each type can be sent per `GC_SEND_HANDSHAKE_INTERVAL` seconds.
 *
 * Return 0 on success.
 * Return -1 on failure.
 */
static int send_pending_handshake(const GC_Chat *chat, GC_Connection *gconn, uint32_t peer_number)
{
    if (chat == nullptr || gconn == nullptr) {
        return -1;
    }

    if (gconn->is_pending_handshake_response) {
        if (!mono_time_is_timeout(chat->mono_time, gconn->last_handshake_response, GC_SEND_HANDSHAKE_INTERVAL)) {
            return 0;
        }

        gconn->last_handshake_response = mono_time_get(chat->mono_time);

        return send_gc_handshake_response(chat, gconn);
    }

    if (!mono_time_is_timeout(chat->mono_time, gconn->last_handshake_request, GC_SEND_HANDSHAKE_INTERVAL)) {
        return 0;
    }

    gconn->last_handshake_request = mono_time_get(chat->mono_time);

    if (gconn->is_oob_handshake) {
        return send_gc_oob_handshake_request(chat, gconn);
    }

    return send_gc_handshake_packet(chat, gconn, GH_REQUEST, gconn->pending_handshake_type);
}

#define GC_TCP_RELAY_SEND_INTERVAL 120
static void do_peer_connections(Messenger *m, int group_number, void *userdata)
{
    GC_Chat *chat = gc_get_group(m->group_handler, group_number);

    if (chat == nullptr) {
        return;
    }

    for (uint32_t i = 1; i < chat->numpeers; ++i) {
        GC_Connection *gconn = &chat->gcc[i];

        if (gconn->pending_delete) {
            continue;
        }

        if (peer_timed_out(m->mono_time, chat, gconn)) {
            gcc_mark_for_deletion(gconn, chat->tcp_conn, GC_EXIT_TYPE_TIMEOUT, nullptr, 0);
            continue;
        }

        gcc_resend_packets(m, chat, i);

        if (chat->new_tcp_relay || (gconn->tcp_relays_count == 0 &&
                                    mono_time_is_timeout(chat->mono_time,
                                            gconn->last_sent_tcp_relays_time,
                                            GC_TCP_RELAY_SEND_INTERVAL))) {
            if (gconn->confirmed) {
                send_gc_tcp_relays(m->mono_time, chat, gconn);
                gconn->last_sent_tcp_relays_time = mono_time_get(chat->mono_time);
            }
        }

        gcc_check_received_array(m, group_number, i, userdata);   // may change peer numbers
    }

    chat->new_tcp_relay = false;
}

static void do_handshakes(Messenger *m, int group_number)
{
    GC_Chat *chat = gc_get_group(m->group_handler, group_number);

    if (chat == nullptr) {
        return;
    }

    for (uint32_t i = 1; i < chat->numpeers; ++i) {
        GC_Connection *gconn = &chat->gcc[i];

        if (gconn->handshaked || gconn->pending_delete) {
            continue;
        }

        send_pending_handshake(chat, gconn, i);
    }
}

/* Adds `gconn` to the group timeout list. */
static void add_gc_peer_timeout_list(GC_Chat *chat, const GC_Connection *gconn)
{
    const size_t idx = chat->timeout_list_index;
    const uint64_t tm = mono_time_get(chat->mono_time);

    copy_gc_saved_peer(gconn, &chat->timeout_list[idx].addr);

    chat->timeout_list[idx].last_seen = tm;
    chat->timeout_list[idx].last_reconn_try = 0;
    chat->timeout_list_index = (idx + 1) % MAX_GC_SAVED_TIMEOUTS;
}

static void do_peer_delete(Messenger *m, int group_number, void *userdata)
{
    GC_Chat *chat = gc_get_group(m->group_handler, group_number);

    if (chat == nullptr) {
        return;
    }

    for (uint32_t i = 1; i < chat->numpeers; ++i) {
        GC_Connection *gconn = &chat->gcc[i];

        if (gconn->pending_delete) {
            GC_Exit_Info *exit_info = &gconn->exit_info;

            if (exit_info->exit_type == GC_EXIT_TYPE_TIMEOUT && gconn->confirmed) {
                add_gc_peer_timeout_list(chat, gconn);
            }

            if (peer_delete(m, group_number, i, exit_info->exit_type, exit_info->part_message, exit_info->length,
                            userdata) == -1) {
                LOGGER_ERROR(m->log, "Failed to delete peer %u", i);
            }

            if (i >= chat->numpeers) {
                break;
            }
        }
    }
}

/* Constructs and sends a ping packet to `gconn` containing info needed for group syncing
 * and connection maintenance.
 *
 * Return 0 on success.
 * Return -1 on failure.
 */
static int ping_peer(const GC_Chat *chat, GC_Connection *gconn)
{
    uint32_t buf_size = GC_PING_PACKET_MIN_DATA_SIZE + sizeof(IP_Port);
    uint8_t *data = (uint8_t *)malloc(buf_size);

    if (data == nullptr) {
        return -1;
    }

    uint32_t packed_len = 0;

    net_pack_u16(data, chat->peers_checksum);
    packed_len += sizeof(uint16_t);

    net_pack_u16(data + packed_len, (uint16_t) get_gc_confirmed_numpeers(chat));
    packed_len += sizeof(uint16_t);

    net_pack_u32(data + packed_len, chat->shared_state.version);
    packed_len += sizeof(uint32_t);

    net_pack_u32(data + packed_len, chat->moderation.sanctions_creds.version);
    packed_len += sizeof(uint32_t);

    net_pack_u16(data + packed_len, chat->moderation.sanctions_creds.checksum);
    packed_len += sizeof(uint16_t);

    net_pack_u32(data + packed_len, chat->topic_info.version);
    packed_len += sizeof(uint32_t);

    net_pack_u16(data + packed_len, chat->topic_info.checksum);
    packed_len += sizeof(uint16_t);

    if (packed_len != GC_PING_PACKET_MIN_DATA_SIZE) {
        LOGGER_FATAL(chat->logger, "Packed length is impossible");
    }

    if (chat->self_udp_status == SELF_UDP_STATUS_WAN && !gcc_conn_is_direct(chat->mono_time, gconn)
            && mono_time_is_timeout(chat->mono_time, gconn->last_sent_ip_time, GC_SEND_IP_PORT_INTERVAL)) {

        const int packed_ipp_len = pack_ip_port(data + buf_size - sizeof(IP_Port), sizeof(IP_Port), &chat->self_ip_port);

        if (packed_ipp_len > 0) {
            packed_len += packed_ipp_len;
        }
    }

    if (send_lossy_group_packet(chat, gconn, data, packed_len, GP_PING) == 0) {
        free(data);
        return 0;
    }

    free(data);

    return -1;
}

/*
 * Sends a ping packet to peers that haven't been pinged in at least GC_PING_TIMEOUT seconds, and
 * a key rotation request to peers with whom we haven't refreshed keys in at least GC_KEY_ROTATION_TIMEOUT
 * seconds.
 *
 * Ping packet always includes your confirmed peer count, a peer list checksum, your shared state and sanctions
 * list version for syncing purposes. We also occasionally try to send our own IP info to peers that we
 * do not have a direct connection with.
 */
#define GC_DO_PINGS_INTERVAL 2
static void do_gc_ping_and_key_rotation(GC_Chat *chat)
{
    if (!mono_time_is_timeout(chat->mono_time, chat->last_ping_interval, GC_DO_PINGS_INTERVAL)) {
        return;
    }

    const uint64_t tm = mono_time_get(chat->mono_time);

    for (uint32_t i = 1; i < chat->numpeers; ++i) {
        GC_Connection *gconn = &chat->gcc[i];

        if (!gconn->confirmed) {
            continue;
        }

        if (mono_time_is_timeout(chat->mono_time, gconn->last_sent_ping_time, GC_PING_TIMEOUT)) {
            if (ping_peer(chat, gconn) >= 0) {
                gconn->last_sent_ping_time = tm;
            }
        }

        if (mono_time_is_timeout(chat->mono_time, gconn->last_key_rotation, GC_KEY_ROTATION_TIMEOUT)) {
            if (send_peer_key_rotation_request(chat, gconn) == 0) {
                gconn->last_key_rotation = tm;
            }
        }
    }

    chat->last_ping_interval = tm;
}

static void do_new_connection_cooldown(GC_Chat *chat)
{
    if (chat->connection_O_metre == 0) {
        return;
    }

    const uint64_t tm = mono_time_get(chat->mono_time);

    if (chat->connection_cooldown_timer < tm) {
        chat->connection_cooldown_timer = tm;
        --chat->connection_O_metre;

        if (chat->connection_O_metre == 0 && chat->block_handshakes) {
            chat->block_handshakes = false;
            LOGGER_DEBUG(chat->logger, "Unblocking handshakes");
        }
    }
}

#define TCP_RELAYS_CHECK_INTERVAL 10
static void do_gc_tcp(Messenger *m, GC_Chat *chat, void *userdata)
{
    if (chat->tcp_conn == nullptr || !group_can_handle_packets(chat)) {
        return;
    }

    do_tcp_connections(chat->logger, chat->tcp_conn, userdata);

    for (uint32_t i = 1; i < chat->numpeers; ++i) {
        GC_Connection *gconn = &chat->gcc[i];
        const bool tcp_set = !gcc_conn_is_direct(chat->mono_time, gconn);
        set_tcp_connection_to_status(chat->tcp_conn, gconn->tcp_connection_num, tcp_set);
    }

    if (mono_time_is_timeout(chat->mono_time, chat->last_checked_tcp_relays, TCP_RELAYS_CHECK_INTERVAL)) {
        if (chat->tcp_connections == 0) {
            add_tcp_relays_to_chat(m, chat);
        }

        chat->last_checked_tcp_relays = mono_time_get(chat->mono_time);
    }
}

/* Updates our TCP and UDP connection status and flags a new announcement if our connection has
 * changed and we have either a UDP or TCP connection.
 */
#define GC_SELF_CONNECTION_CHECK_INTERVAL 2
static void do_self_connection(Messenger *m, GC_Chat *chat)
{
    if (!mono_time_is_timeout(chat->mono_time, chat->last_self_announce_check, GC_SELF_CONNECTION_CHECK_INTERVAL)) {
        return;
    }

    const uint16_t tcp_connections = tcp_connected_relays_count(chat->tcp_conn);
    const unsigned int self_udp_status = ipport_self_copy(m->dht, &chat->self_ip_port);

    // We flag a self announce if our udp status changes, or if we connect to a new tcp relay.
    // TODO (Jfreegman): This should be flagged when the tcp relay count changes at all. However
    // Doing this now on the testnet is pointless and causes spam due to a TCP implementation bug.
    if (((chat->self_udp_status != self_udp_status) && (self_udp_status != SELF_UDP_STATUS_NONE))
            || (tcp_connections > 0 && tcp_connections > chat->tcp_connections)) {
        chat->update_self_announces = true;
    }

    if (tcp_connections > 0) {  // TODO (Jfreegman): Remove this before mainnet merge
        chat->tcp_connections = tcp_connections;
    }

    chat->self_udp_status = (Self_UDP_Status) self_udp_status;
    chat->last_self_announce_check = mono_time_get(chat->mono_time);
}


/* Attempts to initiate a new connection with peers in the timeout list.
 *
 * This function is not used for public groups as the DHT and group sync mechanism
 * should automatically do this for us.
 */
#define TIMED_OUT_RECONN_INTERVAL 2
static void do_timed_out_reconn(Messenger *m, GC_Chat *chat)
{
    if (is_public_chat(chat)) {
        return;
    }

    if (!mono_time_is_timeout(chat->mono_time, chat->last_timed_out_reconn_try, TIMED_OUT_RECONN_INTERVAL)) {
        return;
    }

    const uint64_t curr_time = mono_time_get(chat->mono_time);

    for (size_t i = 0; i < MAX_GC_SAVED_TIMEOUTS; ++i) {
        GC_TimedOutPeer *timeout = &chat->timeout_list[i];

        if (timeout->last_seen == 0 || timeout->last_seen == curr_time) {
            continue;
        }

        if (mono_time_is_timeout(chat->mono_time, timeout->last_seen, GC_TIMED_OUT_STALE_TIMEOUT)
                || get_peer_number_of_enc_pk(chat, timeout->addr.public_key, true) != -1) {
            *timeout = (GC_TimedOutPeer) {
                0
            };

            continue;
        }

        if (mono_time_is_timeout(chat->mono_time, timeout->last_reconn_try, GC_TIMED_OUT_RECONN_TIMEOUT)) {
            if (load_gc_peers(m, chat, &timeout->addr, 1) != 1) {
                LOGGER_WARNING(chat->logger, "Failed to load timed out peer");
            }

            timeout->last_reconn_try = curr_time;
        }
    }

    chat->last_timed_out_reconn_try = curr_time;
}

void do_gc(GC_Session *c, void *userdata)
{
    if (c == nullptr) {
        return;
    }

    for (uint32_t i = 0; i < c->num_chats; ++i) {
        GC_Chat *chat = &c->chats[i];

        const GC_Conn_State state = chat->connection_state;

        if (state == CS_NONE) {
            continue;
        }

        do_peer_delete(c->messenger, i, userdata);

        if (state != CS_DISCONNECTED) {
            do_peer_connections(c->messenger, i, userdata);
            do_gc_tcp(c->messenger, chat, userdata);
            do_handshakes(c->messenger, i);
            do_self_connection(c->messenger, chat);
        }

        if (chat->connection_state == CS_CONNECTED) {
            do_gc_ping_and_key_rotation(chat);
            do_new_connection_cooldown(chat);
            do_timed_out_reconn(c->messenger, chat);
        }
    }
}

/* Set the size of the groupchat list to n.
 *
 *  return -1 on failure.
 *  return 0 success.
 */
static int realloc_groupchats(GC_Session *c, uint32_t n)
{
    if (n == 0) {
        free(c->chats);
        c->chats = nullptr;
        return 0;
    }

    GC_Chat *temp = (GC_Chat *)realloc(c->chats, n * sizeof(GC_Chat));

    if (temp == nullptr) {
        return -1;
    }

    c->chats = temp;
    return 0;
}

static int get_new_group_index(GC_Session *c)
{
    if (c == nullptr) {
        return -1;
    }

    for (uint32_t i = 0; i < c->num_chats; ++i) {
        if (c->chats[i].connection_state == CS_NONE) {
            return i;
        }
    }

    if (realloc_groupchats(c, c->num_chats + 1) != 0) {
        return -1;
    }

    int new_index = c->num_chats;

    c->chats[new_index] = (GC_Chat) {
        nullptr
    };

    memset(&(c->chats[new_index].saved_invites), -1, sizeof(c->chats[new_index].saved_invites));

    ++c->num_chats;

    return new_index;
}

/* Attempts to associate new TCP relays with our group connection. */
static void add_tcp_relays_to_chat(Messenger *m, GC_Chat *chat)
{
    const uint16_t num_relays = tcp_connections_count(nc_get_tcp_c(m->net_crypto));

    if (num_relays == 0) {
        return;
    }

    Node_format *tcp_relays = (Node_format *)malloc(num_relays * sizeof(Node_format));

    if (tcp_relays == nullptr) {
        return;
    }

    const uint32_t num_copied = tcp_copy_connected_relays(nc_get_tcp_c(m->net_crypto), tcp_relays, num_relays);

    for (uint32_t i = 0; i < num_copied; ++i) {
        if (add_tcp_relay_global(chat->tcp_conn, tcp_relays[i].ip_port, tcp_relays[i].public_key) == 0) {
            chat->new_tcp_relay = true;
        }
    }

    free(tcp_relays);
}

static int init_gc_tcp_connection(Messenger *m, GC_Chat *chat)
{
    chat->tcp_conn = new_tcp_connections(m->mono_time, chat->self_secret_key, &m->options.proxy_info);

    if (chat->tcp_conn == nullptr) {
        return -1;
    }

    add_tcp_relays_to_chat(m, chat);

    set_packet_tcp_connection_callback(chat->tcp_conn, &handle_gc_tcp_packet, m);
    set_oob_packet_tcp_connection_callback(chat->tcp_conn, &handle_gc_tcp_oob_packet, m);

    return 0;
}

/* Initializes default shared state values. */
static void init_gc_shared_state(GC_Chat *chat)
{
    chat->shared_state.maxpeers = MAX_GC_PEERS_DEFAULT;
    chat->shared_state.privacy_state = GI_PUBLIC;
    chat->shared_state.topic_lock = 0;
}

/* Initializes the group shared state for the founder.
 *
 * Return 0 on success.
 * Return -1 on failure.
 */
static int init_gc_shared_state_founder(GC_Chat *chat, Group_Privacy_State privacy_state, const uint8_t *group_name,
                                        uint16_t name_length)
{
    memcpy(chat->shared_state.founder_public_key, chat->self_public_key, EXT_PUBLIC_KEY_SIZE);
    memcpy(chat->shared_state.group_name, group_name, name_length);
    chat->shared_state.group_name_len = name_length;
    chat->shared_state.privacy_state = privacy_state;

    return sign_gc_shared_state(chat);
}

static int create_new_chat_ext_keypair(GC_Chat *chat);

static int create_new_group(GC_Session *c, const uint8_t *nick, size_t nick_length, bool founder)
{
    if (nick == nullptr || nick_length == 0) {
        return -1;
    }

    if (nick_length > MAX_GC_NICK_SIZE) {
        return -1;
    }

    const int group_number = get_new_group_index(c);

    if (group_number == -1) {
        return -1;
    }

    Messenger *m = c->messenger;
    GC_Chat *chat = &c->chats[group_number];

    chat->logger = m->log;

    if (create_new_chat_ext_keypair(chat) != 0) {
        LOGGER_ERROR(chat->logger, "Failed to create extended keypair");
        group_delete(c, chat);
        return -1;
    }

    crypto_memlock(chat->self_secret_key, sizeof(chat->self_secret_key));

    if (init_gc_tcp_connection(m, chat) == -1) {
        group_delete(c, chat);
        return -1;
    }

    const uint64_t tm = mono_time_get(m->mono_time);

    chat->group_number = group_number;
    chat->numpeers = 0;
    chat->connection_state = CS_CONNECTING;
    chat->net = m->net;
    chat->mono_time = m->mono_time;
    chat->last_ping_interval = tm;

    if (peer_add(m, group_number, nullptr, chat->self_public_key) != 0) {    /* you are always peer_number/index 0 */
        group_delete(c, chat);
        return -1;
    }

    if (self_gc_set_nick(chat, nick, nick_length) == -1) {
        group_delete(c, chat);
        return -1;
    }

    self_gc_set_status(chat, GS_NONE);
    self_gc_set_role(chat, founder ? GR_FOUNDER : GR_USER);
    self_gc_set_confirmed(chat, true);
    self_gc_set_ext_public_key(chat, chat->self_public_key);

    init_gc_shared_state(chat);

    return group_number;
}

/* Inits the sanctions list credentials. This should be called by the group founder on creation.
 *
 * Returns 0 on success.
 * Returns -1 on failure.
 */
static int init_gc_sanctions_creds(GC_Chat *chat)
{
    if (sanctions_list_make_creds(chat) == -1) {
        return -1;
    }

    return 0;
}

/* Attempts to add `num_addrs` peers from `addrs` to our peerlist and initiate invite requests
 * for all of them.
 *
 * Returns the number of peers successfully loaded.
 */
static size_t load_gc_peers(Messenger *m, GC_Chat *chat, const GC_SavedPeerInfo *addrs, uint16_t num_addrs)
{
    size_t count = 0;

    for (size_t i = 0; i < num_addrs; ++i) {
        if (!saved_peer_is_valid(&addrs[i])) {
            continue;
        }

        const bool ip_port_is_set = ipport_isset(&addrs[i].ip_port);
        const IP_Port *ip_port = ip_port_is_set ? &addrs[i].ip_port : nullptr;

        const int peer_number = peer_add(m, chat->group_number, ip_port, addrs[i].public_key);

        if (peer_number < 0) {
            continue;
        }

        GC_Connection *gconn = gcc_get_connection(chat, peer_number);

        if (gconn == nullptr) {
            continue;
        }

        add_tcp_relay_global(chat->tcp_conn, addrs[i].tcp_relay.ip_port, addrs[i].tcp_relay.public_key);

        const int add_tcp_result = add_tcp_relay_connection(chat->tcp_conn, gconn->tcp_connection_num,
                                   addrs[i].tcp_relay.ip_port,
                                   addrs[i].tcp_relay.public_key);

        if (add_tcp_result == -1 && !ip_port_is_set) {
            gcc_mark_for_deletion(gconn, chat->tcp_conn, GC_EXIT_TYPE_DISCONNECTED, nullptr, 0);
            continue;
        }

        if (add_tcp_result == 0) {
            const int save_tcp_result = gcc_save_tcp_relay(gconn, &addrs[i].tcp_relay);

            if (save_tcp_result == -1) {
                gcc_mark_for_deletion(gconn, chat->tcp_conn, GC_EXIT_TYPE_DISCONNECTED, nullptr, 0);
                continue;
            }

            memcpy(gconn->oob_relay_pk, addrs[i].tcp_relay.public_key, CRYPTO_PUBLIC_KEY_SIZE);
        }

        const uint64_t tm = mono_time_get(chat->mono_time);

        gconn->is_oob_handshake = !gcc_direct_conn_is_possible(chat, gconn);
        gconn->is_pending_handshake_response = false;
        gconn->pending_handshake_type = HS_INVITE_REQUEST;
        gconn->last_received_ping_time = tm;
        gconn->last_key_rotation = tm;

        ++count;
    }

    return count;
}

int gc_group_load(GC_Session *c, const Saved_Group *save, int group_number)
{
    group_number = group_number == -1 ? get_new_group_index(c) : group_number;

    if (group_number == -1) {
        return -1;
    }

    const uint64_t tm = mono_time_get(c->messenger->mono_time);

    Messenger *m = c->messenger;
    GC_Chat *chat = &c->chats[group_number];

    const bool is_active_chat = save->group_connection_state != SGCS_DISCONNECTED;

    chat->group_number = group_number;
    chat->numpeers = 0;
    chat->connection_state = is_active_chat ? CS_CONNECTING : CS_DISCONNECTED;
    chat->net = m->net;
    chat->mono_time = m->mono_time;
    chat->logger = m->log;
    chat->last_ping_interval = tm;

    chat->shared_state.version = net_ntohl(save->shared_state_version);
    memcpy(chat->shared_state_sig, save->shared_state_signature, SIGNATURE_SIZE);
    memcpy(chat->shared_state.founder_public_key, save->founder_public_key, EXT_PUBLIC_KEY_SIZE);
    chat->shared_state.group_name_len = net_ntohs(save->group_name_length);
    memcpy(chat->shared_state.group_name, save->group_name, MAX_GC_GROUP_NAME_SIZE);
    chat->shared_state.privacy_state = (Group_Privacy_State) save->privacy_state;
    chat->shared_state.maxpeers = net_ntohs(save->maxpeers);
    chat->shared_state.password_length = net_ntohs(save->password_length);
    memcpy(chat->shared_state.password, save->password, MAX_GC_PASSWORD_SIZE);
    memcpy(chat->shared_state.mod_list_hash, save->mod_list_hash, GC_MODERATION_HASH_SIZE);
    chat->shared_state.topic_lock = net_ntohl(save->topic_lock);

    chat->topic_info.length = net_ntohs(save->topic_length);
    memcpy(chat->topic_info.topic, save->topic, MAX_GC_TOPIC_SIZE);
    memcpy(chat->topic_info.public_sig_key, save->topic_public_sig_key, SIG_PUBLIC_KEY_SIZE);
    chat->topic_info.version = net_ntohl(save->topic_version);
    memcpy(chat->topic_sig, save->topic_signature, SIGNATURE_SIZE);

    set_gc_topic_checksum(&chat->topic_info);

    memcpy(chat->chat_public_key, save->chat_public_key, EXT_PUBLIC_KEY_SIZE);
    memcpy(chat->chat_secret_key, save->chat_secret_key, EXT_SECRET_KEY_SIZE);

    const uint16_t num_mods = net_ntohs(save->num_mods);

    if (mod_list_unpack(chat, save->mod_list, num_mods * GC_MOD_LIST_ENTRY_SIZE, num_mods) == -1) {
        return -1;
    }

    memcpy(chat->self_public_key, save->self_public_key, EXT_PUBLIC_KEY_SIZE);
    memcpy(chat->self_secret_key, save->self_secret_key, EXT_SECRET_KEY_SIZE);

    chat->self_public_key_hash = gc_get_pk_jenkins_hash(chat->self_public_key);

    if (peer_add(m, group_number, nullptr, save->self_public_key) != 0) {
        return -1;
    }

    self_gc_set_ext_public_key(chat, chat->self_public_key);

    uint16_t self_nick_length = net_ntohs(save->self_nick_length);

    if (self_nick_length > MAX_GC_NICK_SIZE) {
        self_nick_length = MAX_GC_NICK_SIZE;
    }

    if (self_gc_set_nick(chat, save->self_nick, self_nick_length) == -1) {
        return -1;
    }

    self_gc_set_role(chat, (Group_Role) save->self_role);
    self_gc_set_status(chat, (Group_Peer_Status) save->self_status);
    self_gc_set_confirmed(chat, true);

    if (self_gc_is_founder(chat)) {
        if (init_gc_sanctions_creds(chat) == -1) {
            return -1;
        }
    }

    if (init_gc_tcp_connection(m, chat) == -1) {
        return -1;
    }

    memcpy(&chat->saved_peers, save->addrs, GC_MAX_SAVED_PEERS * sizeof(GC_SavedPeerInfo));

    if (!is_active_chat) {
        return group_number;
    }

    if (is_public_chat(chat)) {
        if (m_create_group_connection(m, chat) == -1) {
            LOGGER_ERROR(m->log, "Failed to initialize group friend connection");
        }
    }

    load_gc_peers(m, chat, chat->saved_peers, GC_MAX_SAVED_PEERS);

    return group_number;
}

int gc_group_add(GC_Session *c, Group_Privacy_State privacy_state, const uint8_t *group_name,
                 uint16_t group_name_length,
                 const uint8_t *nick, size_t nick_length)
{
    if (group_name_length > MAX_GC_GROUP_NAME_SIZE) {
        return -1;
    }

    if (nick_length > MAX_GC_NICK_SIZE) {
        return -1;
    }

    if (group_name_length == 0 || group_name == nullptr) {
        return -2;
    }

    if (nick_length == 0 || nick == nullptr) {
        return -2;
    }

    const int group_number = create_new_group(c, nick, nick_length, true);

    if (group_number == -1) {
        return -3;
    }

    GC_Chat *chat = gc_get_group(c, group_number);

    if (chat == nullptr) {
        return -3;
    }

    create_extended_keypair(chat->chat_public_key, chat->chat_secret_key);

    crypto_memlock(chat->chat_secret_key, sizeof(chat->chat_secret_key));

    if (init_gc_shared_state_founder(chat, privacy_state, group_name, group_name_length) == -1) {
        group_delete(c, chat);
        return -4;
    }

    if (init_gc_sanctions_creds(chat) == -1) {
        group_delete(c, chat);
        return -4;
    }

    if (gc_set_topic(chat, (const uint8_t *)"Welcome!", 8) != 0) {
        group_delete(c, chat);
        return -4;
    }

    chat->connection_state = CS_CONNECTED;

    if (is_public_chat(chat)) {
        if (m_create_group_connection(c->messenger, chat) < 0) {
            LOGGER_ERROR(chat->logger, "Failed to initialize group friend connection");
            group_delete(c, chat);
            return -5;
        }
    }

    return group_number;
}

int gc_group_join(GC_Session *c, const uint8_t *chat_id, const uint8_t *nick, size_t nick_length, const uint8_t *passwd,
                  uint16_t passwd_len)
{
    if (chat_id == nullptr || group_exists(c, chat_id) || getfriend_id(c->messenger, chat_id) != -1) {
        return -2;
    }

    if (nick_length > MAX_GC_NICK_SIZE) {
        return -3;
    }

    if (nick == nullptr || nick_length == 0) {
        return -4;
    }

    const int group_number = create_new_group(c, nick, nick_length, false);

    if (group_number == -1) {
        return -1;
    }

    GC_Chat *chat = gc_get_group(c, group_number);

    if (chat == nullptr) {
        return -1;
    }

    if (expand_chat_id(chat->chat_public_key, chat_id) != 0) {
        return -1;
    }

    chat->connection_state = CS_CONNECTING;

    if (passwd != nullptr && passwd_len > 0) {
        if (set_gc_password_local(chat, passwd, passwd_len) == -1) {
            return -5;
        }
    }

    const int friend_number = m_create_group_connection(c->messenger, chat);

    if (friend_number < 0) {
        return -6;
    }

    return group_number;
}

int gc_disconnect_from_group(GC_Session *c, GC_Chat *chat)
{
    if (c == nullptr || chat == nullptr) {
        return -1;
    }

    chat->connection_state = CS_DISCONNECTED;

    send_gc_broadcast_message(chat, nullptr, 0, GM_PEER_EXIT);

    for (uint32_t i = 1; i < chat->numpeers; ++i) {
        gcc_mark_for_deletion(&chat->gcc[i], chat->tcp_conn, GC_EXIT_TYPE_SELF_DISCONNECTED, nullptr, 0);
    }

    return 0;
}

int gc_rejoin_group(GC_Session *c, GC_Chat *chat)
{
    if (c == nullptr || chat == nullptr) {
        return -1;
    }

    chat->time_connected = 0;

    if (group_can_handle_packets(chat)) {
        send_gc_self_exit(chat, nullptr, 0);
    }

    for (uint32_t i = 1; i < chat->numpeers; ++i) {
        GC_Connection *gconn = &chat->gcc[i];
        gcc_mark_for_deletion(gconn, chat->tcp_conn, GC_EXIT_TYPE_SELF_DISCONNECTED, nullptr, 0);
    }

    if (is_public_chat(chat)) {
        m_kill_group_connection(c->messenger, chat);

        if (m_create_group_connection(c->messenger, chat) == -1) {
            LOGGER_WARNING(chat->logger, "Failed to create new messenger connection for group");
            return -2;
        }

        chat->update_self_announces = true;
    }

    load_gc_peers(c->messenger, chat, chat->saved_peers, GC_MAX_SAVED_PEERS);

    chat->connection_state = CS_CONNECTING;

    return 0;
}

bool group_not_added(const GC_Session *c, const uint8_t *chat_id, uint32_t length)
{
    if (length < CHAT_ID_SIZE) {
        return false;
    }

    return !group_exists(c, chat_id);
}

int gc_invite_friend(const GC_Session *c, GC_Chat *chat, int32_t friend_number,
                     gc_send_group_invite_packet_cb *send_group_invite_packet)
{
    if (!friend_is_valid(c->messenger, friend_number)) {
        return -1;
    }

    uint8_t packet[MAX_GC_PACKET_SIZE];
    packet[0] = GP_FRIEND_INVITE;
    packet[1] = GROUP_INVITE;

    memcpy(packet + 2, get_chat_id(chat->chat_public_key), CHAT_ID_SIZE);
    uint16_t length = 2 + CHAT_ID_SIZE;

    memcpy(packet + length, chat->self_public_key, ENC_PUBLIC_KEY_SIZE);
    length += ENC_PUBLIC_KEY_SIZE;

    const size_t group_name_length = chat->shared_state.group_name_len;

    memcpy(packet + length, chat->shared_state.group_name, group_name_length);
    length += group_name_length;

    if (send_group_invite_packet(c->messenger, friend_number, packet, length) == -1) {
        return -2;
    }

    chat->saved_invites[chat->saved_invites_index] = friend_number;
    chat->saved_invites_index = (chat->saved_invites_index + 1) % MAX_GC_SAVED_INVITES;

    return 0;
}

/* Sends an invite accepted packet to `friend_number`.
 *
 * Return 0 on success.
 * Return -1 if `friend_number` does not designate a valid friend.
 * Return -2 if `chat `is null.
 * Return -3 if packet failed to send.
 */
static int send_gc_invite_accepted_packet(Messenger *m, const GC_Chat *chat, uint32_t friend_number)
{
    if (!friend_is_valid(m, friend_number)) {
        return -1;
    }

    if (chat == nullptr) {
        return -2;
    }

    uint8_t packet[1 + 1 + CHAT_ID_SIZE + ENC_PUBLIC_KEY_SIZE];
    packet[0] = GP_FRIEND_INVITE;
    packet[1] = GROUP_INVITE_ACCEPTED;

    memcpy(packet + 2, get_chat_id(chat->chat_public_key), CHAT_ID_SIZE);
    uint16_t length = 2 + CHAT_ID_SIZE;

    memcpy(packet + length, chat->self_public_key, ENC_PUBLIC_KEY_SIZE);
    length += ENC_PUBLIC_KEY_SIZE;

    if (send_group_invite_packet(m, friend_number, packet, length) == -1) {
        LOGGER_ERROR(m->log, "Failed to send group invite packet.");
        return -3;
    }

    return 0;
}

/* Sends an invite confirmed packet to friend designated by `friend_number`.
 *
 * `data` must contain the group's Chat ID, the sender's public encryption key,
 * and either the sender's packed IP_Port, or at least one  packed TCP node that
 * the sender can be connected through (or both).
 *
 * Return 0 on success.
 * Return -1 on failure.
 */
static int send_gc_invite_confirmed_packet(Messenger *m, const GC_Chat *chat, uint32_t friend_number,
        const uint8_t *data, uint16_t length)
{
    if (!friend_is_valid(m, friend_number)) {
        return -1;
    }

    if (chat == nullptr) {
        return -1;
    }

    uint8_t packet[MAX_GC_PACKET_SIZE];
    packet[0] = GP_FRIEND_INVITE;
    packet[1] = GROUP_INVITE_CONFIRMATION;

    memcpy(packet + 2, data, length);

    if (send_group_invite_packet(m, friend_number, packet, length + 2) == -1) {
        return -1;
    }

    return 0;
}

/* Adds `num_nodes` tcp relays from `tcp_relays` to tcp relays list associated with `gconn`
 *
 * Returns the number of relays successfully added.
 */
static uint32_t add_gc_tcp_relays(const GC_Chat *chat, GC_Connection *gconn, const Node_format *tcp_relays,
                                  size_t num_nodes)
{
    uint32_t relays_added = 0;

    for (size_t i = 0; i < num_nodes; ++i) {
        const int add_tcp_result = add_tcp_relay_connection(chat->tcp_conn,
                                   gconn->tcp_connection_num, tcp_relays[i].ip_port,
                                   tcp_relays[i].public_key);

        if (add_tcp_result == 0) {
            if (gcc_save_tcp_relay(gconn, &tcp_relays[i]) == 0) {
                ++relays_added;
            }
        }
    }

    return relays_added;
}

static bool copy_friend_ip_port_to_gconn(Messenger *m, int friend_number, GC_Connection *gconn)
{
    const Friend *f = &m->friendlist[friend_number];
    const int friend_connection_id = f->friendcon_id;
    const Friend_Conn *connection = get_conn(m->fr_c, friend_connection_id);
    const IP_Port *friend_ip_port = friend_conn_get_dht_ip_port(connection);

    if (!ipport_isset(friend_ip_port)) {
        return false;
    }

    memcpy(&gconn->addr.ip_port, friend_ip_port, sizeof(IP_Port));

    return true;
}

int handle_gc_invite_confirmed_packet(const GC_Session *c, int friend_number, const uint8_t *data, uint32_t length)
{
    if (length < GC_JOIN_DATA_LENGTH) {
        return -1;
    }

    if (!friend_is_valid(c->messenger, friend_number)) {
        return -4;
    }

    uint8_t chat_id[CHAT_ID_SIZE];
    uint8_t invite_chat_pk[ENC_PUBLIC_KEY_SIZE];

    memcpy(chat_id, data, CHAT_ID_SIZE);
    memcpy(invite_chat_pk, data + CHAT_ID_SIZE, ENC_PUBLIC_KEY_SIZE);

    GC_Chat *chat = gc_get_group_by_public_key(c, chat_id);

    if (chat == nullptr) {
        return -2;
    }

    const int peer_number = get_peer_number_of_enc_pk(chat, invite_chat_pk, false);

    if (peer_number < 0) {
        return -3;
    }

    GC_Connection *gconn = gcc_get_connection(chat, peer_number);

    Node_format tcp_relays[GCC_MAX_TCP_SHARED_RELAYS];
    const int num_nodes = unpack_nodes(tcp_relays, GCC_MAX_TCP_SHARED_RELAYS,
                                       nullptr, data + ENC_PUBLIC_KEY_SIZE + CHAT_ID_SIZE,
                                       length - GC_JOIN_DATA_LENGTH, 1);

    const bool copy_ip_port_result = copy_friend_ip_port_to_gconn(c->messenger, friend_number, gconn);

    if (num_nodes <= 0 && !copy_ip_port_result) {
        return -5;
    }

    const uint32_t tcp_relays_added = add_gc_tcp_relays(chat, gconn, tcp_relays, num_nodes);

    if (tcp_relays_added == 0 && !copy_ip_port_result) {
        LOGGER_WARNING(chat->logger, "Got invalid connection info from peer");
        return -5;
    }

    gconn->pending_handshake_type = HS_INVITE_REQUEST;

    return 0;
}

/* Return true if we have a pending sent invite for our friend designated by `friend_number`. */
static bool friend_was_invited(const Messenger *m, GC_Chat *chat, int friend_number)
{
    for (size_t i = 0; i < MAX_GC_SAVED_INVITES; ++i) {
        if (chat->saved_invites[i] == friend_number) {
            chat->saved_invites[i] = -1;
            return friend_is_valid(m, friend_number);
        }
    }

    return false;
}

/* Handles an invite accept packet.
 *
 * Return 0 on success.
 * Return -1 on failure.
 */
int handle_gc_invite_accepted_packet(GC_Session *c, int friend_number, const uint8_t *data, uint32_t length)
{
    if (length < GC_JOIN_DATA_LENGTH) {
        return -1;
    }

    Messenger *m = c->messenger;

    const uint8_t *chat_id = data;

    GC_Chat *chat = gc_get_group_by_public_key(c, chat_id);

    if (chat == nullptr || !group_can_handle_packets(chat)) {
        return -1;
    }

    const uint8_t *invite_chat_pk = data + CHAT_ID_SIZE;

    const int peer_number = peer_add(m, chat->group_number, nullptr, invite_chat_pk);

    if (!friend_was_invited(m, chat, friend_number) || peer_number < 0) {
        return -1;
    }

    GC_Connection *gconn = gcc_get_connection(chat, peer_number);

    if (gconn == nullptr) {
        return -1;
    }

    Node_format tcp_relays[GCC_MAX_TCP_SHARED_RELAYS];
    const uint32_t num_tcp_relays = tcp_copy_connected_relays(chat->tcp_conn, tcp_relays, GCC_MAX_TCP_SHARED_RELAYS);

    const bool copy_ip_port_result = copy_friend_ip_port_to_gconn(m, friend_number, gconn);

    if (num_tcp_relays <= 0 && !copy_ip_port_result) {
        return -1;
    }

    uint32_t len = GC_JOIN_DATA_LENGTH;
    uint8_t send_data[GC_JOIN_DATA_LENGTH + sizeof(tcp_relays)];

    memcpy(send_data, chat_id, CHAT_ID_SIZE);
    memcpy(send_data + CHAT_ID_SIZE, chat->self_public_key, ENC_PUBLIC_KEY_SIZE);

    if (num_tcp_relays > 0) {
        const uint32_t tcp_relays_added = add_gc_tcp_relays(chat, gconn, tcp_relays, num_tcp_relays);

        if (tcp_relays_added == 0 && !copy_ip_port_result) {
            LOGGER_WARNING(chat->logger, "Got invalid connection info from peer");
            return -1;
        }

        const int nodes_len = pack_nodes(send_data + len, sizeof(send_data) - len, tcp_relays, num_tcp_relays);

        if (nodes_len <= 0 && !copy_ip_port_result) {
            return -1;
        }

        len += nodes_len;
    }

    return send_gc_invite_confirmed_packet(m, chat, friend_number, send_data, len);
}

int gc_accept_invite(GC_Session *c, int32_t friend_number, const uint8_t *data, uint16_t length, const uint8_t *nick,
                     size_t nick_length, const uint8_t *passwd, uint16_t passwd_len)
{
    if (length < CHAT_ID_SIZE + ENC_PUBLIC_KEY_SIZE) {
        return -1;
    }

    if (nick_length > MAX_GC_NICK_SIZE) {
        return -3;
    }

    if (nick == nullptr || nick_length == 0) {
        return -4;
    }

    if (!friend_is_valid(c->messenger, friend_number)) {
        return -6;
    }

    const uint8_t *chat_id = data;
    const uint8_t *invite_chat_pk = data + CHAT_ID_SIZE;

    const int group_number = create_new_group(c, nick, nick_length, false);

    if (group_number == -1) {
        return -2;
    }

    GC_Chat *chat = gc_get_group(c, group_number);

    if (chat == nullptr) {
        return -2;
    }

    if (expand_chat_id(chat->chat_public_key, chat_id) != 0) {
        group_delete(c, chat);
        return -2;
    }

    if (passwd != nullptr && passwd_len > 0) {
        if (set_gc_password_local(chat, passwd, passwd_len) == -1) {
            group_delete(c, chat);
            return -5;
        }
    }

    const int peer_id = peer_add(c->messenger, group_number, nullptr, invite_chat_pk);

    if (peer_id < 0) {
        return -2;
    }

    if (send_gc_invite_accepted_packet(c->messenger, chat, friend_number)) {
        return -7;
    }

    return group_number;
}

GC_Session *new_dht_groupchats(Messenger *m)
{
    GC_Session *c = (GC_Session *)calloc(sizeof(GC_Session), 1);

    if (c == nullptr) {
        return nullptr;
    }

    c->messenger = m;
    c->announces_list = m->group_announce;

    networking_registerhandler(m->net, NET_PACKET_GC_LOSSLESS, &handle_gc_udp_packet, m);
    networking_registerhandler(m->net, NET_PACKET_GC_LOSSY, &handle_gc_udp_packet, m);
    networking_registerhandler(m->net, NET_PACKET_GC_HANDSHAKE, &handle_gc_udp_packet, m);

    return c;
}

static void group_cleanup(GC_Session *c, GC_Chat *chat)
{
    m_kill_group_connection(c->messenger, chat);
    mod_list_cleanup(chat);
    sanctions_list_cleanup(chat);

    if (chat->tcp_conn) {
        kill_tcp_connections(chat->tcp_conn);
    }

    gcc_cleanup(chat);

    if (chat->group) {
        free(chat->group);
        chat->group = nullptr;
    }

    crypto_memunlock(chat->self_secret_key, sizeof(chat->self_secret_key));
    crypto_memunlock(chat->chat_secret_key, sizeof(chat->chat_secret_key));
    crypto_memunlock(chat->shared_state.password, sizeof(chat->shared_state.password));
}

/* Deletes chat from group chat array and cleans up.
 *
 * Return 0 on success.
 * Return -1 on failure.
 */
static int group_delete(GC_Session *c, GC_Chat *chat)
{
    if (c == nullptr || chat == nullptr) {
        return -1;
    }

    group_cleanup(c, chat);

    c->chats[chat->group_number] = (GC_Chat) {
        nullptr
    };

    uint32_t i;

    for (i = c->num_chats; i > 0; --i) {
        if (c->chats[i - 1].connection_state != CS_NONE) {
            break;
        }
    }

    if (c->num_chats != i) {
        c->num_chats = i;

        if (realloc_groupchats(c, c->num_chats) != 0) {
            return -1;
        }
    }

    return 0;
}

int gc_group_exit(GC_Session *c, GC_Chat *chat, const uint8_t *message, uint16_t length)
{
    const int ret =  group_can_handle_packets(chat) ? send_gc_self_exit(chat, message, length) : 0;
    group_delete(c, chat);
    return ret;
}

void kill_dht_groupchats(GC_Session *c)
{
    for (uint32_t i = 0; i < c->num_chats; ++i) {
        GC_Chat *chat = &c->chats[i];

        if (group_can_handle_packets(chat)) {
            send_gc_self_exit(chat, nullptr, 0);
        }

        group_cleanup(c, chat);
    }

    networking_registerhandler(c->messenger->net, NET_PACKET_GC_LOSSY, nullptr, nullptr);
    networking_registerhandler(c->messenger->net, NET_PACKET_GC_LOSSLESS, nullptr, nullptr);
    networking_registerhandler(c->messenger->net, NET_PACKET_GC_HANDSHAKE, nullptr, nullptr);

    free(c->chats);
    free(c);
}

/* Return true if `group_number` designates an active group in session `c`. */
static bool group_number_valid(const GC_Session *c, int group_number)
{
    if (group_number < 0 || group_number >= c->num_chats) {
        return false;
    }

    if (c->chats == nullptr) {
        return false;
    }

    return c->chats[group_number].connection_state != CS_NONE;
}

uint32_t gc_count_groups(const GC_Session *c)
{
    uint32_t count = 0;

    for (uint32_t i = 0; i < c->num_chats; ++i) {
        if (c->chats[i].connection_state != CS_NONE) {
            ++count;
        }
    }

    return count;
}

GC_Chat *gc_get_group(const GC_Session *c, int group_number)
{
    if (!group_number_valid(c, group_number)) {
        return nullptr;
    }

    return &c->chats[group_number];
}

GC_Chat *gc_get_group_by_public_key(const GC_Session *c, const uint8_t *public_key)
{
    for (uint32_t i = 0; i < c->num_chats; ++i) {
        if (memcmp(public_key, get_chat_id(c->chats[i].chat_public_key), CHAT_ID_SIZE) == 0) {
            return &c->chats[i];
        }
    }

    return nullptr;
}

/* Return True if chat_id exists in the session chat array */
static bool group_exists(const GC_Session *c, const uint8_t *chat_id)
{
    for (uint32_t i = 0; i < c->num_chats; ++i) {
        if (memcmp(get_chat_id(c->chats[i].chat_public_key), chat_id, CHAT_ID_SIZE) == 0) {
            return true;
        }
    }

    return false;
}

/* Creates a new 32-byte session encryption keypair and puts the results in `public_key` and `secret_key`.
 *
 * Return 0 on success.
 * Return -1 if key generation fails.
 */
static int create_gc_session_keypair(uint8_t *public_key, uint8_t *secret_key)
{
    if (crypto_new_keypair(public_key, secret_key) != 0) {
        return -1;
    }

    return 0;
}

/* Creates a new 64-byte extended keypair for `chat` and puts results in `self_public_key`
 * and `self_secret_key` buffers.
 *
 * Return 0 on success.
 * Return -1 if key generation fails.
 */
static int create_new_chat_ext_keypair(GC_Chat *chat)
{
    if (create_extended_keypair(chat->self_public_key, chat->self_secret_key) != 0) {
        return -1;
    }

    return 0;
}

/* Adds TCP relays from `announce` to the TCP relays list for `gconn`.
 *
 * Returns the number of relays successfully added.
 */
static uint32_t add_gc_tcp_relays_from_announce(const GC_Chat *chat, GC_Connection *gconn, const GC_Announce *announce)
{
    uint32_t added_relays = 0;

    for (uint8_t j = 0; j < announce->tcp_relays_count; ++j) {
        const int add_tcp_result = add_tcp_relay_connection(chat->tcp_conn, gconn->tcp_connection_num,
                                   announce->tcp_relays[j].ip_port,
                                   announce->tcp_relays[j].public_key);

        if (add_tcp_result == -1) {
            continue;
        }

        if (gcc_save_tcp_relay(gconn, &announce->tcp_relays[j]) == -1) {
            continue;
        }

        if (added_relays == 0) {
            memcpy(gconn->oob_relay_pk, announce->tcp_relays[j].public_key, CRYPTO_PUBLIC_KEY_SIZE);
        }

        ++added_relays;
    }

    return added_relays;
}

int gc_add_peers_from_announces(const GC_Session *gc_session, GC_Chat *chat, GC_Announce *announces,
                                uint8_t gc_announces_count)
{
    if (chat == nullptr || announces == nullptr || gc_session == nullptr) {
        return -1;
    }

    if (!is_public_chat(chat)) {
        return 0;
    }

    int added_peers = 0;

    for (uint8_t i = 0; i < gc_announces_count; ++i) {
        GC_Announce *announce = &announces[i];

        if (!gca_is_valid_announce(announce)) {
            continue;
        }

        const bool ip_port_set = announce->ip_port_is_set;
        const IP_Port *ip_port = ip_port_set ? &announce->ip_port : nullptr;
        const int peer_number = peer_add(gc_session->messenger, chat->group_number, ip_port, announce->peer_public_key);

        GC_Connection *gconn = gcc_get_connection(chat, peer_number);

        if (gconn == nullptr) {
            continue;
        }

        uint32_t added_tcp_relays = add_gc_tcp_relays_from_announce(chat, gconn, announce);

        if (!ip_port_set && added_tcp_relays == 0) {
            LOGGER_WARNING(chat->logger, "Got invalid announcement: %u relays, IPP set: %d",
                           added_tcp_relays, ip_port_set);
            continue;
        }

        gconn->pending_handshake_type = HS_INVITE_REQUEST;

        if (!ip_port_set) {
            gconn->is_oob_handshake = true;
        }

        ++added_peers;
    }

    return added_peers;
}

#endif

