/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2020 The TokTok team.
 * Copyright © 2015 Tox project.
 */

/*
 * An implementation of massive text only group chats.
 */

#ifndef GROUP_CHATS_H
#define GROUP_CHATS_H

#include <stdbool.h>

#include "TCP_connection.h"
#include "group_announce.h"

#define MAX_GC_NICK_SIZE 128
#define MAX_GC_TOPIC_SIZE 512
#define MAX_GC_GROUP_NAME_SIZE 48
#define MAX_GC_MESSAGE_SIZE 1372
#define MAX_GC_PART_MESSAGE_SIZE 128
#define MAX_GC_PEER_ADDRS 30
#define MAX_GC_PASSWORD_SIZE 32
#define MAX_GC_MODERATORS 30
#define MAX_GC_SAVED_INVITES 50
#define MAX_GC_PEERS_DEFAULT 100
#define MAX_GC_PACKET_SIZE (uint16_t) 1400

#define GC_MOD_LIST_ENTRY_SIZE SIG_PUBLIC_KEY_SIZE
#define GC_MODERATION_HASH_SIZE CRYPTO_SHA256_SIZE
#define GC_SANCTION_HASH_SIZE CRYPTO_SHA256_SIZE
#define GC_PING_TIMEOUT 12
#define GC_SEND_IP_PORT_INTERVAL (GC_PING_TIMEOUT * 5)
#define GC_CONFIRMED_PEER_TIMEOUT (GC_PING_TIMEOUT * 6 + 10)
#define GC_UNCONFIRMED_PEER_TIMEOUT GC_PING_TIMEOUT

#define GC_JOIN_DATA_LENGTH (ENC_PUBLIC_KEY_SIZE + CHAT_ID_SIZE)

typedef enum Self_UDP_Status {
    SELF_UDP_STATUS_NONE = 0x00,
    SELF_UDP_STATUS_WAN  = 0x01,
    SELF_UDP_STATUS_LAN  = 0x02,
} Self_UDP_Status;

/* Group privacy states. */
typedef enum Group_Privacy_State {
    GI_PUBLIC   = 0x00,  // Anyone with the chat ID may join the group
    GI_PRIVATE  = 0x01,  // Peers may only join the group via a friend invite
} Group_Privacy_State;

/* Group topic lock states. */
typedef enum Group_Topic_Lock {
    TL_ENABLED  = 0x00,  // Only the Founder and moderators may set the topic
    TL_DISABLED = 0x01,  // Anyone except Observers may set the topic
} Group_Topic_Lock;

/* Group moderation events. */
typedef enum Group_Moderation_Event {
    MV_KICK      = 0x00,  // A peer has been kicked
    MV_OBSERVER  = 0x01,  // A peer has been demoted to Observer
    MV_USER      = 0x02,  // A peer has been demoted or promoted to User
    MV_MOD       = 0x03,  // A peer has been promoted to or demoted from Moderator
} Group_Moderation_Event;

/* Group exit types. */
typedef enum Group_Exit_Type {
    GC_EXIT_TYPE_QUIT              = 0x00,  // Peer left the group
    GC_EXIT_TYPE_TIMEOUT           = 0x01,  // Peer connection timed out
    GC_EXIT_TYPE_DISCONNECTED      = 0x02,  // Peer diconnected from group
    GC_EXIT_TYPE_SELF_DISCONNECTED = 0x03,  // Self disconnected from group
    GC_EXIT_TYPE_KICKED            = 0x04,  // Peer was kicked from the group
    GC_EXIT_TYPE_SYNC_ERR          = 0x05,  // Peer failed to sync with the group
    GC_EXIT_TYPE_NO_CALLBACK       = 0x06,  // The peer exit callback should not be triggered
} Group_Exit_Type;

/* Messenger level group invite types */
typedef enum Group_Invite_Message_Type {
    GROUP_INVITE              = 0x00,  // Peer has initiated an invite
    GROUP_INVITE_ACCEPTED     = 0x01,  // Peer has accepted the invite
    GROUP_INVITE_CONFIRMATION = 0x02,  // Peer has confirmed the accepted invite
} Group_Invite_Message_Type;

/*
 * Group roles. Roles are hierarchical in that each role has a set of privileges plus
 * all the privileges of the roles below it.
 */
typedef enum Group_Role {
    /* Group creator. All-powerful. Cannot be demoted or kicked. */
    GR_FOUNDER   = 0x00,

    /*
     * May promote or demote peers below them to any role below them.
     * May also kick peers below them and set the topic.
     */
    GR_MODERATOR = 0x01,

    /* may interact normally with the group. */
    GR_USER      = 0x02,

    /* May not interact with the group but may observe. */
    GR_OBSERVER  = 0x03,
} Group_Role;

typedef enum Group_Peer_Status {
    GS_NONE    = 0x00,
    GS_AWAY    = 0x01,
    GS_BUSY    = 0x02,
} Group_Peer_Status;

/* Group connection states. */
typedef enum GC_Conn_State {
    CS_NONE         = 0x00,  // Indicates a group is not initialized
    CS_DISCONNECTED = 0x01,  // Not receiving or sending any packets
    CS_CONNECTING   = 0x02,  // Attempting to establish a connection with peers in the group
    CS_CONNECTED    = 0x03,  // Has successfully received a sync response from a peer in the group
} GC_Conn_State;

/*
 * Group save connection state.
 *
 * Used to determine whether or not a group should auto-connect the next time it's loaded.
 */
typedef enum Saved_GC_Conn_State {
    SGCS_DISCONNECTED = 0x00,  // The saved group is currently disconnected
    SGCS_CONNECTED    = 0x01,  // The saved group is currently connected
} Saved_GC_Conn_State;

/* Handshake join types. */
typedef enum Group_Handshake_Join_Type {
    HJ_PUBLIC  = 0x00,  // Indicates the group was joined via the DHT
    HJ_PRIVATE = 0x01,  // Indicates the group was joined via a friend invite
} Group_Handshake_Join_Type;

typedef enum Group_Join_Rejected {
    GJ_GROUP_FULL       = 0x00,
    GJ_INVALID_PASSWORD = 0x01,
    GJ_INVITE_FAILED    = 0x02,
    GJ_INVALID          = 0x03,
} Group_Join_Rejected;

typedef enum Group_Broadcast_Type {
    GM_STATUS          = 0x00,
    GM_NICK            = 0x01,
    GM_PLAIN_MESSAGE   = 0x02,
    GM_ACTION_MESSAGE  = 0x03,
    GM_PRIVATE_MESSAGE = 0x04,
    GM_PEER_EXIT       = 0x05,
    GM_KICK_PEER       = 0x06,
    GM_SET_MOD         = 0x07,
    GM_SET_OBSERVER    = 0x08,
} Group_Broadcast_Type;

/*
 * Group packet types.
 *
 * For a detailed spec, see docs/DHT_Group_Chats_Packet_Spec.md
 */
typedef enum Group_Packet_Type {
    /* lossy packets (ID 0 is reserved) */
    GP_PING                     = 0x01,
    GP_MESSAGE_ACK              = 0x02,
    GP_INVITE_RESPONSE_REJECT   = 0x03,

    /* lossless packets */
    GP_KEY_ROTATION             = 0xf0,
    GP_TCP_RELAYS               = 0xf1,
    GP_CUSTOM_PACKET            = 0xf2,
    GP_BROADCAST                = 0xf3,
    GP_PEER_INFO_REQUEST        = 0xf4,
    GP_PEER_INFO_RESPONSE       = 0xf5,
    GP_INVITE_REQUEST           = 0xf6,
    GP_INVITE_RESPONSE          = 0xf7,
    GP_SYNC_REQUEST             = 0xf8,
    GP_SYNC_RESPONSE            = 0xf9,
    GP_TOPIC                    = 0xfa,
    GP_SHARED_STATE             = 0xfb,
    GP_MOD_LIST                 = 0xfc,
    GP_SANCTIONS_LIST           = 0xfd,
    GP_FRIEND_INVITE            = 0xfe,
    GP_HS_RESPONSE_ACK          = 0xff,
} Group_Packet_Type;

/* Lossless message acknowledgement types. */
typedef enum Group_Message_Ack_Type {
    GR_ACK_RECV    = 0x00,  // indicates a message has been received
    GR_ACK_REQ     = 0x01,  // indicates a message needs to be re-sent
} Group_Message_Ack_Type;

struct GC_Sanction_Creds {
    uint32_t    version;
    uint8_t     hash[GC_SANCTION_HASH_SIZE];    // hash of all sanctions list signatures + version
    uint16_t    checksum;  // a sum of the hash
    uint8_t     sig_pk[SIG_PUBLIC_KEY_SIZE];    // Last mod to have modified the sanctions list
    uint8_t     sig[SIGNATURE_SIZE];    // signature of hash, signed by sig_pk
};

typedef struct GC_Moderation {
    struct GC_Sanction *sanctions;
    struct GC_Sanction_Creds sanctions_creds;
    uint16_t    num_sanctions;

    uint8_t     **mod_list;  // array of public signature keys of all the mods
    uint16_t    num_mods;
} GC_Moderation;

typedef struct GC_PeerAddress {
    uint8_t     public_key[EXT_PUBLIC_KEY_SIZE];
    IP_Port     ip_port;
} GC_PeerAddress;

typedef struct GC_SavedPeerInfo {
    uint8_t     public_key[EXT_PUBLIC_KEY_SIZE];
    Node_format tcp_relay;
    IP_Port     ip_port;
} GC_SavedPeerInfo;

typedef struct GC_GroupPeer {
    Group_Role  role;
    uint8_t     nick[MAX_GC_NICK_SIZE];
    uint16_t    nick_length;
    uint8_t     status;

    /* Below variables are not sent to other peers */
    uint32_t    peer_id;    // permanent ID (used for the public API)
    bool        ignore;
} GC_GroupPeer;

typedef struct GC_SharedState {
    uint32_t    version;
    uint8_t     founder_public_key[EXT_PUBLIC_KEY_SIZE];
    uint32_t    maxpeers;
    uint16_t    group_name_len;
    uint8_t     group_name[MAX_GC_GROUP_NAME_SIZE];
    Group_Privacy_State privacy_state;   // GI_PUBLIC (uses DHT) or GI_PRIVATE (invite only)
    uint16_t    password_length;
    uint8_t     password[MAX_GC_PASSWORD_SIZE];
    uint8_t     mod_list_hash[GC_MODERATION_HASH_SIZE];
    uint32_t    topic_lock; // non-zero value when lock is enabled
} GC_SharedState;

typedef struct GC_TopicInfo {
    uint32_t    version;
    uint16_t    length;
    uint16_t    checksum;  // used for syncing problems. the checksum with the highest value gets priority.
    uint8_t     topic[MAX_GC_TOPIC_SIZE];
    uint8_t     public_sig_key[SIG_PUBLIC_KEY_SIZE];  // Public signature key of the topic setter
} GC_TopicInfo;

typedef struct GC_Connection GC_Connection;
typedef struct GC_Exit_Info GC_Exit_Info;

#define GROUP_SAVE_MAX_PEERS MAX_GC_PEER_ADDRS
#define GROUP_SAVE_MAX_MODERATORS 128  // must be <= MAX_GC_MODERATORS (temporary fix to prevent save format breakage)

struct Saved_Group {
    /* Group shared state */
    uint32_t  shared_state_version;
    uint8_t   shared_state_signature[SIGNATURE_SIZE];
    uint8_t   founder_public_key[EXT_PUBLIC_KEY_SIZE];
    uint16_t  maxpeers;
    uint16_t  group_name_length;
    uint8_t   group_name[MAX_GC_GROUP_NAME_SIZE];
    uint8_t   privacy_state;
    uint16_t  password_length;
    uint8_t   password[MAX_GC_PASSWORD_SIZE];
    uint8_t   mod_list_hash[GC_MODERATION_HASH_SIZE];
    uint8_t   topic_lock;

    /* Topic info */
    uint16_t  topic_length;
    uint8_t   topic[MAX_GC_TOPIC_SIZE];
    uint8_t   topic_public_sig_key[SIG_PUBLIC_KEY_SIZE];
    uint32_t  topic_version;
    uint8_t   topic_signature[SIGNATURE_SIZE];

    /* Other group info */
    uint8_t   chat_public_key[EXT_PUBLIC_KEY_SIZE];
    uint8_t   chat_secret_key[EXT_SECRET_KEY_SIZE];
    uint16_t  num_addrs;
    GC_SavedPeerInfo addrs[GROUP_SAVE_MAX_PEERS];
    uint16_t  num_mods;
    uint8_t   mod_list[GC_MOD_LIST_ENTRY_SIZE * GROUP_SAVE_MAX_MODERATORS];
    uint8_t   group_connection_state;

    /* self info */
    uint8_t   self_public_key[EXT_PUBLIC_KEY_SIZE];
    uint8_t   self_secret_key[EXT_SECRET_KEY_SIZE];
    uint8_t   self_nick[MAX_GC_NICK_SIZE];
    uint16_t  self_nick_length;
    uint8_t   self_role;
    uint8_t   self_status;
};

typedef struct Saved_Group Saved_Group;

typedef struct GC_Chat {
    const Mono_Time *mono_time;
    const Logger    *logger;

    Self_UDP_Status self_udp_status;
    IP_Port         self_ip_port;


    Networking_Core *net;
    TCP_Connections *tcp_conn;

    bool            new_tcp_relay;   // true if we need to send peers a new TCP relay
    uint16_t        tcp_connections; // the number of global TCP relays we're connected to
    uint64_t        last_checked_tcp_relays;

    GC_GroupPeer    *group;
    GC_Connection   *gcc;
    GC_Moderation   moderation;

    GC_Conn_State   connection_state;

    GC_SharedState  shared_state;
    uint8_t         shared_state_sig[SIGNATURE_SIZE];  // signed by founder using the chat secret key

    GC_TopicInfo    topic_info;
    uint8_t         topic_sig[SIGNATURE_SIZE];  // signed by the peer who set the current topic

    uint16_t    peers_checksum;  // a sum of the public key hash of every confirmed peer in the group
    uint32_t    numpeers;
    int         group_number;

    uint8_t     chat_public_key[EXT_PUBLIC_KEY_SIZE];  // the chat_id is the sig portion
    uint8_t     chat_secret_key[EXT_SECRET_KEY_SIZE];  // only used by the founder

    uint8_t     self_public_key[EXT_PUBLIC_KEY_SIZE];
    uint8_t     self_secret_key[EXT_SECRET_KEY_SIZE];

    uint32_t    self_public_key_hash;  // Jenkins one at a time hash of our self public encryption key

    uint64_t    time_connected;
    uint64_t    last_ping_interval;
    uint64_t    last_sync_request;

    Group_Handshake_Join_Type join_type;

    /* keeps track of frequency of new inbound connections */
    uint8_t     connection_O_metre;
    uint64_t    connection_cooldown_timer;
    bool        block_handshakes;

    int32_t     saved_invites[MAX_GC_SAVED_INVITES];
    uint8_t     saved_invites_index;

    bool        update_self_announces;  // true if we should try to update our announcements
    uint64_t    last_self_announce_check;  // the last time we checked if we should update our announcements

    uint8_t     m_group_public_key[CRYPTO_PUBLIC_KEY_SIZE];  // public key for group's messenger friend connection
    int         friend_connection_id;  // identifier for group's messenger friend connection
} GC_Chat;

#ifndef MESSENGER_DEFINED
#define MESSENGER_DEFINED
typedef struct Messenger Messenger;
#endif /* MESSENGER_DEFINED */

typedef void gc_message_cb(Messenger *m, uint32_t group_number, uint32_t peer_id, unsigned int type,
                           const uint8_t *data, size_t length, void *user_data);
typedef void gc_private_message_cb(Messenger *m, uint32_t group_number, uint32_t peer_id, unsigned int type,
                                   const uint8_t *data, size_t length, void *user_data);
typedef void gc_custom_packet_cb(Messenger *m, uint32_t group_number, uint32_t peer_id, const uint8_t *data,
                                 size_t length, void *user_data);
typedef void gc_moderation_cb(Messenger *m, uint32_t group_number, uint32_t peer_id, uint32_t target_peer,
                              unsigned int mod_event, void *user_data);
typedef void gc_nick_change_cb(Messenger *m, uint32_t group_number, uint32_t peer_id, const uint8_t *data,
                               size_t length, void *user_data);
typedef void gc_status_change_cb(Messenger *m, uint32_t group_number, uint32_t peer_id, unsigned int status,
                                 void *user_data);
typedef void gc_topic_change_cb(Messenger *m, uint32_t group_number, uint32_t peer_id, const uint8_t *data,
                                size_t length, void *user_data);
typedef void gc_topic_lock_cb(Messenger *m, uint32_t group_number, unsigned int topic_lock, void *user_data);
typedef void gc_peer_limit_cb(Messenger *m, uint32_t group_number, uint32_t max_peers, void *user_data);
typedef void gc_privacy_state_cb(Messenger *m, uint32_t group_number, unsigned int state, void *user_data);
typedef void gc_password_cb(Messenger *m, uint32_t group_number, const uint8_t *data, size_t length, void *user_data);
typedef void gc_peer_join_cb(Messenger *m, uint32_t group_number, uint32_t peer_id, void *user_data);
typedef void gc_peer_exit_cb(Messenger *m, uint32_t group_number, uint32_t peer_id, unsigned int exit_type,
                             const uint8_t *nick, size_t nick_len, const uint8_t *data, size_t length, void *user_data);
typedef void gc_self_join_cb(Messenger *m, uint32_t group_number, void *user_data);
typedef void gc_rejected_cb(Messenger *m, uint32_t group_number, unsigned int type, void *user_data);

typedef struct GC_Session {
    Messenger                 *messenger;
    GC_Chat                   *chats;
    struct GC_Announces_List  *announces_list;

    uint32_t     num_chats;

    gc_message_cb *message;
    gc_private_message_cb *private_message;
    gc_custom_packet_cb *custom_packet;
    gc_moderation_cb *moderation;
    gc_nick_change_cb *nick_change;
    gc_status_change_cb *status_change;
    gc_topic_change_cb *topic_change;
    gc_topic_lock_cb *topic_lock;
    gc_peer_limit_cb *peer_limit;
    gc_privacy_state_cb *privacy_state;
    gc_password_cb *password;
    gc_peer_join_cb *peer_join;
    gc_peer_exit_cb *peer_exit;
    gc_self_join_cb *self_join;
    gc_rejected_cb *rejected;
} GC_Session;


/* Returns the jenkins hash of a 32 byte public encryption key. */
uint32_t gc_get_pk_jenkins_hash(const uint8_t *public_key);

/* Encrypts `data` of size `length` using the peer's shared key and a new nonce.
 *
 * Adds encrypted header consisting of: packet type, message_id (only for lossless packets).
 * Adds plaintext header consisting of: packet identifier, chat_id_hash, self public encryption key, nonce.
 *
 * Returns length of encrypted packet on success.
 * Returns -1 on failure.
 */
int group_packet_wrap(const Logger *logger, const uint8_t *self_pk, const uint8_t *shared_key, uint8_t *packet,
                      uint32_t packet_size, const uint8_t *data, uint32_t length, uint64_t message_id, uint8_t gp_packet_type,
                      uint32_t chat_id_hash, uint8_t net_packet_type);

/* Packs group info for `chat` into `temp`. */
void gc_pack_group_info(const GC_Chat *chat, Saved_Group *temp);

/* Sends a plain message or an action, depending on type.
 *
 * `length` must not exceept MAX_GC_MESSAGE_SIZE and must not be equal to zero.
 *
 * Returns 0 on success.
 * Returns -1 if the message is too long.
 * Returns -2 if the message pointer is NULL or length is zero.
 * Returns -3 if the message type is invalid.
 * Returns -4 if the sender has the observer role.
 * Returns -5 if the packet fails to send.
 */
int gc_send_message(const GC_Chat *chat, const uint8_t *message, uint16_t length, uint8_t type);

/* Sends a private message to peer_id.
 *
 * `length` must not exceept MAX_GC_MESSAGE_SIZE and must not be equal to zero.
 *
 * Returns 0 on success.
 * Returns -1 if the message is too long.
 * Returns -2 if the message pointer is NULL or length is zero.
 * Returns -3 if the peer_id is invalid.
 * Returns -4 if the message type is invalid.
 * Returns -5 if the sender has the observer role.
 * Returns -6 if the packet fails to send.
 */
int gc_send_private_message(const GC_Chat *chat, uint32_t peer_id, uint8_t type, const uint8_t *message,
                            uint16_t length);

/* Sends a custom packet to the group. If lossless is true, the packet will be lossless.
 *
 * `length` must not exceept MAX_GC_MESSAGE_SIZE and must not be equal to zero.
 *
 * Returns 0 on success.
 * Returns -1 if the message is too long.
 * Returns -2 if the message pointer is NULL or length is zero.
 * Returns -3 if the sender has the observer role.
 */
int gc_send_custom_packet(const GC_Chat *chat, bool lossless, const uint8_t *data, uint32_t length);

/* Toggles ignore for peer_id.
 *
 * Returns 0 on success.
 * Returns -1 if the peer_id is invalid.
 * Returns -2 if the caller attempted to ignore himself.
 */
int gc_toggle_ignore(GC_Chat *chat, uint32_t peer_id, bool ignore);

/* Sets the group topic and broadcasts it to the group.
 *
 * If `length` is equal to zero or topic is null the topic will be unset.
 *
 * Returns 0 on success.
 * Returns -1 if the topic is too long (must be <= MAX_GC_TOPIC_LENGTH).
 * Returns -2 if the caller does not have the required permissions to set the topic.
 * Returns -3 if the packet cannot be created or signing fails.
 * Returns -4 if the packet fails
 */
int gc_set_topic(GC_Chat *chat, const uint8_t *topic, uint16_t length);

/* Copies the group topic to `topic`. If topic is null this function has no effect.
 *
 * Call `gc_get_topic_size` to determine the allocation size for the `topic` parameter.
 *
 * The data written to `topic` is equal to the data received by the last topic callback.
 */
void gc_get_topic(const GC_Chat *chat, uint8_t *topic);

/* Returns the topic length.
 *
 * The return value is equal to the `length` agument received by the last topic
 * callback.
 */
uint16_t gc_get_topic_size(const GC_Chat *chat);

/* Copies group name to `group_name`. If `group_name` is null this function has no effect.
 *
 * Call `gc_get_group_name_size` to determine the allocation size for the `group_name`
 * parameter.
 */
void gc_get_group_name(const GC_Chat *chat, uint8_t *group_name);

/* Returns the group name length. */
uint16_t gc_get_group_name_size(const GC_Chat *chat);

/* Copies the group password to password. If password is null this function has no effect.
 *
 * Call the `gc_get_password_size` function to determine the allocation size for
 * the `password` buffer.
 *
 * The data received is equal to the data received by the last password callback.
 */
void gc_get_password(const GC_Chat *chat, uint8_t *password);

/* Returns the group password length. */
uint16_t gc_get_password_size(const GC_Chat *chat);

/* Returns the group privacy state.
 *
 * The value returned is equal to the data receieved by the last privacy_state callback.
 */
Group_Privacy_State gc_get_privacy_state(const GC_Chat *chat);

/* Returns the group topic lock state.
 *
 * The value returned is equal to the data received by the last last topic_lock callback.
 */
Group_Topic_Lock gc_get_topic_lock_state(const GC_Chat *chat);

/* Returns the group peer limit.
 *
 * The value returned is equal to the data receieved by the last peer_limit callback.
 */
uint32_t gc_get_max_peers(const GC_Chat *chat);

/* Sets your own nick to `nick`.
 *
 * `length` cannot exceed MAX_GC_NICK_SIZE. if `length` is zero or `name` is a
 * null pointer the function call will fail.
 *
 * Returns 0 on success.
 * Returns -1 if group_number is invalid.
 * Returns -2 if the length is too long.
 * Returns -3 if the length is zero or nick is a NULL pointer.
 * Returns -4 if the nick is already taken.
 * Returns -5 if the packet fails to send.
 */
int gc_set_self_nick(const Messenger *m, int group_number, const uint8_t *nick, uint16_t length);

/* Copies your own name to `nick`. If `nick` is null this function has no effect. */
void gc_get_self_nick(const GC_Chat *chat, uint8_t *nick);

/* Return your own nick length.
 *
 * If no nick was set before calling this function it will return 0.
 */
uint16_t gc_get_self_nick_size(const GC_Chat *chat);

/* Returns your own group role. */
Group_Role gc_get_self_role(const GC_Chat *chat);

/* Return your own status. */
uint8_t gc_get_self_status(const GC_Chat *chat);

/* Returns your own peer id. */
uint32_t gc_get_self_peer_id(const GC_Chat *chat);

/* Copies self public key to `public_key`. If `public_key` is null this function has no effect.
 *
 * This key is permanently tied to our identity for `chat` until we explicitly
 * exit the group. This key is the only way for other peers to reliably identify
 * us across client restarts.
 */
void gc_get_self_public_key(const GC_Chat *chat, uint8_t *public_key);

/* Copies nick designated by `peer_id` to `name`.
 *
 * Call `gc_get_peer_nick_size` to determine the allocation size for the `name` parameter.
 *
 * The data written to `name` is equal to the data received by the last nick_change callback.
 *
 * Returns 0 on success.
 * Returns -1 if peer_id is invalid.
 */
int gc_get_peer_nick(const GC_Chat *chat, uint32_t peer_id, uint8_t *name);

/* Returns the length of the nick for the peer designated by `peer_id`.
 * Returns -1 if peer_id is invalid.
 *
 * The value returned is equal to the `length` argument received by the last
 * nick_change callback.
 */
int gc_get_peer_nick_size(const GC_Chat *chat, uint32_t peer_id);

/* Copies peer_id's public key to `public_key`.
 *
 * This key is permanently tied to the peer's identity for `chat` until they explicitly
 * exit the group. This key is the only way for to reliably identify the given peer
 * across client restarts.
 *
 * `public_key` shold have room for at least ENC_PUBLIC_KEY_SIZE bytes.
 *
 * Returns 0 on success.
 * Returns -1 if peer_id is invalid or doesn't correspond to a valid peer connection.
 * Returns -2 if `public_key` is null.
 */
int gc_get_peer_public_key_by_peer_id(const GC_Chat *chat, uint32_t peer_id, uint8_t *public_key);

/* Gets the connection status for peer associated with `peer_id`.
 *
 * Returns 2 if we have a direct (UDP) connection with a peer.
 * Returns 1 if we have an indirect (TCP) connection with a peer.
 * Returns 0 if peer_id is invalid or corresponds to ourselves.
 *
 * Note: Return values must correspond to Tox_Connection enum in API.
 */
unsigned int gc_get_peer_connection_status(const GC_Chat *chat, uint32_t peer_id);

/* Sets the caller's status to `status`.
 *
 * Returns 0 on success.
 * Returns -1 if the group_number is invalid.
 * Returns -2 if the packet failed to send.
 */
int gc_set_self_status(const Messenger *m, int group_number, Group_Peer_Status status);

/* Returns the status of peer designated by `peer_id`.
 * Returns (uint8_t) -1 on failure.
 *
 * The status returned is equal to the last status received through the status_change
 * callback.
 */
uint8_t gc_get_status(const GC_Chat *chat, uint32_t peer_id);

/* Returns the group role of peer designated by `peer_id`.
 * Returns (uint8_t)-1 on failure.
 *
 * The role returned is equal to the last role received through the moderation callback.
 */
uint8_t gc_get_role(const GC_Chat *chat, uint32_t peer_id);

/* Sets the role of peer_id. role must be one of: GR_MODERATOR, GR_USER, GR_OBSERVER
 *
 * Returns 0 on success.
 * Returns -1 if the group_number is invalid.
 * Returns -2 if the peer_id is invalid.
 * Returns -3 if caller does not have sufficient permissions for the action.
 * Returns -4 if the role assignment is invalid.
 * Returns -5 if the role failed to be set.
 * Returns -6 if the caller attempted to kick himself.
 */
int gc_set_peer_role(const Messenger *m, int group_number, uint32_t peer_id, Group_Role role);

/* Sets the group password and distributes the new shared state to the group.
 *
 * This function requires that the shared state be re-signed and will only work for the group founder.
 *
 * If `password` is null or `password_length` is 0 the password will be unset for the group.
 *
 * Returns 0 on success.
 * Returns -1 if the caller does not have sufficient permissions for the action.
 * Returns -2 if the password is too long.
 * Returns -3 if the packet failed to send.
 * Returns -4 if malloc failed.
 */
int gc_founder_set_password(GC_Chat *chat, const uint8_t *password, uint16_t password_length);

/* Sets the topic lock and distributes the new shared state to the group.
 *
 * When the topic lock is enabled, only the group founder and moderators may set the topic.
 * When disabled, all peers except those with the observer role may set the topic.
 *
 * This function requires that the shared state be re-signed and will only work for the group founder.
 *
 * Returns 0 on success.
 * Returns -1 if group_number is invalid.
 * Returns -2 if `topic_lock` is an invalid type.
 * Returns -3 if the caller does not have sufficient permissions for this action.
 * Returns -4 if the group is disconnected.
 * Returns -5 if the topic lock could not be set.
 * Returns -6 if the packet failed to send.
 */
int gc_founder_set_topic_lock(Messenger *m, int group_number, Group_Topic_Lock topic_lock);

/* Sets the group privacy state and distributes the new shared state to the group.
 *
 * This function requires that the shared state be re-signed and will only work for the group founder.
 *
 * If an attempt is made to set the privacy state to the same state that the group is already
 * in, the function call will be successful and no action will be taken.
 *
 * Returns 0 on success.
 * Returns -1 if group_number is invalid.
 * Returns -2 if the caller does not have sufficient permissions for this action.
 * Returns -3 if the group is disconnected.
 * Returns -4 if the privacy state could not be set.
 * Returns -5 if the packet failed to send.
 */
int gc_founder_set_privacy_state(Messenger *m, int group_number, Group_Privacy_State new_privacy_state);

/* Sets the peer limit to maxpeers and distributes the new shared state to the group.
 *
 * This function requires that the shared state be re-signed and will only work for the group founder.
 *
 * Returns 0 on success.
 * Returns -1 if the caller does not have sufficient permissions for this action.
 * Returns -2 if the peer limit could not be set.
 * Returns -3 if the packet failed to send.
 */
int gc_founder_set_max_peers(GC_Chat *chat, uint32_t max_peers);

/* Removes peer designated by `peer_id` from peer list and sends a broadcast instructing
 * all other peers to remove the peer from their peerlist as well.
 *
 * This function will not trigger the peer_exit callback for the caller.
 *
 * Returns 0 on success.
 * Returns -1 if the group_number is invalid.
 * Returns -2 if the peer_id is invalid.
 * Returns -3 if the caller does not have sufficient permissions for this action.
 * Returns -4 if the action failed.
 * Returns -5 if the packet failed to send.
 * Returns -6 if the caller attempted to kick himself.
 */
int gc_kick_peer(Messenger *m, int group_number, uint32_t peer_id);

/* Copies the chat_id to dest. If dest is null this function has no effect.
 *
 * `dest` should have room for at least CHAT_ID_SIZE bytes.
 */
void gc_get_chat_id(const GC_Chat *chat, uint8_t *dest);


/* Group callbacks */
void gc_callback_message(Messenger *m, gc_message_cb *function);
void gc_callback_private_message(Messenger *m, gc_private_message_cb *function);
void gc_callback_custom_packet(Messenger *m, gc_custom_packet_cb *function);
void gc_callback_moderation(Messenger *m, gc_moderation_cb *function);
void gc_callback_nick_change(Messenger *m, gc_nick_change_cb *function);
void gc_callback_status_change(Messenger *m, gc_status_change_cb *function);
void gc_callback_topic_change(Messenger *m, gc_topic_change_cb *function);
void gc_callback_peer_limit(Messenger *m, gc_peer_limit_cb *function);
void gc_callback_privacy_state(Messenger *m, gc_privacy_state_cb *function);
void gc_callback_topic_lock(Messenger *m, gc_topic_lock_cb *function);
void gc_callback_password(Messenger *m, gc_password_cb *function);
void gc_callback_peer_join(Messenger *m, gc_peer_join_cb *function);
void gc_callback_peer_exit(Messenger *m, gc_peer_exit_cb *function);
void gc_callback_self_join(Messenger *m, gc_self_join_cb *function);
void gc_callback_rejected(Messenger *m, gc_rejected_cb *function);

/* The main loop. Should be called with every Messenger iteration. */
void do_gc(GC_Session *c, void *userdata);

/* Returns a NULL pointer if fail.
 * Make sure that DHT is initialized before calling this
 */
GC_Session *new_dht_groupchats(Messenger *m);

/* Cleans up groupchat structures and calls gc_group_exit() for every group chat */
void kill_dht_groupchats(GC_Session *c);

/* Loads a previously saved group and attempts to join it.
 *
 * `save` is the packed group info.
 *
 * Returns group_number on success.
 * Returns -1 on failure.
 */
int gc_group_load(GC_Session *c, const Saved_Group *save, int group_number);

/* Creates a new group and adds it to the group sessions group array.
 *
 * The caller of this function has founder role privileges.
 *
 * The client should initiate its peer list with self info after calling this function, as
 * the peer_join callback will not be triggered.
 *
 * Return -1 if the nick or group name is too long.
 * Return -2 if the nick or group name is empty.
 * Return -3 if the the group object fails to initialize.
 * Return -4 if the group state fails to initialize.
 * Return -5 if the Messenger friend connection fails to initialize.
 */
int gc_group_add(GC_Session *c, Group_Privacy_State privacy_state, const uint8_t *group_name,
                 uint16_t group_name_length,
                 const uint8_t *nick, size_t nick_length);

/* Joins a group designated by `chat_id`.
 *
 * This function creates a new GC_Chat object, adds it to the chats array, and sends a DHT
 * announcement to find peers in the group associated with `chat_id`. Once a peer has been
 * found a join attempt will be initiated.
 *
 * If the group is not password protected password should be set to NULL and password_length should be 0.
 *
 * Return group_number on success.
 * Return -1 if the group object fails to initialize.
 * Return -2 if chat_id is NULL or a group with chat_id already exists in the chats array.
 * Return -3 if nick is too long.
 * Return -4 if nick is empty or nick length is zero.
 * Return -5 if there is an error setting the group password.
 * Return -6 if the Messenger friend connection fails to initialize.
 */
int gc_group_join(GC_Session *c, const uint8_t *chat_id, const uint8_t *nick, size_t nick_length, const uint8_t *passwd,
                  uint16_t passwd_len);

/* Disconnects from all peers in a group but saves the group state for later use.
 *
 * Return 0 on sucess.
 * Return -1 if the group handler object or chat object is null.
 * Return -2 if malloc fails.
 */
int gc_disconnect_from_group(GC_Session *c, GC_Chat *chat);

/* Disconnects from all peers in a group and attempts to reconnect. All self
 * state and credentials are retained.
 *
 * Returns 0 on success.
 * Returns -1 if the group handler object or chat object is null.
 * Returns -2 if the Messenger friend connection fails to initialize.
 */
int gc_rejoin_group(GC_Session *c, GC_Chat *chat);

/* Joins a group using the invite data received in a friend's group invite. The invite is
 * only valid while the inviter is present in the group.
 *
 * Return group_number on success.
 * Return -1 if the invite data is malformed.
 * Return -2 if the group object fails to initialize.
 * Return -3 if nick is too long.
 * Return -4 if nick is empty or nick length is zero.
 * Return -5 if there is an error setting the password.
 * Return -6 if friend doesn't exist.
 * Return -7 if sending packet failed.
 */
int gc_accept_invite(GC_Session *c, int32_t friend_number, const uint8_t *data, uint16_t length, const uint8_t *nick,
                     size_t nick_length, const uint8_t *passwd, uint16_t passwd_len);

typedef int gc_send_group_invite_packet_cb(const Messenger *m, uint32_t friendnumber, const uint8_t *packet,
        size_t length);

/* Invites friend designated by `friendnumber` to chat.
 * Packet includes: Type, chat_id, TCP node or packed IP_Port.
 *
 * Return 0 on success.
 * Return -1 if friendnumber does not exist.
 * Return -2 on failure to create the invite data.
 * Return -3 if the packet fails to send.
 */
int gc_invite_friend(const GC_Session *c, GC_Chat *chat, int32_t friendnum,
                     gc_send_group_invite_packet_cb *send_group_invite_packet);

/* Leaves a group and sends an exit broadcast packet with an optional parting message.
 *
 * All group state is permanently lost, including keys and roles.
 *
 * Return 0 on success.
 * Return -1 if the parting message is too long.
 * Return -2 if the parting message failed to send.
 * Return -3 if the group instance failed delete.
 */
int gc_group_exit(GC_Session *c, GC_Chat *chat, const uint8_t *message, uint16_t length);

/* Returns the number of active groups in `c`. */
uint32_t gc_count_groups(const GC_Session *c);

/* Returns true if peer_number exists */
bool gc_peer_number_is_valid(const GC_Chat *chat, int peer_number);

/* Return group_number's GC_Chat pointer on success
 * Return NULL on failure
 */
GC_Chat *gc_get_group(const GC_Session *c, int group_number);

/* Copies up to max_addrs peer addresses from chat into addrs.
 *
 * Returns number of addresses copied.
 */
uint16_t gc_copy_peer_addrs(const GC_Chat *chat, GC_SavedPeerInfo *addrs, size_t max_addrs);

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
int gc_send_message_ack(const GC_Chat *chat, GC_Connection *gconn, uint64_t message_id, Group_Message_Ack_Type type);

/* Helper function for handle_gc_lossless_packet().
 *
 * Return 0 if packet is successfully handled.
 * Return -1 on failure.
 */
int handle_gc_lossless_helper(Messenger *m, int group_number, uint32_t peer_number, const uint8_t *data,
                              uint16_t length, uint64_t message_id, uint8_t packet_type, void *userdata);

/* Handles an invite accept packet.
 *
 * Return 0 on success.
 * Return -1 on failure.
 */
int handle_gc_invite_accepted_packet(GC_Session *c, int friend_number, const uint8_t *data, uint32_t length);

/* Return true if `chat_id` is not present in our group sessions array.
 *
 * `length` must be at least CHAT_ID_SIZE bytes in length.
 */
bool group_not_added(const GC_Session *c, const uint8_t *chat_id, uint32_t length);

/* Handles an invite confirmed packet.
 *
 * Return 0 on success.
 * Return -1 if length is invalid.
 * Return -2 if data contains invalid chat_id.
 * Return -3 if data contains invalid peer info.
 * Return -4 if `friend_number` does not designate a valid friend.
 * Return -5 if data contains invalid connection info.
 */
int handle_gc_invite_confirmed_packet(const GC_Session *c, int friend_number, const uint8_t *data, uint32_t length);

/* Returns the group designated by `public_key`.
 * Returns null if group does not exist.
 */
GC_Chat *gc_get_group_by_public_key(const GC_Session *c, const uint8_t *public_key);

/* Attempts to add peers from `announces` to our peer list and initiate an invite request.
 *
 * Returns the number of peers added on success.
 * Returns -1 on failure.
 */
int gc_add_peers_from_announces(const GC_Session *gc_session, GC_Chat *chat, GC_Announce *announces,
                                uint8_t gc_announces_count);

/* Puts the encryption public key associated with `signature_key` in `public_key`.
 *
 * `public_key` must have room for at least ENC_PUBLIC_KEY_SIZE bytes.
 *
 * Return 0 on success.
 * Return -1 if no peer associated with signature key is found.
 */
int gc_get_enc_pk_from_sig_pk(const GC_Chat *chat, uint8_t *public_key, const uint8_t *signature_key);

#endif  // GROUP_CHATS_H
