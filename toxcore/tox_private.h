/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2026 The TokTok team.
 * Copyright © 2013 Tox project.
 */

#ifndef C_TOXCORE_TOXCORE_TOX_PRIVATE_H
#define C_TOXCORE_TOXCORE_TOX_PRIVATE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "tox.h"
#include "tox_attributes.h"
#include "tox_events.h"
#include "tox_options.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef uint64_t tox_mono_time_cb(void *_Nullable user_data);

typedef struct Random Random;
typedef struct Network Network;
typedef struct Memory Memory;

typedef struct Tox_System {
    tox_mono_time_cb *_Nullable mono_time_callback;
    void *_Nullable mono_time_user_data;
    const Random *_Nullable rng;
    const Network *_Nullable ns;
    const Memory *_Nullable mem;
} Tox_System;

Tox_System tox_default_system(void);

const Tox_System *_Nonnull tox_get_system(const Tox *_Nonnull tox);

typedef struct Tox_Options_Testing {
    const struct Tox_System *_Nullable operating_system;
} Tox_Options_Testing;

typedef enum Tox_Err_New_Testing {
    TOX_ERR_NEW_TESTING_OK,
    TOX_ERR_NEW_TESTING_NULL,
} Tox_Err_New_Testing;

Tox *_Nullable tox_new_testing(const Tox_Options *_Nonnull options, Tox_Err_New *_Nullable error, const Tox_Options_Testing *_Nonnull testing, Tox_Err_New_Testing *_Nullable testing_error);

typedef enum Tox_Err_Iterate_Options_New {
    TOX_ERR_ITERATE_OPTIONS_NEW_OK,
    TOX_ERR_ITERATE_OPTIONS_NEW_MALLOC,
} Tox_Err_Iterate_Options_New;

typedef struct Tox_Iterate_Options Tox_Iterate_Options;

/**
 * Allocates a new Tox_Iterate_Options object and initializes it with
 * default values.
 *
 * Default values:
 * - fail_hard: false
 *
 * @param error An error code. Will be set to OK on success.
 * @return A new options object or NULL on failure.
 */
Tox_Iterate_Options *_Nullable tox_iterate_options_new(Tox_Err_Iterate_Options_New *_Nullable error);

/**
 * Frees the options object.
 */
void tox_iterate_options_free(Tox_Iterate_Options *_Nullable options);

/**
 * Set whether to drop all events when any allocation fails.
 *
 * This only applies when using tox_events_iterate.
 */
void tox_iterate_options_set_fail_hard(Tox_Iterate_Options *_Nonnull options, bool fail_hard);

/**
 * Get whether to drop all events when any allocation fails.
 */
bool tox_iterate_options_get_fail_hard(const Tox_Iterate_Options *_Nullable options);

/**
 * Run a single tox_iterate iteration with custom options.
 */
void tox_iterate_with_options(
    Tox *_Nonnull tox,
    const Tox_Iterate_Options *_Nullable options,
    void *_Nullable user_data);

void tox_lock(const Tox *_Nonnull tox);
void tox_unlock(const Tox *_Nonnull tox);

Tox_Events *_Nullable tox_iterate_internal(Tox *_Nonnull tox, Tox_Err_Events_Iterate *_Nullable error);

/**
 * Set the callback for the `friend_lossy_packet` event for a specific packet
 * ID. Pass NULL to unset.
 *
 * allowed packet ID range:
 * from `PACKET_ID_RANGE_LOSSY_START` to `PACKET_ID_RANGE_LOSSY_END` (both
 * inclusive)
 */
void tox_callback_friend_lossy_packet_per_pktid(Tox *_Nonnull tox, tox_friend_lossy_packet_cb *_Nullable callback, uint8_t pktid);

/**
 * Set the callback for the `friend_lossless_packet` event for a specific packet
 * ID. Pass NULL to unset.
 *
 * allowed packet ID range:
 * from `PACKET_ID_RANGE_LOSSLESS_CUSTOM_START` to
 * `PACKET_ID_RANGE_LOSSLESS_CUSTOM_END` (both inclusive) and `PACKET_ID_MSI`
 */
void tox_callback_friend_lossless_packet_per_pktid(Tox *_Nonnull tox, tox_friend_lossless_packet_cb *_Nullable callback, uint8_t pktid);

/**
 * Send a lossless packet with any packet ID, including the IDs toxcore uses
 * for its own packets.
 *
 * `tox_friend_send_lossless_packet` only sends custom packet IDs. Tests use
 * this function to send packets that a client can't, such as a malformed
 * conference invite. Otherwise it works the same: the first byte of `data` is
 * the packet ID.
 */
bool tox_friend_send_lossless_packet_any_id(Tox *_Nonnull tox, uint32_t friend_number, const uint8_t *_Nonnull data, size_t length,
        Tox_Err_Friend_Custom_Packet *_Nullable error);

void tox_set_av_object(Tox *_Nonnull tox, void *_Nullable object);
void *_Nullable tox_get_av_object(const Tox *_Nonnull tox);

/*******************************************************************************
 *
 * :: DHT network queries.
 *
 ******************************************************************************/

/**
 * The minimum size of an IP string buffer in bytes.
 */
#define TOX_DHT_NODE_IP_STRING_SIZE      96

uint32_t tox_dht_node_ip_string_size(void);

/**
 * The size of a DHT node public key in bytes.
 */
#define TOX_DHT_NODE_PUBLIC_KEY_SIZE     32

uint32_t tox_dht_node_public_key_size(void);

/**
 * @param public_key The node's public key.
 * @param ip The node's IP address, represented as a NUL-terminated C string.
 * @param port The node's port.
 */
typedef void tox_dht_nodes_response_cb(
    Tox *_Nonnull tox, const uint8_t *_Nonnull public_key, const char *_Nonnull ip, uint32_t ip_length,
    uint16_t port, void *_Nullable user_data);

/**
 * Set the callback for the `dht_nodes_response` event. Pass NULL to unset.
 *
 * This event is triggered when a nodes response is received from a DHT peer.
 */
void tox_callback_dht_nodes_response(Tox *_Nonnull tox, tox_dht_nodes_response_cb *_Nullable callback);

typedef enum Tox_Err_Dht_Send_Nodes_Request {
    /**
     * The function returned successfully.
     */
    TOX_ERR_DHT_SEND_NODES_REQUEST_OK,

    /**
     * UDP is disabled in Tox options; the DHT can only be queried when UDP is
     * enabled.
     */
    TOX_ERR_DHT_SEND_NODES_REQUEST_UDP_DISABLED,

    /**
     * One of the arguments to the function was NULL when it was not expected.
     */
    TOX_ERR_DHT_SEND_NODES_REQUEST_NULL,

    /**
     * The supplied port is invalid.
     */
    TOX_ERR_DHT_SEND_NODES_REQUEST_BAD_PORT,

    /**
     * The supplied IP address is invalid.
     */
    TOX_ERR_DHT_SEND_NODES_REQUEST_BAD_IP,

    /**
     * The nodes request failed. This usually means the packet failed to
     * send.
     */
    TOX_ERR_DHT_SEND_NODES_REQUEST_FAIL,
} Tox_Err_Dht_Send_Nodes_Request;

/**
 * This function sends a nodes request to a DHT node for its peers that
 * are "close" to the passed target public key according to the distance metric
 * used by the DHT implementation.
 *
 * @param public_key The public key of the node that we wish to query. This key
 *   must be at least `TOX_DHT_NODE_PUBLIC_KEY_SIZE` bytes in length.
 * @param ip A NUL-terminated C string representing the IP address of the node
 *   we wish to query.
 * @param port The port of the node we wish to query.
 * @param target_public_key The public key for which we want to find close
 *   nodes.
 *
 * @return true on success.
 */
bool tox_dht_send_nodes_request(const Tox *_Nonnull tox, const uint8_t *_Nonnull public_key, const char *_Nonnull ip, uint16_t port,
                                const uint8_t *_Nonnull target_public_key, Tox_Err_Dht_Send_Nodes_Request *_Nullable error);

/**
 * This function returns the number of DHT nodes in the closelist.
 *
 * @return number
 */
uint16_t tox_dht_get_num_closelist(const Tox *_Nonnull tox);

/**
 * This function returns the number of DHT nodes in the closelist
 * that are capable of storing announce data (introduced in version 0.2.18).
 *
 * @return number
 */
uint16_t tox_dht_get_num_closelist_announce_capable(const Tox *_Nonnull tox);

/*******************************************************************************
 *
 * :: Network profiler
 *
 ******************************************************************************/


/**
 * Represents all of the network packet identifiers that Toxcore uses.
 *
 * Notes:
 * - Some packet ID's have different purposes depending on the
 * packet type. These ID's are given numeral names.
 *
 * - Queries for invalid packet ID's return undefined results. For example,
 *   querying a TCP-exclusive packet ID for UDP, or querying an ID that
 *   doesn't exist in this enum.
 */
typedef enum Tox_Netprof_Packet_Id {
    /**
     * Ping request packet (UDP).
     * Routing request (TCP).
     */
    TOX_NETPROF_PACKET_ID_ZERO                 = 0x00,

    /**
     * Ping response packet (UDP).
     * Routing response (TCP).
     */
    TOX_NETPROF_PACKET_ID_ONE                  = 0x01,

    /**
     * Nodes request packet (UDP).
     * Connection notification (TCP).
     */
    TOX_NETPROF_PACKET_ID_TWO                  = 0x02,

    /**
     * TCP disconnect notification.
     */
    TOX_NETPROF_PACKET_ID_TCP_DISCONNECT       = 0x03,

    /**
     * Nodes response packet (UDP).
     * Ping packet (TCP).
     */
    TOX_NETPROF_PACKET_ID_FOUR                 = 0x04,

    /**
     * TCP pong packet.
     */
    TOX_NETPROF_PACKET_ID_TCP_PONG             = 0x05,

    /**
     * TCP out-of-band send packet.
     */
    TOX_NETPROF_PACKET_ID_TCP_OOB_SEND         = 0x06,

    /**
     * TCP out-of-band receive packet.
     */
    TOX_NETPROF_PACKET_ID_TCP_OOB_RECV         = 0x07,

    /**
     * TCP onion request packet.
     */
    TOX_NETPROF_PACKET_ID_TCP_ONION_REQUEST    = 0x08,

    /**
     * TCP onion response packet.
     */
    TOX_NETPROF_PACKET_ID_TCP_ONION_RESPONSE   = 0x09,

    /**
     * TCP data packet.
     */
    TOX_NETPROF_PACKET_ID_TCP_DATA             = 0x10,

    /**
     * Cookie request packet.
     */
    TOX_NETPROF_PACKET_ID_COOKIE_REQUEST       = 0x18,

    /**
     * Cookie response packet.
     */
    TOX_NETPROF_PACKET_ID_COOKIE_RESPONSE      = 0x19,

    /**
     * Crypto handshake packet.
     */
    TOX_NETPROF_PACKET_ID_CRYPTO_HS            = 0x1a,

    /**
     * Crypto data packet.
     */
    TOX_NETPROF_PACKET_ID_CRYPTO_DATA          = 0x1b,

    /**
     * Encrypted data packet.
     */
    TOX_NETPROF_PACKET_ID_CRYPTO               = 0x20,

    /**
     * LAN discovery packet.
     */
    TOX_NETPROF_PACKET_ID_LAN_DISCOVERY        = 0x21,

    /**
     * DHT groupchat packets.
     */
    TOX_NETPROF_PACKET_ID_GC_HANDSHAKE         = 0x5a,
    TOX_NETPROF_PACKET_ID_GC_LOSSLESS          = 0x5b,
    TOX_NETPROF_PACKET_ID_GC_LOSSY             = 0x5c,

    /**
     * Onion send packets.
     */
    TOX_NETPROF_PACKET_ID_ONION_SEND_INITIAL   = 0x80,
    TOX_NETPROF_PACKET_ID_ONION_SEND_1         = 0x81,
    TOX_NETPROF_PACKET_ID_ONION_SEND_2         = 0x82,

    /**
     * DHT announce request packet (deprecated).
     */
    TOX_NETPROF_PACKET_ID_ANNOUNCE_REQUEST_OLD = 0x83,

    /**
     * DHT announce response packet (deprecated).
     */
    TOX_NETPROF_PACKET_ID_ANNOUNCE_RESPONSE_OLD = 0x84,

    /**
     * Onion data request packet.
     */
    TOX_NETPROF_PACKET_ID_ONION_DATA_REQUEST   = 0x85,

    /**
     * Onion data response packet.
     */
    TOX_NETPROF_PACKET_ID_ONION_DATA_RESPONSE  = 0x86,

    /**
     * DHT announce request packet.
     */
    TOX_NETPROF_PACKET_ID_ANNOUNCE_REQUEST     = 0x87,

    /**
     * DHT announce response packet.
     */
    TOX_NETPROF_PACKET_ID_ANNOUNCE_RESPONSE    = 0x88,

    /**
     * Onion receive packets.
     */
    TOX_NETPROF_PACKET_ID_ONION_RECV_3         = 0x8c,
    TOX_NETPROF_PACKET_ID_ONION_RECV_2         = 0x8d,
    TOX_NETPROF_PACKET_ID_ONION_RECV_1         = 0x8e,

    TOX_NETPROF_PACKET_ID_FORWARD_REQUEST      = 0x90,
    TOX_NETPROF_PACKET_ID_FORWARDING           = 0x91,
    TOX_NETPROF_PACKET_ID_FORWARD_REPLY        = 0x92,

    TOX_NETPROF_PACKET_ID_DATA_SEARCH_REQUEST     = 0x93,
    TOX_NETPROF_PACKET_ID_DATA_SEARCH_RESPONSE    = 0x94,
    TOX_NETPROF_PACKET_ID_DATA_RETRIEVE_REQUEST   = 0x95,
    TOX_NETPROF_PACKET_ID_DATA_RETRIEVE_RESPONSE  = 0x96,
    TOX_NETPROF_PACKET_ID_STORE_ANNOUNCE_REQUEST  = 0x97,
    TOX_NETPROF_PACKET_ID_STORE_ANNOUNCE_RESPONSE = 0x98,

    /**
     * Bootstrap info packet.
     */
    TOX_NETPROF_PACKET_ID_BOOTSTRAP_INFO       = 0xf0,
} Tox_Netprof_Packet_Id;

const char *_Nonnull tox_netprof_packet_id_to_string(Tox_Netprof_Packet_Id value);

/**
 * Specifies the packet type for a given query.
 */
typedef enum Tox_Netprof_Packet_Type {
    /**
     * TCP client packets.
     */
    TOX_NETPROF_PACKET_TYPE_TCP_CLIENT,

    /**
     * TCP server packets.
     */
    TOX_NETPROF_PACKET_TYPE_TCP_SERVER,

    /**
     * Combined TCP server and TCP client packets.
     */
    TOX_NETPROF_PACKET_TYPE_TCP,

    /**
     * UDP packets.
     */
    TOX_NETPROF_PACKET_TYPE_UDP,
} Tox_Netprof_Packet_Type;

const char *_Nonnull tox_netprof_packet_type_to_string(Tox_Netprof_Packet_Type value);

/**
 * Specifies the packet direction for a given query.
 */
typedef enum Tox_Netprof_Direction {
    /**
     * Outbound packets.
     */
    TOX_NETPROF_DIRECTION_SENT,

    /**
     * Inbound packets.
     */
    TOX_NETPROF_DIRECTION_RECV,
} Tox_Netprof_Direction;

const char *_Nonnull tox_netprof_direction_to_string(Tox_Netprof_Direction value);

/**
 * Return the number of packets sent or received for a specific packet ID.
 *
 * @param type The types of packets being queried.
 * @param id The packet ID being queried.
 * @param direction The packet direction.
 */
uint64_t tox_netprof_get_packet_id_count(const Tox *_Nonnull tox, Tox_Netprof_Packet_Type type, uint8_t id,
        Tox_Netprof_Direction direction);

/**
 * Return the total number of packets sent or received.
 *
 * @param type The types of packets being queried.
 * @param direction The packet direction.
 */
uint64_t tox_netprof_get_packet_total_count(const Tox *_Nonnull tox, Tox_Netprof_Packet_Type type,
        Tox_Netprof_Direction direction);

/**
 * Return the number of bytes sent or received for a specific packet ID.
 *
 * @param type The types of packets being queried.
 * @param id The packet ID being queried.
 * @param direction The packet direction.
 */
uint64_t tox_netprof_get_packet_id_bytes(const Tox *_Nonnull tox, Tox_Netprof_Packet_Type type, uint8_t id,
        Tox_Netprof_Direction direction);

/**
 * Return the total number of bytes sent or received.
 *
 * @param type The types of packets being queried.
 * @param direction The packet direction.
 */
uint64_t tox_netprof_get_packet_total_bytes(const Tox *_Nonnull tox, Tox_Netprof_Packet_Type type,
        Tox_Netprof_Direction direction);


/*******************************************************************************
 *
 * :: DHT groupchat queries.
 *
 ******************************************************************************/

/**
 * Maximum size of a peer IP address string.
 */
#define TOX_GROUP_PEER_IP_STRING_MAX_LENGTH 96

uint32_t tox_group_peer_ip_string_max_length(void);

/**
 * Return the length of the peer's IP address in string form. If the group
 * number or ID is invalid, the return value is unspecified.
 *
 * @param group_number The group number of the group we wish to query.
 * @param peer_id The ID of the peer whose IP address length we want to
 *   retrieve.
 */
size_t tox_group_peer_get_ip_address_size(const Tox *_Nonnull tox, uint32_t group_number, uint32_t peer_id,
        Tox_Err_Group_Peer_Query *_Nullable error);
/**
 * Write the IP address associated with the designated peer_id for the
 * designated group number to ip_addr.
 *
 * If the peer is forcing TCP connections a placeholder value will be written
 * instead, indicating that their real IP address is unknown to us.
 *
 * If `peer_id` designates ourself, it will write either our own IP address or a
 * placeholder value, depending on whether or not we're forcing TCP connections.
 *
 * Call tox_group_peer_get_ip_address_size to determine the allocation size for
 * the `ip_addr` parameter.
 *
 * @param group_number The group number of the group we wish to query.
 * @param peer_id The ID of the peer whose public key we wish to retrieve.
 * @param ip_addr A valid memory region large enough to store the IP address
 *   string. If this parameter is NULL, this function call has no effect.
 *
 * @return true on success.
 */
bool tox_group_peer_get_ip_address(const Tox *_Nonnull tox, uint32_t group_number, uint32_t peer_id, uint8_t *_Nonnull ip_addr,
                                   Tox_Err_Group_Peer_Query *_Nullable error);

/*******************************************************************************
 *
 * :: Group chat keys and peer endpoints.
 *
 ******************************************************************************/

/**
 * The size of a group secret key in bytes.
 */
#define TOX_GROUP_SECRET_KEY_SIZE        32

uint32_t tox_group_secret_key_size(void);

/**
 * Write our secret key in a group to a byte array.
 *
 * Our public key in the group, as tox_group_self_get_public_key gives it, is
 * made from this key. A client that keeps it can join the group again with
 * tox_group_join_as as the same member, so we keep our role in it. Keep it as
 * safe as the Tox secret key.
 *
 * @param group_number The group number of the group.
 * @param secret_key A memory region of at least TOX_GROUP_SECRET_KEY_SIZE
 *   bytes.
 *
 * @return true on success.
 */
bool tox_group_self_get_secret_key(const Tox *_Nonnull tox, uint32_t group_number, uint8_t secret_key[_Nonnull TOX_GROUP_SECRET_KEY_SIZE],
                                   Tox_Err_Group_Self_Query *_Nullable error);

typedef enum Tox_Err_Group_Get_Chat_Secret_Key {
    /**
     * The function returned successfully.
     */
    TOX_ERR_GROUP_GET_CHAT_SECRET_KEY_OK,

    /**
     * The group number passed did not designate a valid group.
     */
    TOX_ERR_GROUP_GET_CHAT_SECRET_KEY_GROUP_NOT_FOUND,

    /**
     * We don't have the group's secret key: only its founder does.
     */
    TOX_ERR_GROUP_GET_CHAT_SECRET_KEY_NOT_FOUNDER,
} Tox_Err_Group_Get_Chat_Secret_Key;

/**
 * Write the group's secret key to a byte array.
 *
 * The Chat ID is made from this key, and only the group's founder has it. A
 * founder who passes it to tox_group_join_as can change the group's settings
 * again once a peer has sent them. Keep it as safe as the Tox secret key.
 *
 * @param group_number The group number of the group.
 * @param secret_key A memory region of at least TOX_GROUP_SECRET_KEY_SIZE
 *   bytes.
 *
 * @return true on success.
 */
bool tox_group_get_chat_secret_key(const Tox *_Nonnull tox, uint32_t group_number, uint8_t secret_key[_Nonnull TOX_GROUP_SECRET_KEY_SIZE],
                                   Tox_Err_Group_Get_Chat_Secret_Key *_Nullable error);

typedef enum Tox_Err_Group_Join_As {
    /**
     * The function returned successfully.
     */
    TOX_ERR_GROUP_JOIN_AS_OK,

    /**
     * The group instance failed to initialize.
     */
    TOX_ERR_GROUP_JOIN_AS_INIT,

    /**
     * The group is already in this Tox instance.
     */
    TOX_ERR_GROUP_JOIN_AS_DUPLICATE,

    /**
     * name is NULL or name_length is zero.
     */
    TOX_ERR_GROUP_JOIN_AS_EMPTY,

    /**
     * name exceeds TOX_MAX_NAME_LENGTH.
     */
    TOX_ERR_GROUP_JOIN_AS_TOO_LONG,

    /**
     * Failed to set password. This usually occurs if the password exceeds
     * TOX_GROUP_MAX_PASSWORD_SIZE.
     */
    TOX_ERR_GROUP_JOIN_AS_PASSWORD,

    /**
     * chat_secret_key isn't the secret key of the group with chat_id.
     */
    TOX_ERR_GROUP_JOIN_AS_BAD_CHAT_SECRET_KEY,

    /**
     * There was a core error when initiating the group.
     */
    TOX_ERR_GROUP_JOIN_AS_CORE,
} Tox_Err_Group_Join_As;

/**
 * Join a group as the member that a secret key makes.
 *
 * Like tox_group_join, but our key in the group is made from `self_secret_key`.
 * With the key tox_group_self_get_secret_key gave, e.g. before a restart, peers
 * know us as before: we keep our role, and a moderator stays a moderator. Pass
 * the group's secret key from tox_group_get_chat_secret_key to be its founder
 * again. Any 32 random bytes make a new member. Two Tox instances must not be in
 * a group with the same key at the same time.
 *
 * A public group is found through the DHT. A private group is never announced,
 * so it only finds peers at the endpoints the client passes to
 * tox_group_add_peer_endpoint. Anyone who has an endpoint of a member, and the
 * password if there is one, can join a private group this way, as with an invite.
 *
 * The group has no settings until a peer sends them, so it isn't in the group
 * list until then. That includes a founder: with no other member online, the
 * group stays without settings until one comes back.
 *
 * @param chat_id The Chat ID of the group.
 * @param self_secret_key Our secret key in the group, e.g. as
 *   tox_group_self_get_secret_key gave it.
 * @param chat_secret_key The group's secret key, as
 *   tox_group_get_chat_secret_key gave it, or NULL if we're not its founder.
 * @param privacy_state The group's privacy state, as
 *   tox_group_get_privacy_state gave it.
 * @param name The name of the peer joining the group.
 * @param name_length The length of the peer's name. This must be greater than
 *   zero and no larger than TOX_MAX_NAME_LENGTH.
 * @param password The password required to join the group. Set to NULL if no
 *   password is required.
 * @param password_length The length of the password. If length is equal to
 *   zero, the password parameter is ignored. length must be no larger than
 *   TOX_GROUP_MAX_PASSWORD_SIZE.
 *
 * @return group_number on success, UINT32_MAX on failure.
 */
uint32_t tox_group_join_as(Tox *_Nonnull tox, const uint8_t chat_id[_Nonnull TOX_GROUP_CHAT_ID_SIZE],
                           const uint8_t self_secret_key[_Nonnull TOX_GROUP_SECRET_KEY_SIZE],
                           const uint8_t chat_secret_key[_Nullable TOX_GROUP_SECRET_KEY_SIZE], Tox_Group_Privacy_State privacy_state,
                           const uint8_t name[_Nullable], size_t name_length, const uint8_t password[_Nullable], size_t password_length,
                           Tox_Err_Group_Join_As *_Nullable error);

/**
 * Return the number of peer endpoints a group keeps.
 *
 * A peer endpoint says where a peer can be reached. A group keeps the endpoints
 * of peers it was connected to, so it can reach them again when it has no
 * peers. Private groups need them, because they're never announced.
 *
 * @param group_number The group number of the group.
 */
uint32_t tox_group_get_peer_endpoint_count(const Tox *_Nonnull tox, uint32_t group_number,
        Tox_Err_Group_State_Query *_Nullable error);

typedef enum Tox_Err_Group_Get_Peer_Endpoint {
    /**
     * The function returned successfully.
     */
    TOX_ERR_GROUP_GET_PEER_ENDPOINT_OK,

    /**
     * The group number passed did not designate a valid group.
     */
    TOX_ERR_GROUP_GET_PEER_ENDPOINT_GROUP_NOT_FOUND,

    /**
     * The group has no peer endpoint with this index.
     */
    TOX_ERR_GROUP_GET_PEER_ENDPOINT_NOT_FOUND,
} Tox_Err_Group_Get_Peer_Endpoint;

/**
 * Write a peer endpoint a group keeps.
 *
 * An endpoint has the peer's public key, and an IP address and port, a TCP
 * relay, or both. A missing IP address or relay has an empty string as its IP
 * address.
 *
 * @param group_number The group number of the group.
 * @param index The index of the endpoint, below tox_group_get_peer_endpoint_count.
 * @param public_key A memory region of at least TOX_GROUP_PEER_PUBLIC_KEY_SIZE
 *   bytes for the peer's public key.
 * @param ip A memory region of at least TOX_GROUP_PEER_IP_STRING_MAX_LENGTH
 *   bytes for the peer's IP address, as a NUL-terminated string.
 * @param port The peer's port.
 * @param relay_public_key A memory region of at least TOX_PUBLIC_KEY_SIZE bytes
 *   for the public key of the TCP relay.
 * @param relay_ip A memory region of at least
 *   TOX_GROUP_PEER_IP_STRING_MAX_LENGTH bytes for the TCP relay's IP address, as
 *   a NUL-terminated string.
 * @param relay_port The TCP relay's port.
 *
 * @return true on success.
 */
bool tox_group_get_peer_endpoint(const Tox *_Nonnull tox, uint32_t group_number, uint32_t index,
                                 uint8_t public_key[_Nonnull TOX_GROUP_PEER_PUBLIC_KEY_SIZE], char ip[_Nonnull TOX_GROUP_PEER_IP_STRING_MAX_LENGTH],
                                 uint16_t *_Nonnull port, uint8_t relay_public_key[_Nonnull TOX_PUBLIC_KEY_SIZE],
                                 char relay_ip[_Nonnull TOX_GROUP_PEER_IP_STRING_MAX_LENGTH], uint16_t *_Nonnull relay_port,
                                 Tox_Err_Group_Get_Peer_Endpoint *_Nullable error);

typedef enum Tox_Err_Group_Add_Peer_Endpoint {
    /**
     * The function returned successfully.
     */
    TOX_ERR_GROUP_ADD_PEER_ENDPOINT_OK,

    /**
     * The group number passed did not designate a valid group.
     */
    TOX_ERR_GROUP_ADD_PEER_ENDPOINT_GROUP_NOT_FOUND,

    /**
     * The endpoint has neither an IP address nor a TCP relay, or one of its IP
     * addresses isn't an IP address.
     */
    TOX_ERR_GROUP_ADD_PEER_ENDPOINT_BAD_ENDPOINT,

    /**
     * Every peer endpoint the group keeps is of a peer it's connected to.
     */
    TOX_ERR_GROUP_ADD_PEER_ENDPOINT_FULL,
} Tox_Err_Group_Add_Peer_Endpoint;

/**
 * Give a group a peer endpoint to connect to, e.g. one that
 * tox_group_get_peer_endpoint gave before a restart.
 *
 * The group connects to the endpoints it keeps when it has no peers.
 *
 * @param group_number The group number of the group.
 * @param public_key The peer's public key.
 * @param ip The peer's IP address, or NULL if there is none.
 * @param port The peer's port.
 * @param relay_public_key The public key of the peer's TCP relay, or NULL if
 *   there is none.
 * @param relay_ip The TCP relay's IP address. Ignored if relay_public_key is
 *   NULL.
 * @param relay_port The TCP relay's port.
 *
 * @return true on success.
 */
bool tox_group_add_peer_endpoint(Tox *_Nonnull tox, uint32_t group_number, const uint8_t public_key[_Nonnull TOX_GROUP_PEER_PUBLIC_KEY_SIZE],
                                 const char *_Nullable ip, uint16_t port, const uint8_t relay_public_key[_Nullable TOX_PUBLIC_KEY_SIZE],
                                 const char *_Nullable relay_ip, uint16_t relay_port, Tox_Err_Group_Add_Peer_Endpoint *_Nullable error);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* C_TOXCORE_TOXCORE_TOX_PRIVATE_H */
