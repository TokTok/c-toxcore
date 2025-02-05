/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2025 The TokTok team.
 * Copyright © 2013 Tox project.
 */

#ifndef C_TOXCORE_TOXCORE_TOX_PRIVATE_H
#define C_TOXCORE_TOXCORE_TOX_PRIVATE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "tox.h"
#include "tox_options.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef uint64_t tox_mono_time_cb(void *user_data);

typedef struct Tox_System {
    tox_mono_time_cb *mono_time_callback;
    void *mono_time_user_data;
    const struct Random *rng;
    const struct Network *ns;
    const struct Memory *mem;
} Tox_System;

Tox_System tox_default_system(void);

const Tox_System *tox_get_system(Tox *tox);

typedef struct Tox_Options_Testing {
    const struct Tox_System *operating_system;
} Tox_Options_Testing;

typedef enum Tox_Err_New_Testing {
    TOX_ERR_NEW_TESTING_OK,
    TOX_ERR_NEW_TESTING_NULL,
} Tox_Err_New_Testing;

Tox *tox_new_testing(const Tox_Options *options, Tox_Err_New *error, const Tox_Options_Testing *testing, Tox_Err_New_Testing *testing_error);

void tox_lock(const Tox *tox);
void tox_unlock(const Tox *tox);

/**
 * Set the callback for the `friend_lossy_packet` event for a specific packet
 * ID. Pass NULL to unset.
 *
 * allowed packet ID range:
 * from `PACKET_ID_RANGE_LOSSY_START` to `PACKET_ID_RANGE_LOSSY_END` (both
 * inclusive)
 */
void tox_callback_friend_lossy_packet_per_pktid(Tox *tox, tox_friend_lossy_packet_cb *callback, uint8_t pktid);

/**
 * Set the callback for the `friend_lossless_packet` event for a specific packet
 * ID. Pass NULL to unset.
 *
 * allowed packet ID range:
 * from `PACKET_ID_RANGE_LOSSLESS_CUSTOM_START` to
 * `PACKET_ID_RANGE_LOSSLESS_CUSTOM_END` (both inclusive) and `PACKET_ID_MSI`
 */
void tox_callback_friend_lossless_packet_per_pktid(Tox *tox, tox_friend_lossless_packet_cb *callback, uint8_t pktid);

void tox_set_av_object(Tox *tox, void *object);
void *tox_get_av_object(const Tox *tox);

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
    Tox *tox, const uint8_t *public_key, const char *ip, uint32_t ip_length,
    uint16_t port, void *user_data);

/**
 * Set the callback for the `dht_nodes_response` event. Pass NULL to unset.
 *
 * This event is triggered when a nodes response is received from a DHT peer.
 */
void tox_callback_dht_nodes_response(Tox *tox, tox_dht_nodes_response_cb *callback);

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
bool tox_dht_send_nodes_request(const Tox *tox, const uint8_t *public_key, const char *ip, uint16_t port,
                                const uint8_t *target_public_key, Tox_Err_Dht_Send_Nodes_Request *error);

/**
 * This function returns the number of DHT nodes in the closelist.
 *
 * @return number
 */
uint16_t tox_dht_get_num_closelist(const Tox *tox);

/**
 * This function returns the number of DHT nodes in the closelist
 * that are capable of storing announce data (introduced in version 0.2.18).
 *
 * @return number
 */
uint16_t tox_dht_get_num_closelist_announce_capable(const Tox *tox);

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

const char *tox_netprof_packet_id_to_string(Tox_Netprof_Packet_Id value);

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

const char *tox_netprof_packet_type_to_string(Tox_Netprof_Packet_Type value);

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

const char *tox_netprof_direction_to_string(Tox_Netprof_Direction value);

/**
 * Return the number of packets sent or received for a specific packet ID.
 *
 * @param type The types of packets being queried.
 * @param id The packet ID being queried.
 * @param direction The packet direction.
 */
uint64_t tox_netprof_get_packet_id_count(const Tox *tox, Tox_Netprof_Packet_Type type, uint8_t id,
        Tox_Netprof_Direction direction);

/**
 * Return the total number of packets sent or received.
 *
 * @param type The types of packets being queried.
 * @param direction The packet direction.
 */
uint64_t tox_netprof_get_packet_total_count(const Tox *tox, Tox_Netprof_Packet_Type type,
        Tox_Netprof_Direction direction);

/**
 * Return the number of bytes sent or received for a specific packet ID.
 *
 * @param type The types of packets being queried.
 * @param id The packet ID being queried.
 * @param direction The packet direction.
 */
uint64_t tox_netprof_get_packet_id_bytes(const Tox *tox, Tox_Netprof_Packet_Type type, uint8_t id,
        Tox_Netprof_Direction direction);

/**
 * Return the total number of bytes sent or received.
 *
 * @param type The types of packets being queried.
 * @param direction The packet direction.
 */
uint64_t tox_netprof_get_packet_total_bytes(const Tox *tox, Tox_Netprof_Packet_Type type,
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
size_t tox_group_peer_get_ip_address_size(const Tox *tox, uint32_t group_number, uint32_t peer_id,
        Tox_Err_Group_Peer_Query *error);
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
bool tox_group_peer_get_ip_address(const Tox *tox, uint32_t group_number, uint32_t peer_id, uint8_t *ip_addr,
                                   Tox_Err_Group_Peer_Query *error);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* C_TOXCORE_TOXCORE_TOX_PRIVATE_H */
