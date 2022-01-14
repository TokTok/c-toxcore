/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2020 The TokTok team.
 * Copyright © 2013 Tox project.
 */

#ifndef C_TOXCORE_TOXCORE_TOX_PRIVATE_H
#define C_TOXCORE_TOXCORE_TOX_PRIVATE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Set the callback for the `friend_lossy_packet` event for a specific packet ID.
 * Pass NULL to unset.
 *
 * allowed packet ID range:
 * from `PACKET_ID_RANGE_LOSSY_START` to `PACKET_ID_RANGE_LOSSY_END` (both inclusive)
 */
void tox_callback_friend_lossy_packet_per_pktid(Tox *tox, tox_friend_lossy_packet_cb *callback, uint8_t pktid);

/**
 * Set the callback for the `friend_lossless_packet` event for a specific packet ID.
 * Pass NULL to unset.
 *
 * allowed packet ID range:
 * from `PACKET_ID_RANGE_LOSSLESS_CUSTOM_START` to `PACKET_ID_RANGE_LOSSLESS_CUSTOM_END` (both inclusive)
 * and
 * `PACKET_ID_MSI`
 */
void tox_callback_friend_lossless_packet_per_pktid(Tox *tox, tox_friend_lossless_packet_cb *callback, uint8_t pktid);

void tox_set_av_object(Tox *tox, void *object);
void *tox_get_av_object(const Tox *tox);


/*******************************************************************************
 *
 * :: Network profiler
 *
 ******************************************************************************/



/**
 * Represents all of the network packet identifiers that Toxcore uses.
 *
 * Note: Some packet ID's have different purposes depending on the
 * packet type. These ID's are given numeral names.
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
     * Get nodes request packet (UDP).
     * Connection notification (TCP).
     */
    TOX_NETPROF_PACKET_ID_TWO                  = 0x02,

    /**
     * TCP disconnect notification.
     */
    TOX_NETPROF_PACKET_ID_TCP_DISCONNECT       = 0x03,

    /**
     * Send nodes response packet (UDP).
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
     * Onion send packets.
     */
    TOX_NETPROF_PACKET_ID_ONION_SEND_INITIAL   = 0x80,
    TOX_NETPROF_PACKET_ID_ONION_SEND_1         = 0x81,
    TOX_NETPROF_PACKET_ID_ONION_SEND_2         = 0x82,

    /**
     * DHT announce request packet.
     */
    TOX_NETPROF_PACKET_ID_ANNOUNCE_REQUEST     = 0x83,

    /**
     * DHT announce response packet.
     */
    TOX_NETPROF_PACKET_ID_ANNOUNCE_RESPONSE    = 0x84,

    /**
     * Onion data request packet.
     */
    TOX_NETPROF_PACKET_ID_ONION_DATA_REQUEST   = 0x85,

    /**
     * Onion data response packet.
     */
    TOX_NETPROF_PACKET_ID_ONION_DATA_RESPONSE  = 0x86,

    /**
     * Onion receive packets.
     */
    TOX_NETPROF_PACKET_ID_ONION_RECV_3         = 0x8c,
    TOX_NETPROF_PACKET_ID_ONION_RECV_2         = 0x8d,
    TOX_NETPROF_PACKET_ID_ONION_RECV_1         = 0x8e,

    /**
     * Bootstrap info packet.
     */
    TOX_NETPROF_PACKET_ID_BOOTSTRAP_INFO       = 0xf0,
} Tox_Netprof_Packet_Id;

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

/**
 * Specifies the packet direction for a given query.
 */
typedef enum Tox_Netprof_Direction {
    /**
     * Outbound packets.
     */
    TOX_NET_PROFILE_DIRECTION_SENT,

    /**
     * Inbound packets.
     */
    TOX_NET_PROFILE_DIRECTION_RECV,
} Tox_Netprof_Direction;

/**
 * Return the number of packets sent or received for a specific packet ID.
 *
 * @param type The types of packets being queried.
 * @param id The packet ID being queried.
 * @param direction The packet direction.
 */
uint64_t tox_netprof_get_packet_id_count(const Tox *tox, Tox_Netprof_Packet_Type type,
        Tox_Netprof_Packet_Id id, Tox_Netprof_Direction direction);

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
uint64_t tox_netprof_get_packet_id_bytes(const Tox *tox, Tox_Netprof_Packet_Type type,
        Tox_Netprof_Packet_Id id, Tox_Netprof_Direction direction);
/**
 * Return the total number of bytes sent or received.
 *
 * @param type The types of packets being queried.
 * @param direction The packet direction.
 */
uint64_t tox_netprof_get_packet_total_bytes(const Tox *tox, Tox_Netprof_Packet_Type type,
        Tox_Netprof_Direction direction);


#ifdef __cplusplus
}
#endif

//!TOKSTYLE-
typedef Tox_Netprof_Packet_Id   TOX_NETPROF_PACKET_ID;
typedef Tox_Netprof_Direction   TOX_NETPROF_PAKCKET_DIRECTION;
typedef Tox_Netprof_Packet_Type TOX_NETPROF_PACKET_TYPE;
//!TOKSTYLE+

#endif // C_TOXCORE_TOXCORE_TOX_PRIVATE_H

