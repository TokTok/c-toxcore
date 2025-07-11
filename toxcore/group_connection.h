/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2020 The TokTok team.
 * Copyright © 2015 Tox project.
 */

/**
 * An implementation of massive text only group chats.
 */

#ifndef C_TOXCORE_TOXCORE_GROUP_CONNECTION_H
#define C_TOXCORE_TOXCORE_GROUP_CONNECTION_H

#include "DHT.h"
#include "TCP_connection.h"
#include "attributes.h"
#include "crypto_core.h"
#include "group_common.h"
#include "logger.h"
#include "mem.h"
#include "mono_time.h"
#include "network.h"

/* Max number of TCP relays we share with a peer on handshake */
#define GCC_MAX_TCP_SHARED_RELAYS 3

/** Marks a peer for deletion. If gconn is null or already marked for deletion this function has no effect. */
void gcc_mark_for_deletion(non_null() GC_Connection *gconn, non_null() TCP_Connections *tcp_conn, Group_Exit_Type type,
                           nullable() const uint8_t *part_message, uint16_t length);
/** @brief Decides if message need to be put in recv_array or immediately handled.
 *
 * Return 3 if message is in correct sequence and is a fragment packet.
 * Return 2 if message is in correct sequence and may be handled immediately.
 * Return 1 if packet is out of sequence and added to recv_array.
 * Return 0 if message is a duplicate.
 * Return -1 on failure
 */
int gcc_handle_received_message(non_null() const Logger *log, non_null() const Memory *mem, non_null() const Mono_Time *mono_time, non_null() GC_Connection *gconn,
                                nullable() const uint8_t *data, uint16_t length, uint8_t packet_type, uint64_t message_id,
                                bool direct_conn);
/** @brief Handles a packet fragment.
 *
 * If the fragment is incomplete, it gets stored in the recv
 * array. Otherwise the segment is re-assembled into a complete
 * payload and processed.
 *
 * Return 1 if fragment is successfully handled and is not the end of the sequence.
 * Return 0 if fragment is the end of a sequence and successfully handled.
 * Return -1 on failure.
 */
int gcc_handle_packet_fragment(non_null() const GC_Session *c, non_null() GC_Chat *chat, uint32_t peer_number, non_null() GC_Connection *gconn,
                               nullable() const uint8_t *chunk, uint16_t length, uint8_t packet_type, uint64_t message_id,
                               nullable() void *userdata);
/** @brief Return array index for message_id */
uint16_t gcc_get_array_index(uint64_t message_id);

/** @brief Removes send_array item with message_id.
 *
 * Return true on success.
 */
bool gcc_handle_ack(non_null() const Logger *log, non_null() const Memory *mem, non_null() GC_Connection *gconn, uint64_t message_id);

/** @brief Sets the send_message_id and send_array_start for `gconn` to `id`.
 *
 * This should only be used to initialize a new lossless connection.
 */
void gcc_set_send_message_id(non_null() GC_Connection *gconn, uint64_t id);

/** @brief Sets the received_message_id for `gconn` to `id`. */
void gcc_set_recv_message_id(non_null() GC_Connection *gconn, uint64_t id);

/**
 * @brief Returns true if the ip_port is set for gconn.
 */
bool gcc_ip_port_is_set(non_null() const GC_Connection *gconn);

/**
 * @brief Sets the ip_port for gconn to ipp.
 *
 * If ipp is not set this function has no effect.
 */
void gcc_set_ip_port(non_null() GC_Connection *gconn, nullable() const IP_Port *ipp);
/** @brief Copies a random TCP relay node from gconn to tcp_node.
 *
 * Return true on success.
 */
bool gcc_copy_tcp_relay(non_null() const Random *rng, non_null() Node_format *tcp_node, non_null() const GC_Connection *gconn);

/** @brief Saves tcp_node to gconn's list of connected tcp relays.
 *
 * If relays list is full a random node is overwritten with the new node.
 *
 * Return 0 on success.
 * Return -1 on failure.
 * Return -2 if node is already in list.
 */
int gcc_save_tcp_relay(non_null() const Random *rng, non_null() GC_Connection *gconn, non_null() const Node_format *tcp_node);

/** @brief Checks for and handles messages that are in proper sequence in gconn's recv_array.
 * This should always be called after a new packet is successfully handled.
 */
void gcc_check_recv_array(non_null() const GC_Session *c, non_null() GC_Chat *chat, non_null() GC_Connection *gconn, uint32_t peer_number,
                          nullable() void *userdata);
/** @brief Attempts to re-send lossless packets that have not yet received an ack. */
void gcc_resend_packets(non_null() const GC_Chat *chat, non_null() GC_Connection *gconn);

/**
 * Uses public encryption key `sender_pk` and the shared secret key associated with `gconn`
 * to generate a shared 32-byte encryption key that can be used by the owners of both keys for symmetric
 * encryption and decryption.
 *
 * Puts the result in the shared session key buffer for `gconn`, which must have room for
 * CRYPTO_SHARED_KEY_SIZE bytes. This resulting shared key should be treated as a secret key.
 */
void gcc_make_session_shared_key(non_null() GC_Connection *gconn, non_null() const uint8_t *sender_pk);

/** @brief Return true if we have a direct connection with `gconn`. */
bool gcc_conn_is_direct(non_null() const Mono_Time *mono_time, non_null() const GC_Connection *gconn);

/** @brief Return true if we can try a direct connection with `gconn` again. */
bool gcc_conn_should_try_direct(non_null() const Mono_Time *mono_time, non_null() const GC_Connection *gconn);

/** @brief Return true if a direct UDP connection is possible with `gconn`. */
bool gcc_direct_conn_is_possible(non_null() const GC_Chat *chat, non_null() const GC_Connection *gconn);

/** @brief Sends a packet to the peer associated with gconn.
 *
 * This is a lower level function that does not encrypt or wrap the packet.
 *
 * Return true on success.
 */
bool gcc_send_packet(non_null() const GC_Chat *chat, non_null() GC_Connection *gconn, non_null() const uint8_t *packet, uint16_t length);

/** @brief Sends a lossless packet to `gconn` comprised of `data` of size `length`.
 *
 * This function will add the packet to the lossless send array, encrypt/wrap it using the
 * shared key associated with `gconn`, and try to send it over the wire.
 *
 * Return 0 if the packet was successfully encrypted and added to the send array.
 * Return -1 if the packet couldn't be added to the send array.
 * Return -2 if the packet failed to be wrapped or encrypted.
 */
int gcc_send_lossless_packet(non_null() const GC_Chat *chat, non_null() GC_Connection *gconn, nullable() const uint8_t *data, uint16_t length,
                             uint8_t packet_type);
/** @brief Splits a lossless packet up into fragments, wraps each fragment in a GP_FRAGMENT
 * header, encrypts them, and send them in succession.
 *
 * This function will first try to add each packet fragment to the send array as an atomic
 * unit. If any chunk fails to be added the process will be reversed and an error will be
 * returned. Otherwise it will then try to send all the fragments in succession.
 *
 * Return true if all fragments are successfully added to the send array.
 */
bool gcc_send_lossless_packet_fragments(non_null() const GC_Chat *chat, non_null() GC_Connection *gconn, non_null() const uint8_t *data, uint16_t length, uint8_t packet_type);

/** @brief Encrypts `data` of `length` bytes, designated by `message_id`, using the shared key
 * associated with `gconn` and sends lossless packet over the wire.
 *
 * This function does not add the packet to the send array.
 *
 * Return 0 on success.
 * Return -1 if packet wrapping and encryption fails.
 * Return -2 if the packet fails to send.
 */
int gcc_encrypt_and_send_lossless_packet(non_null() const GC_Chat *chat, non_null() GC_Connection *gconn, nullable() const uint8_t *data,
        uint16_t length, uint64_t message_id, uint8_t packet_type);
/** @brief Called when a peer leaves the group. */
void gcc_peer_cleanup(non_null() const Memory *mem, non_null() GC_Connection *gconn);

/** @brief Called on group exit. */
void gcc_cleanup(non_null() const GC_Chat *chat);

#endif /* C_TOXCORE_TOXCORE_GROUP_CONNECTION_H */
