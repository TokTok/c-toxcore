/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2020 The TokTok team.
 * Copyright © 2015 Tox project.
 */

/**
 * An implementation of massive text only group chats.
 */

#ifndef GROUP_CONNECTION_H
#define GROUP_CONNECTION_H

#include "group_common.h"

/* Max number of TCP relays we share with a peer */
#define GCC_MAX_TCP_SHARED_RELAYS 3

/** Marks a peer for deletion. If gconn is null or already marked for deletion this function has no effect. */
void gcc_mark_for_deletion(GC_Connection *gconn, TCP_Connections *tcp_conn, Group_Exit_Type type,
                           const uint8_t *part_message, uint16_t length);

/** Adds data of length to gconn's send_array.
 *
 * Returns 0 on success and increments gconn's send_message_id.
 * Returns -1 on failure.
 */
int gcc_add_to_send_array(const Logger *logger, const Mono_Time *mono_time, GC_Connection *gconn, const uint8_t *data,
                          uint16_t length, uint8_t packet_type);

/** Decides if message need to be put in received_array or immediately handled.
 *
 * Return 2 if message is in correct sequence and may be handled immediately.
 * Return 1 if packet is out of sequence and added to received_array.
 * Return 0 if message is a duplicate.
 * Return -1 on failure
 */
int gcc_handle_received_message(const Logger *log, const Mono_Time *mono_time, GC_Connection *gconn,
                                const uint8_t *data, uint16_t length, uint8_t packet_type, uint64_t message_id,
                                bool direct_conn);

/** Return array index for message_id */
uint16_t gcc_get_array_index(uint64_t message_id);

/** Removes send_array item with message_id.
 *
 * Return 0 if success.
 * Return -1 on failure.
 */
int gcc_handle_ack(GC_Connection *gconn, uint64_t message_id);

/** Sets the send_message_id and send_array_start for `gconn` to `id`. This
 * should only be used to initialize a new lossless connection.
 */
void gcc_set_send_message_id(GC_Connection *gconn, uint64_t id);

/** Sets the received_message_id for `gconn` to `id`. */
void gcc_set_recv_message_id(GC_Connection *gconn, uint64_t id);

/**
 * Returns true if the ip_port is set for gconn.
 */
bool gcc_ip_port_is_set(const GC_Connection *gconn);

/**
 * Sets the ip_port for gconn to ipp. If ipp is not set this function has no effect.
 */
void gcc_set_ip_port(GC_Connection *gconn, const IP_Port *ipp);

/** Copies a random TCP relay node from gconn to tcp_node.
 *
 * Return 0 on success.
 * Return -1 on failure.
 */
int gcc_copy_tcp_relay(Node_format *tcp_node, const GC_Connection *gconn);

/** Saves tcp_node to gconn's list of connected tcp relays. If relays list is full a
 * random node is overwritten with the new node.
 *
 * Return 0 on success.
 * Return -1 on failure.
 * Return -2 if node is already in list.
 */
int gcc_save_tcp_relay(GC_Connection *gconn, const Node_format *tcp_node);

/** Checks for and handles messages that are in proper sequence in gconn's received_array.
 * This should always be called after a new packet is successfully handled.
 *
 * Return 0 on success.
 * Return -1 on failure.
 */
int gcc_check_received_array(const GC_Session *c, GC_Chat *chat, GC_Connection *gconn, uint32_t peer_number,
                             void *userdata);

/** Attempts to re-send lossless packets that have not yet received an ack. */
void gcc_resend_packets(const GC_Chat *chat, GC_Connection *gconn);

/** Uses public encryption key `sender_pk` and the shared secret key associated with `gconn`
 * to generate a shared 32-byte encryption key that can be used by the owners of both keys for symmetric
 * encryption and decryption.
 *
 * Puts the result in the shared session key buffer for `gconn`, which must have room for
 * CRYPTO_SHARED_KEY_SIZE bytes. This resulting shared key should be treated as a secret key.
 */
void gcc_make_session_shared_key(GC_Connection *gconn, const uint8_t *sender_pk);

/** Return true if we have a direct connection with `gconn`. */
bool gcc_conn_is_direct(const Mono_Time *mono_time, const GC_Connection *gconn);

/** Return true if a direct UDP connection is possible with `gconn`. */
bool gcc_direct_conn_is_possible(const GC_Chat *chat, const GC_Connection *gconn);

/** Sends a lossless packet to the peer associated with gconn.
 *
 * Return 0 on success.
 * Return -1 on failure.
 */
int gcc_send_packet(const GC_Chat *chat, const GC_Connection *gconn, const uint8_t *packet, uint16_t length);

/** Encrypts `data` of `length` bytes, designated by `message_id`, using the shared key associated with
 * `gconn` and sends lossless packet.
 *
 * Return 0 on success.
 * Return -1 on failure.
 */
int gcc_encrypt_and_send_lossless_packet(const GC_Chat *chat, const GC_Connection *gconn, const uint8_t *data,
        uint16_t length, uint64_t message_id, uint8_t gp_packet_type);

/** called when a peer leaves the group */
void gcc_peer_cleanup(GC_Connection *gconn);

/** called on group exit */
void gcc_cleanup(const GC_Chat *chat);

#endif  // GROUP_CONNECTION_H
