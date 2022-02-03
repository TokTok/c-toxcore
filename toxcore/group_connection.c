/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2020 The TokTok team.
 * Copyright © 2015 Tox project.
 */

/**
 * An implementation of massive text only group chats.
 */

#include "group_connection.h"

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "DHT.h"
#include "crypto_core.h"
#include "group_chats.h"
#include "group_common.h"
#include "mono_time.h"
#include "util.h"

#ifndef VANILLA_NACL

/** Seconds since last direct UDP packet was received before the connection is considered dead */
#define GCC_UDP_DIRECT_TIMEOUT (GC_PING_TIMEOUT + 4)

/** Returns true if ary entry does not contain an active packet. */
static bool array_entry_is_empty(const GC_Message_Array_Entry *array_entry)
{
    return array_entry->time_added == 0;
}

/** Clears an array entry.
 *
 * Return 0 on success.
 * Return -1 on failure.
 */
static void clear_array_entry(GC_Message_Array_Entry *array_entry)
{
    if (array_entry->data) {
        free(array_entry->data);
    }

    *array_entry = (GC_Message_Array_Entry) {
        nullptr
    };
}

uint16_t gcc_get_array_index(uint64_t message_id)
{
    return message_id % GCC_BUFFER_SIZE;
}

void gcc_set_send_message_id(GC_Connection *gconn, uint64_t id)
{
    gconn->send_message_id = id;
    gconn->send_array_start = id % GCC_BUFFER_SIZE;
}

void gcc_set_recv_message_id(GC_Connection *gconn, uint64_t id)
{
    gconn->received_message_id = id;
}

/** Puts packet data in ary_entry.
 *
 * Return 0 on success.
 * Return -1 on failure.
 */
static int create_array_entry(const Mono_Time *mono_time, GC_Message_Array_Entry *array_entry, const uint8_t *data,
                              uint16_t length, uint8_t packet_type, uint64_t message_id)
{
    if (length > 0) {
        if (data == nullptr) {
            return -1;
        }

        array_entry->data = (uint8_t *)malloc(sizeof(uint8_t) * length);

        if (array_entry->data == nullptr) {
            return -1;
        }

        memcpy(array_entry->data, data, length);
    }

    const uint64_t tm = mono_time_get(mono_time);

    array_entry->data_length = length;
    array_entry->packet_type = packet_type;
    array_entry->message_id = message_id;
    array_entry->time_added = tm;
    array_entry->last_send_try = tm;

    return 0;
}

int gcc_add_to_send_array(const Logger *log, const Mono_Time *mono_time, GC_Connection *gconn, const uint8_t *data,
                          uint16_t length, uint8_t packet_type)
{
    /* check if send_array is full */
    if ((gconn->send_message_id % GCC_BUFFER_SIZE) == (uint16_t)(gconn->send_array_start - 1)) {
        LOGGER_DEBUG(log, "Send array overflow");
        return -1;
    }

    const uint16_t idx = gcc_get_array_index(gconn->send_message_id);
    GC_Message_Array_Entry *array_entry = &gconn->send_array[idx];

    if (!array_entry_is_empty(array_entry)) {
        LOGGER_DEBUG(log, "Send array entry isn't empty");
        return -1;
    }

    if (create_array_entry(mono_time, array_entry, data, length, packet_type, gconn->send_message_id) == -1) {
        LOGGER_WARNING(log, "Failed to create array entry");
        return -1;
    }

    ++gconn->send_message_id;

    return 0;
}

int gcc_handle_ack(GC_Connection *gconn, uint64_t message_id)
{
    uint16_t idx = gcc_get_array_index(message_id);
    GC_Message_Array_Entry *array_entry = &gconn->send_array[idx];

    if (array_entry_is_empty(array_entry)) {
        return 0;
    }

    if (array_entry->message_id != message_id) {  // wrap-around indicates a connection problem
        return -1;
    }

    clear_array_entry(array_entry);

    /* Put send_array_start in proper position */
    if (idx == gconn->send_array_start) {
        const uint16_t end = gconn->send_message_id % GCC_BUFFER_SIZE;

        while (array_entry_is_empty(&gconn->send_array[idx]) && gconn->send_array_start != end) {
            gconn->send_array_start = (gconn->send_array_start + 1) % GCC_BUFFER_SIZE;
            idx = (idx + 1) % GCC_BUFFER_SIZE;
        }
    }

    return 0;
}

bool gcc_ip_port_is_set(const GC_Connection *gconn)
{
    return ipport_isset(&gconn->addr.ip_port);
}

void gcc_set_ip_port(GC_Connection *gconn, const IP_Port *ipp)
{
    if (ipp != nullptr && ipport_isset(ipp)) {
        gconn->addr.ip_port = *ipp;
    }
}

int gcc_copy_tcp_relay(Node_format *tcp_node, const GC_Connection *gconn)
{
    if (gconn == nullptr || tcp_node == nullptr) {
        return -1;
    }

    if (gconn->tcp_relays_count == 0) {
        return -1;
    }

    const uint32_t rand_idx = random_u32() % gconn->tcp_relays_count;

    if (!ipport_isset(&gconn->connected_tcp_relays[rand_idx].ip_port)) {
        return -1;
    }

    *tcp_node = gconn->connected_tcp_relays[rand_idx];

    return 0;
}

int gcc_save_tcp_relay(GC_Connection *gconn, const Node_format *tcp_node)
{
    if (gconn == nullptr || tcp_node == nullptr) {
        return -1;
    }

    if (!ipport_isset(&tcp_node->ip_port)) {
        return -1;
    }

    for (uint16_t i = 0; i < gconn->tcp_relays_count; ++i) {
        if (id_equal(gconn->connected_tcp_relays[i].public_key, tcp_node->public_key)) {
            return -2;
        }
    }

    uint32_t idx = gconn->tcp_relays_count;

    if (gconn->tcp_relays_count >= MAX_FRIEND_TCP_CONNECTIONS) {
        idx = random_u32() % gconn->tcp_relays_count;
    } else {
        ++gconn->tcp_relays_count;
    }

    gconn->connected_tcp_relays[idx] = *tcp_node;

    return 0;
}

int gcc_handle_received_message(const Logger *log, const Mono_Time *mono_time, GC_Connection *gconn,
                                const uint8_t *data, uint16_t length, uint8_t packet_type, uint64_t message_id,
                                bool direct_conn)
{
    /* Appears to be a duplicate packet so we discard it */
    if (message_id < gconn->received_message_id + 1) {
        return 0;
    }

    /* we're missing an older message from this peer so we store it in received_array */
    if (message_id > gconn->received_message_id + 1) {
        const uint16_t idx = gcc_get_array_index(message_id);
        GC_Message_Array_Entry *ary_entry = &gconn->received_array[idx];

        if (!array_entry_is_empty(ary_entry)) {
            LOGGER_DEBUG(log, "Recv array is not empty");
            return -1;
        }

        if (create_array_entry(mono_time, ary_entry, data, length, packet_type, message_id) == -1) {
            LOGGER_DEBUG(log, "Failed to create array entry");
            return -1;
        }

        return 1;
    }

    if (direct_conn) {
        gconn->last_received_direct_time = mono_time_get(mono_time);
    }

    gcc_set_recv_message_id(gconn, gconn->received_message_id + 1);

    return 2;
}

/** Handles peer_number's array entry with appropriate handler and clears it from array.
 *
 * This function increments the received message ID for `gconn`.
 *
 * Return 0 on success.
 * Return -1 on failure.
 */
static int process_received_array_entry(const GC_Session *c, GC_Chat *chat, GC_Connection *gconn, uint32_t peer_number,
                                        GC_Message_Array_Entry *const array_entry, void *userdata)
{
    uint8_t sender_pk[ENC_PUBLIC_KEY_SIZE];
    memcpy(sender_pk, get_enc_key(gconn->addr.public_key), ENC_PUBLIC_KEY_SIZE);

    const int ret = handle_gc_lossless_helper(c, chat, peer_number, array_entry->data, array_entry->data_length,
                    array_entry->packet_type, userdata);

    /* peer number can change from peer add operations in packet handlers */
    peer_number = get_peer_number_of_enc_pk(chat, sender_pk, false);
    gconn = get_gc_connection(chat, peer_number);

    clear_array_entry(array_entry);

    if (ret < 0) {
        gc_send_message_ack(chat, gconn, array_entry->message_id, GR_ACK_REQ);
        return -1;
    }

    gc_send_message_ack(chat, gconn, array_entry->message_id, GR_ACK_RECV);

    gcc_set_recv_message_id(gconn, gconn->received_message_id + 1);

    return 0;
}

int gcc_check_received_array(const GC_Session *c, GC_Chat *chat, GC_Connection *gconn, uint32_t peer_number,
                             void *userdata)
{
    const uint16_t idx = (gconn->received_message_id + 1) % GCC_BUFFER_SIZE;
    GC_Message_Array_Entry *const array_entry = &gconn->received_array[idx];

    if (!array_entry_is_empty(array_entry)) {
        return process_received_array_entry(c, chat, gconn, peer_number, array_entry, userdata);
    }

    return 0;
}

void gcc_resend_packets(const GC_Chat *chat, GC_Connection *gconn)
{
    const uint64_t tm = mono_time_get(chat->mono_time);
    const uint16_t start = gconn->send_array_start;
    const uint16_t end = gconn->send_message_id % GCC_BUFFER_SIZE;

    for (uint16_t i = start; i != end; i = (i + 1) % GCC_BUFFER_SIZE) {
        GC_Message_Array_Entry *array_entry = &gconn->send_array[i];

        if (array_entry_is_empty(array_entry)) {
            continue;
        }

        if (tm == array_entry->last_send_try) {
            continue;
        }

        const uint64_t delta = array_entry->last_send_try - array_entry->time_added;
        array_entry->last_send_try = tm;

        /* if this occurrs less than once per second this won't be reliable */
        if (delta > 1 && is_power_of_2(delta)) {
            gcc_encrypt_and_send_lossless_packet(chat, gconn, array_entry->data, array_entry->data_length,
                                                 array_entry->message_id, array_entry->packet_type);
            continue;
        }

        if (mono_time_is_timeout(chat->mono_time, array_entry->time_added, GC_CONFIRMED_PEER_TIMEOUT)) {
            gcc_mark_for_deletion(gconn, chat->tcp_conn, GC_EXIT_TYPE_TIMEOUT, nullptr, 0);
            return;
        }
    }
}

int gcc_send_packet(const GC_Chat *chat, const GC_Connection *gconn, const uint8_t *packet, uint16_t length)
{
    if (packet == nullptr || length == 0) {
        return -1;
    }

    bool direct_send_attempt = false;

    if (gcc_direct_conn_is_possible(chat, gconn)) {
        if (gcc_conn_is_direct(chat->mono_time, gconn)) {
            if ((uint16_t) sendpacket(chat->net, &gconn->addr.ip_port, packet, length) == length) {
                return 0;
            }

            return -1;
        }

        if ((uint16_t) sendpacket(chat->net, &gconn->addr.ip_port, packet, length) == length) {
            direct_send_attempt = true;
        }
    }

    const int ret = send_packet_tcp_connection(chat->tcp_conn, gconn->tcp_connection_num, packet, length);

    if (ret == 0 || direct_send_attempt) {
        return 0;
    }

    return -1;
}

int gcc_encrypt_and_send_lossless_packet(const GC_Chat *chat, const GC_Connection *gconn, const uint8_t *data,
        uint16_t length, uint64_t message_id, uint8_t packet_type)
{
    uint8_t packet[MAX_GC_PACKET_SIZE];
    const int enc_len = group_packet_wrap(chat->log, chat->self_public_key, gconn->session_shared_key, packet,
                                          sizeof(packet), data, length, message_id, packet_type, NET_PACKET_GC_LOSSLESS);

    if (enc_len < 0) {
        LOGGER_WARNING(chat->log, "Failed to wrap packet (type: 0x%02x, error: %d)", packet_type, enc_len);
        return -1;
    }

    if (gcc_send_packet(chat, gconn, packet, (uint16_t)enc_len) == -1) {
        LOGGER_WARNING(chat->log, "Failed to send packet (type: 0x%02x, enc_len: %d)", packet_type, enc_len);
        return -1;
    }

    return 0;
}

void gcc_make_session_shared_key(GC_Connection *gconn, const uint8_t *sender_pk)
{
    encrypt_precompute(sender_pk, gconn->session_secret_key, gconn->session_shared_key);
}

bool gcc_conn_is_direct(const Mono_Time *mono_time, const GC_Connection *gconn)
{
    return ((GCC_UDP_DIRECT_TIMEOUT + gconn->last_received_direct_time) > mono_time_get(mono_time));
}

bool gcc_direct_conn_is_possible(const GC_Chat *chat, const GC_Connection *gconn)
{
    return !net_family_is_unspec(gconn->addr.ip_port.ip.family) && !net_family_is_unspec(net_family(chat->net));
}

void gcc_mark_for_deletion(GC_Connection *gconn, TCP_Connections *tcp_conn, Group_Exit_Type type,
                           const uint8_t *part_message, uint16_t length)
{
    if (gconn == nullptr) {
        return;
    }

    if (gconn->pending_delete) {
        return;
    }

    gconn->pending_delete = true;
    gconn->exit_info.exit_type = type;

    kill_tcp_connection_to(tcp_conn, gconn->tcp_connection_num);

    if (length > 0 && length <= MAX_GC_PART_MESSAGE_SIZE  && part_message != nullptr) {
        memcpy(gconn->exit_info.part_message, part_message, length);
        gconn->exit_info.length = length;
    }
}

void gcc_peer_cleanup(GC_Connection *gconn)
{
    for (size_t i = 0; i < GCC_BUFFER_SIZE; ++i) {
        if (gconn->send_array[i].data) {
            free(gconn->send_array[i].data);
        }

        if (gconn->received_array[i].data) {
            free(gconn->received_array[i].data);
        }
    }

    crypto_memunlock(gconn->session_secret_key, sizeof(gconn->session_secret_key));
    crypto_memunlock(gconn->session_shared_key, sizeof(gconn->session_shared_key));
    crypto_memzero(gconn, sizeof(GC_Connection));
}

void gcc_cleanup(const GC_Chat *chat)
{
    for (uint32_t i = 0; i < chat->numpeers; ++i) {
        GC_Connection *gconn = get_gc_connection(chat, i);
        assert(gconn != nullptr);

        gcc_peer_cleanup(gconn);
    }
}

#endif // VANILLA_NACL
