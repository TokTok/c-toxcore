/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2026 The TokTok team.
 * Copyright © 2014 Tox project.
 */

#include "TCP_common.h"

#include <string.h>

#include "attributes.h"
#include "ccompat.h"
#include "crypto_core.h"
#include "logger.h"
#include "mem.h"
#include "network.h"

void wipe_priority_list(const Memory *mem, TCP_Priority_List *p)
{
    while (p != nullptr) {
        TCP_Priority_List *pp = p;
        p = p->next;
        mem_delete(mem, pp->data);
        mem_delete(mem, pp);
    }
}

/**
 * @retval 0 if pending data was sent completely
 * @retval -1 if it wasn't
 */
int send_pending_data_nonpriority(const Logger *logger, TCP_Connection *con)
{
    if (con->last_packet_length == 0) {
        return 0;
    }

    const uint16_t left = con->last_packet_length - con->last_packet_sent;
    const int len = net_send(con->ns, logger, con->sock, con->last_packet + con->last_packet_sent, left, &con->ip_port,
                             con->net_profile);

    if (len <= 0) {
        return -1;
    }

    if (len == left) {
        con->last_packet_length = 0;
        con->last_packet_sent = 0;
        return 0;
    }

    con->last_packet_sent += len;
    return -1;
}

/**
 * @retval 0 if pending data was sent completely
 * @retval -1 if it wasn't
 */
int send_pending_data(const Logger *logger, TCP_Connection *con)
{
    /* finish sending current non-priority packet */
    if (send_pending_data_nonpriority(logger, con) == -1) {
        return -1;
    }

    TCP_Priority_List *p = con->priority_queue_start;

    while (p != nullptr) {
        const uint16_t left = p->size - p->sent;
        const int len = net_send(con->ns, logger, con->sock, p->data + p->sent, left, &con->ip_port, con->net_profile);

        if (len != left) {
            if (len > 0) {
                p->sent += len;
            }

            break;
        }

        TCP_Priority_List *pp = p;
        p = p->next;
        mem_delete(con->mem, pp->data);
        mem_delete(con->mem, pp);
        --con->priority_queue_length;
    }

    con->priority_queue_start = p;

    if (p == nullptr) {
        con->priority_queue_end = nullptr;
        return 0;
    }

    return -1;
}

/**
 * @retval false on failure (only if mem_alloc fails)
 * @retval true on success
 */
static bool add_priority(TCP_Connection *_Nonnull con, const uint8_t *_Nonnull packet, uint16_t size, uint16_t sent)
{
    TCP_Priority_List *p = con->priority_queue_end;
    TCP_Priority_List *new_list = (TCP_Priority_List *)mem_alloc(con->mem, sizeof(TCP_Priority_List));

    if (new_list == nullptr) {
        return false;
    }

    uint8_t *data = (uint8_t *)mem_balloc(con->mem, size);

    if (data == nullptr) {
        mem_delete(con->mem, new_list);
        return false;
    }

    memcpy(data, packet, size);
    new_list->data = data;
    new_list->size = size;

    new_list->next = nullptr;
    new_list->sent = sent;

    if (p != nullptr) {
        p->next = new_list;
    } else {
        con->priority_queue_start = new_list;
    }

    con->priority_queue_end = new_list;
    ++con->priority_queue_length;
    return true;
}

/**
 * @retval 1 on success.
 * @retval 0 if could not send packet.
 * @retval -1 on failure (connection must be killed).
 */
int write_packet_tcp_secure_connection(const Logger *logger, TCP_Connection *con, const uint8_t *data, uint16_t length,
                                       bool priority)
{
    if (length + CRYPTO_MAC_SIZE > MAX_PACKET_SIZE) {
        return -1;
    }

    bool sendpriority = true;

    if (send_pending_data(logger, con) == -1) {
        if (priority) {
            // Drop it before encrypting, so it doesn't use up a nonce the peer expects.
            if (con->priority_queue_length >= TCP_MAX_PRIORITY_PACKETS) {
                return 0;
            }

            sendpriority = false;
        } else {
            return 0;
        }
    }

    const uint16_t packet_size = sizeof(uint16_t) + length + CRYPTO_MAC_SIZE;
    VLA(uint8_t, packet, packet_size);

    uint16_t c_length = net_htons(length + CRYPTO_MAC_SIZE);
    memcpy(packet, &c_length, sizeof(uint16_t));
    int len = encrypt_data_symmetric(con->mem, con->shared_key, con->sent_nonce, data, length, packet + sizeof(uint16_t));

    if ((unsigned int)len != (packet_size - sizeof(uint16_t))) {
        return -1;
    }

    if (priority) {
        len = sendpriority ? net_send(con->ns, logger, con->sock, packet, packet_size, &con->ip_port,
                                      con->net_profile) : 0;

        if (len <= 0) {
            len = 0;
        }

        increment_nonce(con->sent_nonce);

        if ((unsigned int)len == packet_size) {
            return 1;
        }

        return add_priority(con, packet, packet_size, len) ? 1 : 0;
    }

    len = net_send(con->ns, logger, con->sock, packet, packet_size, &con->ip_port, con->net_profile);

    if (len <= 0) {
        return 0;
    }

    increment_nonce(con->sent_nonce);

    if ((unsigned int)len == packet_size) {
        return 1;
    }

    memcpy(con->last_packet, packet, packet_size);
    con->last_packet_length = packet_size;
    con->last_packet_sent = len;
    return 1;
}

void tcp_free_recv_partial(TCP_Connection *con)
{
    if (con->recv_partial == nullptr) {
        return;
    }

    mem_delete(con->mem, con->recv_partial);
    con->recv_partial = nullptr;
    con->recv_partial_length = 0;
    con->recv_partial_wanted = 0;
}

/** @brief Read length bytes from the connection's socket.
 *
 * Takes what has arrived out of the socket even when that's less than length,
 * and keeps it in the connection, so the socket is only readable again when
 * more arrives. Until all of it is there, each call must ask for the same
 * length.
 *
 * return length on success
 * return -1 on failure/not enough data yet.
 */
int read_tcp_packet(const Logger *logger, TCP_Connection *con, uint8_t *data, uint16_t length)
{
    const uint16_t count = net_socket_data_recv_buffer(con->ns, con->sock);

    if (con->recv_partial == nullptr) {
        if (count >= length) {
            const int len = net_recv(con->ns, logger, con->sock, data, length, &con->ip_port);

            if (len != length) {
                LOGGER_ERROR(logger, "FAIL recv packet");
                return -1;
            }

            return len;
        }

        if (count == 0) {
            return -1;
        }

        // Left in the socket, these bytes would keep it readable until the rest arrives.
        uint8_t *partial = (uint8_t *)mem_balloc(con->mem, length);

        if (partial == nullptr) {
            return -1;
        }

        con->recv_partial = partial;
        con->recv_partial_length = 0;
        con->recv_partial_wanted = length;
    }

    if (con->recv_partial_wanted != length) {
        LOGGER_ERROR(logger, "asked for %d bytes while waiting for the rest of %d", length, con->recv_partial_wanted);
        return -1;
    }

    const uint16_t missing = length - con->recv_partial_length;
    const uint16_t take = count < missing ? count : missing;

    if (take > 0) {
        const int len = net_recv(con->ns, logger, con->sock, con->recv_partial + con->recv_partial_length, take, &con->ip_port);

        if (len != take) {
            LOGGER_ERROR(logger, "FAIL recv packet");
            return -1;
        }

        con->recv_partial_length += take;
    }

    if (con->recv_partial_length < length) {
        LOGGER_TRACE(logger, "have %d of the %d bytes asked for", con->recv_partial_length, length);
        return -1;
    }

    memcpy(data, con->recv_partial, length);
    tcp_free_recv_partial(con);
    return length;
}

/** @brief Read the next two bytes in TCP stream then convert them to
 * length (host byte order).
 *
 * return length on success
 * return 0 if nothing has been read from socket.
 * return -1 on failure.
 */
static uint16_t read_tcp_length(const Logger *_Nonnull logger, TCP_Connection *_Nonnull con)
{
    uint8_t length_buf[sizeof(uint16_t)];

    if (read_tcp_packet(logger, con, length_buf, sizeof(length_buf)) == -1) {
        return 0;
    }

    uint16_t length;
    net_unpack_u16(length_buf, &length);

    if (length > MAX_PACKET_SIZE) {
        LOGGER_ERROR(logger, "TCP packet too large: %d > %d", length, MAX_PACKET_SIZE);
        return -1;
    }

    return length;
}

/**
 * @return length of received packet on success.
 * @retval 0 if could not read any packet.
 * @retval -1 on failure (connection must be killed).
 */
int read_packet_tcp_secure_connection(
    const Logger *logger, TCP_Connection *con, uint16_t *next_packet_length,
    uint8_t *recv_nonce, uint8_t *data, uint16_t max_len)
{
    if (*next_packet_length == 0) {
        const uint16_t len = read_tcp_length(logger, con);

        if (len == (uint16_t) -1) {
            return -1;
        }

        if (len == 0) {
            return 0;
        }

        *next_packet_length = len;
    }

    if (max_len + CRYPTO_MAC_SIZE < *next_packet_length) {
        LOGGER_DEBUG(logger, "packet too large");
        return -1;
    }

    VLA(uint8_t, data_encrypted, (int) *next_packet_length);
    const int len_packet = read_tcp_packet(logger, con, data_encrypted, *next_packet_length);

    if (len_packet == -1) {
        return 0;
    }

    if (len_packet != *next_packet_length) {
        // TODO(Green-Sky): this is probably unrecoverable
        LOGGER_WARNING(logger, "invalid packet length: %d, expected %d", len_packet, *next_packet_length);
        return 0;
    }

    *next_packet_length = 0;

    const int len = decrypt_data_symmetric(con->mem, con->shared_key, recv_nonce, data_encrypted, len_packet, data);

    if (len + CRYPTO_MAC_SIZE != len_packet) {
        LOGGER_ERROR(logger, "decrypted length %d does not match expected length %d", len + CRYPTO_MAC_SIZE, len_packet);
        return -1;
    }

    increment_nonce(recv_nonce);

    return len;
}

const char *tcp_packet_type_to_string(Tcp_Packet type)
{
    switch (type) {
        case TCP_PACKET_ROUTING_REQUEST:
            return "TCP_PACKET_ROUTING_REQUEST";

        case TCP_PACKET_ROUTING_RESPONSE:
            return "TCP_PACKET_ROUTING_RESPONSE";

        case TCP_PACKET_CONNECTION_NOTIFICATION:
            return "TCP_PACKET_CONNECTION_NOTIFICATION";

        case TCP_PACKET_DISCONNECT_NOTIFICATION:
            return "TCP_PACKET_DISCONNECT_NOTIFICATION";

        case TCP_PACKET_PING:
            return "TCP_PACKET_PING";

        case TCP_PACKET_PONG:
            return "TCP_PACKET_PONG";

        case TCP_PACKET_OOB_SEND:
            return "TCP_PACKET_OOB_SEND";

        case TCP_PACKET_OOB_RECV:
            return "TCP_PACKET_OOB_RECV";

        case TCP_PACKET_ONION_REQUEST:
            return "TCP_PACKET_ONION_REQUEST";

        case TCP_PACKET_ONION_RESPONSE:
            return "TCP_PACKET_ONION_RESPONSE";

        case TCP_PACKET_FORWARD_REQUEST:
            return "TCP_PACKET_FORWARD_REQUEST";

        case TCP_PACKET_FORWARDING:
            return "TCP_PACKET_FORWARDING";
    }

    return "<invalid Tcp_Packet>";
}

bool tcp_packet_from_int(uint32_t value, Tcp_Packet *out_enum)
{
    switch (value) {
        case TCP_PACKET_ROUTING_REQUEST:
        case TCP_PACKET_ROUTING_RESPONSE:
        case TCP_PACKET_CONNECTION_NOTIFICATION:
        case TCP_PACKET_DISCONNECT_NOTIFICATION:
        case TCP_PACKET_PING:
        case TCP_PACKET_PONG:
        case TCP_PACKET_OOB_SEND:
        case TCP_PACKET_OOB_RECV:
        case TCP_PACKET_ONION_REQUEST:
        case TCP_PACKET_ONION_RESPONSE:
        case TCP_PACKET_FORWARD_REQUEST:
        case TCP_PACKET_FORWARDING: {
            *out_enum = (Tcp_Packet)value;
            return true;
        }
    }

    return false;
}
