/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2026 The TokTok team.
 * Copyright © 2014 Tox project.
 */

/**
 * Implementation of the TCP relay server part of Tox.
 */
#include "TCP_server.h"

#include <assert.h>
#include <string.h>
#if !defined(_WIN32) && !defined(__WIN32__) && !defined (WIN32)
#include <sys/ioctl.h>
#endif /* !WIN32 */

#include "TCP_common.h"
#include "attributes.h"
#include "ccompat.h"
#include "crypto_core.h"
#include "forwarding.h"
#include "list.h"
#include "logger.h"
#include "mem.h"
#include "mono_time.h"
#include "net_profile.h"
#include "network.h"
#include "onion.h"

#define TCP_SOCKET_LISTENING 0
#define TCP_SOCKET_INCOMING 1
#define TCP_SOCKET_UNCONFIRMED 2
#define TCP_SOCKET_CONFIRMED 3

/** How many low bits of a socket's event loop key hold its index; the rest hold its kind. */
#define TCP_SOCKET_KEY_INDEX_BITS 24
#define TCP_SOCKET_KEY_INDEX_MASK ((1U << TCP_SOCKET_KEY_INDEX_BITS) - 1U)

/** @brief The event loop key of a socket: its kind and its index in that kind's array. */
static uint32_t tcp_socket_key(uint8_t type, uint32_t index)
{
    assert(index <= TCP_SOCKET_KEY_INDEX_MASK);
    return ((uint32_t)type << TCP_SOCKET_KEY_INDEX_BITS) | index;
}

typedef struct TCP_Secure_Conn {
    uint8_t public_key[CRYPTO_PUBLIC_KEY_SIZE];
    uint32_t index;
    // TODO(iphydf): Add an enum for this (same as in TCP_client.c, probably).
    uint8_t status; /* 0 if not used, 1 if other is offline, 2 if other is online. */
    uint8_t other_id;
} TCP_Secure_Conn;

typedef struct TCP_Secure_Connection {
    TCP_Connection con;

    uint8_t public_key[CRYPTO_PUBLIC_KEY_SIZE];
    uint8_t recv_nonce[CRYPTO_NONCE_SIZE]; /* Nonce of received packets. */
    uint16_t next_packet_length;
    TCP_Secure_Conn connections[NUM_CLIENT_CONNECTIONS];
    uint8_t status;

    uint64_t identifier;

    uint64_t last_pinged;
    uint64_t ping_id;

    Ev_Watch *_Nullable watch;
} TCP_Secure_Connection;

static const TCP_Secure_Connection empty_tcp_secure_connection = {{nullptr}};

static void handle_tcp_server_event(void *_Nullable obj, uint32_t key, Ev_Events events);

struct TCP_Server {
    const Logger *_Nonnull logger;
    const Memory *_Nonnull mem;
    const Random *_Nonnull rng;
    const Network *_Nonnull ns;
    const Mono_Time *_Nonnull mono_time;
    Ev *_Nonnull ev;
    Onion *_Nullable onion;
    Forwarding *_Nullable forwarding;

    uint64_t last_run_pinged;
    Socket *_Nullable socks_listening;
    Ev_Watch *_Nullable *_Nullable watches_listening;
    unsigned int num_listening_socks;

    uint8_t public_key[CRYPTO_PUBLIC_KEY_SIZE];
    uint8_t secret_key[CRYPTO_SECRET_KEY_SIZE];
    TCP_Secure_Connection incoming_connection_queue[MAX_INCOMING_CONNECTIONS];
    uint16_t incoming_connection_queue_index;
    TCP_Secure_Connection unconfirmed_connection_queue[MAX_INCOMING_CONNECTIONS];
    uint16_t unconfirmed_connection_queue_index;

    TCP_Secure_Connection *_Nullable accepted_connection_array;
    uint32_t size_accepted_connections;
    uint32_t num_accepted_connections;

    uint64_t counter;

    BS_List accepted_key_list;

    /* Network profile for all TCP server packets. */
    Net_Profile *_Nullable net_profile;
};

static_assert(MAX_ACCEPTED_CONNECTIONS + 2 * MAX_INCOMING_CONNECTIONS < EV_MAX_WATCHES,
              "the event loop must be able to watch all of a relay's connections");

static_assert(sizeof(TCP_Server) < 7 * 1024 * 1024,
              "TCP_Server struct should not grow more; it's already 6MB");

const uint8_t *tcp_server_public_key(const TCP_Server *tcp_server)
{
    return tcp_server->public_key;
}

size_t tcp_server_listen_count(const TCP_Server *tcp_server)
{
    return tcp_server->num_listening_socks;
}

/** @brief Increase the size of the connection list
 *
 * @retval -1 on failure
 * @retval 0 on success.
 */
static int alloc_new_connections(TCP_Server *_Nonnull tcp_server, uint32_t num)
{
    const uint32_t new_size = tcp_server->size_accepted_connections + num;

    if (new_size < tcp_server->size_accepted_connections) {
        return -1;
    }

    TCP_Secure_Connection *new_connections = (TCP_Secure_Connection *)mem_vrealloc(
            tcp_server->mem, tcp_server->accepted_connection_array,
            new_size, sizeof(TCP_Secure_Connection));

    if (new_connections == nullptr) {
        return -1;
    }

    const uint32_t old_size = tcp_server->size_accepted_connections;
    for (uint32_t i = 0; i < num; ++i) {
        new_connections[old_size + i] = empty_tcp_secure_connection;
    }

    tcp_server->accepted_connection_array = new_connections;
    tcp_server->size_accepted_connections = new_size;
    return 0;
}

static void wipe_secure_connection(TCP_Secure_Connection *_Nonnull con)
{
    if (con->status != 0) {
        wipe_priority_list(con->con.mem, con->con.priority_queue_start);
        tcp_free_recv_partial(&con->con);
        crypto_memzero(con, sizeof(TCP_Secure_Connection));
    }
}

static void move_secure_connection(TCP_Secure_Connection *_Nonnull con_new, TCP_Secure_Connection *_Nonnull con_old)
{
    *con_new = *con_old;
    crypto_memzero(con_old, sizeof(TCP_Secure_Connection));
}

/** Kill a TCP_Secure_Connection */
static void kill_tcp_secure_connection(TCP_Server *_Nonnull tcp_server, TCP_Secure_Connection *_Nonnull con)
{
    if (con->status == TCP_STATUS_NO_STATUS) {
        return;
    }

    ev_del(tcp_server->ev, con->watch);
    kill_sock(con->con.ns, con->con.sock);
    wipe_secure_connection(con);
}

static void free_accepted_connection_array(TCP_Server *_Nonnull tcp_server)
{
    if (tcp_server->accepted_connection_array == nullptr) {
        return;
    }

    for (uint32_t i = 0; i < tcp_server->size_accepted_connections; ++i) {
        kill_tcp_secure_connection(tcp_server, &tcp_server->accepted_connection_array[i]);
    }

    mem_delete(tcp_server->mem, tcp_server->accepted_connection_array);
    tcp_server->accepted_connection_array = nullptr;
    tcp_server->size_accepted_connections = 0;
}

/**
 * @return index corresponding to connection with peer on success
 * @retval -1 on failure.
 */
static int get_tcp_connection_index(const TCP_Server *_Nonnull tcp_server, const uint8_t *_Nonnull public_key)
{
    return bs_list_find(&tcp_server->accepted_key_list, public_key);
}

static int kill_accepted(TCP_Server *_Nonnull tcp_server, int index);

/** @brief Add accepted TCP connection to the list.
 *
 * @return index on success
 * @retval -1 on failure
 */
static int add_accepted(TCP_Server *_Nonnull tcp_server, TCP_Secure_Connection *_Nonnull con)
{
    int index = get_tcp_connection_index(tcp_server, con->public_key);

    if (index != -1) { /* If an old connection to the same public key exists, kill it. */
        kill_accepted(tcp_server, index);
        index = -1;
    }

    if (tcp_server->num_accepted_connections >= MAX_ACCEPTED_CONNECTIONS) {
        LOGGER_DEBUG(tcp_server->logger, "Not accepting connection: too many clients");
        return -1;
    }

    if (tcp_server->size_accepted_connections == tcp_server->num_accepted_connections) {
        if (alloc_new_connections(tcp_server, 4) == -1) {
            return -1;
        }

        index = tcp_server->num_accepted_connections;
    } else {
        for (uint32_t i = tcp_server->size_accepted_connections; i != 0; --i) {
            if (tcp_server->accepted_connection_array[i - 1].status == TCP_STATUS_NO_STATUS) {
                index = i - 1;
                break;
            }
        }
    }

    if (index == -1) {
        LOGGER_ERROR(tcp_server->logger, "FAIL index is -1");
        return -1;
    }

    if (!bs_list_add(&tcp_server->accepted_key_list, con->public_key, index)) {
        return -1;
    }

    move_secure_connection(&tcp_server->accepted_connection_array[index], con);

    tcp_server->accepted_connection_array[index].status = TCP_STATUS_CONFIRMED;
    ++tcp_server->num_accepted_connections;
    tcp_server->accepted_connection_array[index].identifier = ++tcp_server->counter;
    tcp_server->accepted_connection_array[index].last_pinged = mono_time_get(tcp_server->mono_time);
    tcp_server->accepted_connection_array[index].ping_id = 0;
    tcp_server->accepted_connection_array[index].con.net_profile = tcp_server->net_profile;

    return index;
}

/** @brief Delete accepted connection from list.
 *
 * @retval 0 on success
 * @retval -1 on failure
 */
static int del_accepted(TCP_Server *_Nonnull tcp_server, int index)
{
    if ((uint32_t)index >= tcp_server->size_accepted_connections) {
        return -1;
    }

    if (tcp_server->accepted_connection_array[index].status == TCP_STATUS_NO_STATUS) {
        return -1;
    }

    if (!bs_list_remove(&tcp_server->accepted_key_list, tcp_server->accepted_connection_array[index].public_key, index)) {
        return -1;
    }

    wipe_secure_connection(&tcp_server->accepted_connection_array[index]);
    --tcp_server->num_accepted_connections;

    if (tcp_server->num_accepted_connections == 0) {
        free_accepted_connection_array(tcp_server);
    }

    return 0;
}

static int rm_connection_index(TCP_Server *_Nonnull tcp_server, TCP_Secure_Connection *_Nonnull con, uint8_t con_number);

/** @brief Kill an accepted TCP_Secure_Connection
 *
 * @retval -1 on failure.
 * @retval 0 on success.
 */
static int kill_accepted(TCP_Server *tcp_server, int index)
{
    if ((uint32_t)index >= tcp_server->size_accepted_connections) {
        return -1;
    }

    for (uint32_t i = 0; i < NUM_CLIENT_CONNECTIONS; ++i) {
        rm_connection_index(tcp_server, &tcp_server->accepted_connection_array[index], i);
    }

    const Socket sock = tcp_server->accepted_connection_array[index].con.sock;
    Ev_Watch *watch = tcp_server->accepted_connection_array[index].watch;

    if (del_accepted(tcp_server, index) != 0) {
        return -1;
    }

    ev_del(tcp_server->ev, watch);
    kill_sock(tcp_server->ns, sock);
    return 0;
}

/**
 * @retval 1 if everything went well.
 * @retval -1 if the connection must be killed.
 */
static int handle_tcp_handshake(const Logger *_Nonnull logger, TCP_Secure_Connection *_Nonnull con, const uint8_t *_Nonnull data, uint16_t length, const uint8_t *_Nonnull self_secret_key)
{
    if (length != TCP_CLIENT_HANDSHAKE_SIZE) {
        LOGGER_ERROR(logger, "invalid handshake length: %d != %d", length, TCP_CLIENT_HANDSHAKE_SIZE);
        return -1;
    }

    if (con->status != TCP_STATUS_CONNECTED) {
        LOGGER_ERROR(logger, "TCP connection %u not connected", (unsigned int)con->identifier);
        return -1;
    }

    uint8_t shared_key[CRYPTO_SHARED_KEY_SIZE];
    encrypt_precompute(data, self_secret_key, shared_key);
    uint8_t plain[TCP_HANDSHAKE_PLAIN_SIZE];
    int len = decrypt_data_symmetric(con->con.mem, shared_key, data + CRYPTO_PUBLIC_KEY_SIZE,
                                     data + CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_NONCE_SIZE, TCP_HANDSHAKE_PLAIN_SIZE + CRYPTO_MAC_SIZE, plain);

    if (len != TCP_HANDSHAKE_PLAIN_SIZE) {
        LOGGER_ERROR(logger, "invalid TCP handshake decrypted length: %d != %d", len, TCP_HANDSHAKE_PLAIN_SIZE);
        crypto_memzero(shared_key, sizeof(shared_key));
        return -1;
    }

    memcpy(con->public_key, data, CRYPTO_PUBLIC_KEY_SIZE);
    uint8_t temp_secret_key[CRYPTO_SECRET_KEY_SIZE];
    uint8_t resp_plain[TCP_HANDSHAKE_PLAIN_SIZE];
    crypto_new_keypair(con->con.rng, resp_plain, temp_secret_key);
    random_nonce(con->con.rng, con->con.sent_nonce);
    memcpy(resp_plain + CRYPTO_PUBLIC_KEY_SIZE, con->con.sent_nonce, CRYPTO_NONCE_SIZE);
    memcpy(con->recv_nonce, plain + CRYPTO_PUBLIC_KEY_SIZE, CRYPTO_NONCE_SIZE);

    uint8_t response[TCP_SERVER_HANDSHAKE_SIZE];
    random_nonce(con->con.rng, response);

    len = encrypt_data_symmetric(con->con.mem, shared_key, response, resp_plain, TCP_HANDSHAKE_PLAIN_SIZE,
                                 response + CRYPTO_NONCE_SIZE);

    if (len != TCP_HANDSHAKE_PLAIN_SIZE + CRYPTO_MAC_SIZE) {
        crypto_memzero(shared_key, sizeof(shared_key));
        return -1;
    }

    const IP_Port ipp = {{{0}}};

    if (TCP_SERVER_HANDSHAKE_SIZE != net_send(con->con.ns, logger, con->con.sock, response, TCP_SERVER_HANDSHAKE_SIZE, &ipp, con->con.net_profile)) {
        crypto_memzero(shared_key, sizeof(shared_key));
        return -1;
    }

    encrypt_precompute(plain, temp_secret_key, con->con.shared_key);
    con->status = TCP_STATUS_UNCONFIRMED;

    crypto_memzero(shared_key, sizeof(shared_key));

    return 1;
}

/**
 * @retval 1 if connection handshake was handled correctly.
 * @retval 0 if we didn't get it yet.
 * @retval -1 if the connection must be killed.
 */
static int read_connection_handshake(const Logger *_Nonnull logger, TCP_Secure_Connection *_Nonnull con, const uint8_t *_Nonnull self_secret_key)
{
    uint8_t data[TCP_CLIENT_HANDSHAKE_SIZE];
    const int len = read_tcp_packet(logger, &con->con, data, TCP_CLIENT_HANDSHAKE_SIZE);

    if (len == -1) {
        LOGGER_TRACE(logger, "connection handshake is not ready yet");
        return 0;
    }

    return handle_tcp_handshake(logger, con, data, len, self_secret_key);
}

/**
 * @retval 1 on success.
 * @retval 0 if could not send packet.
 * @retval -1 on failure (connection must be killed).
 */
static int send_routing_response(const Logger *_Nonnull logger, TCP_Secure_Connection *_Nonnull con, uint8_t rpid, const uint8_t *_Nonnull public_key)
{
    uint8_t data[2 + CRYPTO_PUBLIC_KEY_SIZE];
    data[0] = TCP_PACKET_ROUTING_RESPONSE;
    data[1] = rpid;
    memcpy(data + 2, public_key, CRYPTO_PUBLIC_KEY_SIZE);

    return write_packet_tcp_secure_connection(logger, &con->con, data, sizeof(data), true);
}

/**
 * @retval 1 on success.
 * @retval 0 if could not send packet.
 * @retval -1 on failure (connection must be killed).
 */
static int send_connect_notification(const Logger *_Nonnull logger, TCP_Secure_Connection *_Nonnull con, uint8_t id)
{
    uint8_t data[2] = {TCP_PACKET_CONNECTION_NOTIFICATION, (uint8_t)(id + NUM_RESERVED_PORTS)};
    return write_packet_tcp_secure_connection(logger, &con->con, data, sizeof(data), true);
}

/**
 * @retval 1 on success.
 * @retval 0 if could not send packet.
 * @retval -1 on failure (connection must be killed).
 */
static int send_disconnect_notification(const Logger *_Nonnull logger, TCP_Secure_Connection *_Nonnull con, uint8_t id)
{
    uint8_t data[2] = {TCP_PACKET_DISCONNECT_NOTIFICATION, (uint8_t)(id + NUM_RESERVED_PORTS)};
    return write_packet_tcp_secure_connection(logger, &con->con, data, sizeof(data), true);
}

/**
 * @retval 0 on success.
 * @retval -1 on failure (connection must be killed).
 */
static int handle_tcp_routing_req(TCP_Server *_Nonnull tcp_server, uint32_t con_id, const uint8_t *_Nonnull public_key)
{
    uint32_t index = -1;
    TCP_Secure_Connection *con = &tcp_server->accepted_connection_array[con_id];

    /* If peer tries to connect to itself we deny the request. */
    if (pk_equal(con->public_key, public_key)) {
        if (send_routing_response(tcp_server->logger, con, 0, public_key) == -1) {
            return -1;
        }

        return 0;
    }

    for (uint32_t i = 0; i < NUM_CLIENT_CONNECTIONS; ++i) {
        if (con->connections[i].status != 0) {
            if (pk_equal(public_key, con->connections[i].public_key)) {
                if (send_routing_response(tcp_server->logger, con, i + NUM_RESERVED_PORTS, public_key) == -1) {
                    return -1;
                }

                return 0;
            }
        } else if (index == (uint32_t) -1) {
            index = i;
        }
    }

    if (index == (uint32_t) -1) {
        if (send_routing_response(tcp_server->logger, con, 0, public_key) == -1) {
            return -1;
        }

        return 0;
    }

    const int ret = send_routing_response(tcp_server->logger, con, index + NUM_RESERVED_PORTS, public_key);

    if (ret == 0) {
        return 0;
    }

    if (ret == -1) {
        return -1;
    }

    con->connections[index].status = 1;
    memcpy(con->connections[index].public_key, public_key, CRYPTO_PUBLIC_KEY_SIZE);
    const int other_index = get_tcp_connection_index(tcp_server, public_key);

    if (other_index != -1) {
        uint32_t other_id = -1;
        TCP_Secure_Connection *other_conn = &tcp_server->accepted_connection_array[other_index];

        for (uint32_t i = 0; i < NUM_CLIENT_CONNECTIONS; ++i) {
            if (other_conn->connections[i].status == 1
                    && pk_equal(other_conn->connections[i].public_key, con->public_key)) {
                other_id = i;
                break;
            }
        }

        if (other_id != (uint32_t) -1) {
            con->connections[index].status = 2;
            con->connections[index].index = other_index;
            con->connections[index].other_id = other_id;
            other_conn->connections[other_id].status = 2;
            other_conn->connections[other_id].index = con_id;
            other_conn->connections[other_id].other_id = index;
            // TODO(irungentoo): return values?
            send_connect_notification(tcp_server->logger, con, index);
            send_connect_notification(tcp_server->logger, other_conn, other_id);
        }
    }

    return 0;
}

/**
 * @retval 0 on success.
 * @retval -1 on failure (connection must be killed).
 */
static int handle_tcp_oob_send(TCP_Server *_Nonnull tcp_server, uint32_t con_id, const uint8_t *_Nonnull public_key, const uint8_t *_Nonnull data, uint16_t length)
{
    if (length == 0 || length > TCP_MAX_OOB_DATA_LENGTH) {
        return -1;
    }

    const TCP_Secure_Connection *con = &tcp_server->accepted_connection_array[con_id];

    const int other_index = get_tcp_connection_index(tcp_server, public_key);

    if (other_index != -1) {
        const uint16_t resp_packet_size = 1 + CRYPTO_PUBLIC_KEY_SIZE + length;
        VLA(uint8_t, resp_packet, resp_packet_size);
        resp_packet[0] = TCP_PACKET_OOB_RECV;
        memcpy(resp_packet + 1, con->public_key, CRYPTO_PUBLIC_KEY_SIZE);
        memcpy(resp_packet + 1 + CRYPTO_PUBLIC_KEY_SIZE, data, length);
        write_packet_tcp_secure_connection(tcp_server->logger, &tcp_server->accepted_connection_array[other_index].con,
                                           resp_packet, resp_packet_size, false);
    }

    return 0;
}

/** @brief Remove connection with con_number from the connections array of con.
 *
 * return -1 on failure.
 * return 0 on success.
 */
static int rm_connection_index(TCP_Server *tcp_server, TCP_Secure_Connection *con, uint8_t con_number)
{
    if (con_number >= NUM_CLIENT_CONNECTIONS) {
        return -1;
    }

    if (con->connections[con_number].status != 0) {
        if (con->connections[con_number].status == 2) {
            const uint32_t index = con->connections[con_number].index;
            const uint8_t other_id = con->connections[con_number].other_id;

            if (index >= tcp_server->size_accepted_connections) {
                return -1;
            }

            tcp_server->accepted_connection_array[index].connections[other_id].other_id = 0;
            tcp_server->accepted_connection_array[index].connections[other_id].index = 0;
            tcp_server->accepted_connection_array[index].connections[other_id].status = 1;
            // TODO(irungentoo): return values?
            send_disconnect_notification(tcp_server->logger, &tcp_server->accepted_connection_array[index], other_id);
        }

        con->connections[con_number].index = 0;
        con->connections[con_number].other_id = 0;
        con->connections[con_number].status = 0;
        return 0;
    }

    return -1;
}

/** @brief Encode con_id and identifier as a custom IP_Port.
 *
 * @return ip_port.
 */
static IP_Port con_id_to_ip_port(uint32_t con_id, uint64_t identifier)
{
    IP_Port ip_port = {{{0}}};
    ip_port.ip.family = net_family_tcp_client();
    ip_port.ip.ip.v6.uint32[0] = con_id;
    ip_port.ip.ip.v6.uint64[1] = identifier;
    return ip_port;

}

/** @brief Decode ip_port created by con_id_to_ip_port to con_id.
 *
 * @retval true on success.
 * @retval false if ip_port is invalid.
 */
static bool ip_port_to_con_id(const TCP_Server *_Nonnull tcp_server, const IP_Port *_Nonnull ip_port, uint32_t *_Nonnull con_id)
{
    *con_id = ip_port->ip.ip.v6.uint32[0];

    return net_family_is_tcp_client(ip_port->ip.family) &&
           *con_id < tcp_server->size_accepted_connections &&
           tcp_server->accepted_connection_array[*con_id].identifier == ip_port->ip.ip.v6.uint64[1];
}

static int handle_onion_recv_1(void *_Nonnull object, const IP_Port *_Nonnull dest, const uint8_t *_Nonnull data, uint16_t length)
{
    TCP_Server *tcp_server = (TCP_Server *)object;

    if (1 + length + CRYPTO_MAC_SIZE > MAX_PACKET_SIZE) {
        return 1;
    }

    uint32_t index;

    if (!ip_port_to_con_id(tcp_server, dest, &index)) {
        return 1;
    }

    TCP_Secure_Connection *con = &tcp_server->accepted_connection_array[index];

    const uint16_t packet_size = 1 + length;
    VLA(uint8_t, packet, packet_size);
    memcpy(packet + 1, data, length);
    packet[0] = TCP_PACKET_ONION_RESPONSE;

    if (write_packet_tcp_secure_connection(tcp_server->logger, &con->con, packet, packet_size, false) != 1) {
        return 1;
    }

    return 0;
}

static bool handle_forward_reply_tcp(void *_Nonnull object, const uint8_t *_Nonnull sendback_data, uint16_t sendback_data_len, const uint8_t *_Nonnull data, uint16_t length)
{
    TCP_Server *tcp_server = (TCP_Server *)object;

    if (1 + length + CRYPTO_MAC_SIZE > MAX_PACKET_SIZE) {
        return false;
    }

    if (sendback_data_len != 1 + sizeof(uint32_t) + sizeof(uint64_t)) {
        return false;
    }

    if (*sendback_data != SENDBACK_TCP) {
        return false;
    }

    uint32_t con_id;
    uint64_t identifier;
    net_unpack_u32(sendback_data + 1, &con_id);
    net_unpack_u64(sendback_data + 1 + sizeof(uint32_t), &identifier);

    if (con_id >= tcp_server->size_accepted_connections) {
        return false;
    }

    TCP_Secure_Connection *con = &tcp_server->accepted_connection_array[con_id];

    if (con->identifier != identifier) {
        return false;
    }

    const uint16_t packet_size = 1 + length;
    VLA(uint8_t, packet, packet_size);
    memcpy(packet + 1, data, length);
    packet[0] = TCP_PACKET_FORWARDING;

    return write_packet_tcp_secure_connection(tcp_server->logger, &con->con, packet, packet_size, false) == 1;
}

/**
 * @retval 0 on success
 * @retval -1 on failure
 */
static int handle_tcp_packet(TCP_Server *_Nonnull tcp_server, uint32_t con_id, const uint8_t *_Nonnull data, uint16_t length)
{
    if (length == 0) {
        return -1;
    }

    assert(con_id < tcp_server->size_accepted_connections);

    Tcp_Packet type;
    const char *type_name = tcp_packet_from_int(data[0], &type) ? tcp_packet_type_to_string(type) : "<invalid Tcp_Packet>";

    LOGGER_TRACE(tcp_server->logger, "Received TCP packet for connection %u of type %s (%u) and length %u.", con_id,
                 type_name, data[0], length);

    TCP_Secure_Connection *const con = &tcp_server->accepted_connection_array[con_id];
    netprof_record_packet(con->con.net_profile, data[0], length, PACKET_DIRECTION_RECV);

    switch (data[0]) {
        case TCP_PACKET_ROUTING_REQUEST: {
            if (length != 1 + CRYPTO_PUBLIC_KEY_SIZE) {
                return -1;
            }

            LOGGER_TRACE(tcp_server->logger, "handling routing request for %u", con_id);
            return handle_tcp_routing_req(tcp_server, con_id, data + 1);
        }

        case TCP_PACKET_CONNECTION_NOTIFICATION: {
            if (length != 2) {
                return -1;
            }

            LOGGER_TRACE(tcp_server->logger, "handling connection notification for %u", con_id);
            break;
        }

        case TCP_PACKET_DISCONNECT_NOTIFICATION: {
            if (length != 2) {
                return -1;
            }

            LOGGER_TRACE(tcp_server->logger, "handling disconnect notification for %u", con_id);
            return rm_connection_index(tcp_server, con, data[1] - NUM_RESERVED_PORTS);
        }

        case TCP_PACKET_PING: {
            if (length != 1 + sizeof(uint64_t)) {
                return -1;
            }

            LOGGER_TRACE(tcp_server->logger, "handling ping for %u", con_id);

            uint8_t response[1 + sizeof(uint64_t)];
            response[0] = TCP_PACKET_PONG;
            memcpy(response + 1, data + 1, sizeof(uint64_t));
            write_packet_tcp_secure_connection(tcp_server->logger, &con->con, response, sizeof(response), true);
            return 0;
        }

        case TCP_PACKET_PONG: {
            if (length != 1 + sizeof(uint64_t)) {
                return -1;
            }

            LOGGER_TRACE(tcp_server->logger, "handling pong for %u", con_id);

            uint64_t ping_id;
            memcpy(&ping_id, data + 1, sizeof(uint64_t));

            if (ping_id != 0) {
                if (ping_id == con->ping_id) {
                    con->ping_id = 0;
                }

                return 0;
            }

            return -1;
        }

        case TCP_PACKET_OOB_SEND: {
            if (length <= 1 + CRYPTO_PUBLIC_KEY_SIZE) {
                return -1;
            }

            LOGGER_TRACE(tcp_server->logger, "handling oob send for %u", con_id);

            return handle_tcp_oob_send(tcp_server, con_id, data + 1, data + 1 + CRYPTO_PUBLIC_KEY_SIZE,
                                       length - (1 + CRYPTO_PUBLIC_KEY_SIZE));
        }

        case TCP_PACKET_ONION_REQUEST: {
            LOGGER_TRACE(tcp_server->logger, "handling onion request for %u", con_id);

            if (tcp_server->onion != nullptr) {
                if (length <= 1 + CRYPTO_NONCE_SIZE + ONION_SEND_BASE * 2) {
                    return -1;
                }

                const IP_Port source = con_id_to_ip_port(con_id, con->identifier);
                onion_send_1(tcp_server->onion, data + 1 + CRYPTO_NONCE_SIZE, length - (1 + CRYPTO_NONCE_SIZE), &source,
                             data + 1);
            }

            return 0;
        }

        case TCP_PACKET_ONION_RESPONSE: {
            LOGGER_TRACE(tcp_server->logger, "handling onion response for %u", con_id);
            return -1;
        }

        case TCP_PACKET_FORWARD_REQUEST: {
            if (tcp_server->forwarding == nullptr) {
                return -1;
            }

            const uint16_t sendback_data_len = 1 + sizeof(uint32_t) + sizeof(uint64_t);
            uint8_t sendback_data[1 + sizeof(uint32_t) + sizeof(uint64_t)];
            sendback_data[0] = SENDBACK_TCP;
            net_pack_u32(sendback_data + 1, con_id);
            net_pack_u64(sendback_data + 1 + sizeof(uint32_t), con->identifier);

            IP_Port dest;
            const int ipport_length = unpack_ip_port(&dest, data + 1, length - 1, false);

            if (ipport_length == -1) {
                return -1;
            }

            const uint8_t *const forward_data = data + (1 + ipport_length);
            const uint16_t forward_data_len = length - (1 + ipport_length);

            if (forward_data_len > MAX_FORWARD_DATA_SIZE) {
                return -1;
            }

            send_forwarding(tcp_server->forwarding, &dest, sendback_data, sendback_data_len, forward_data, forward_data_len);
            return 0;
        }

        case TCP_PACKET_FORWARDING: {
            return -1;
        }

        default: {
            if (data[0] < NUM_RESERVED_PORTS) {
                return -1;
            }

            const uint8_t c_id = data[0] - NUM_RESERVED_PORTS;
            LOGGER_TRACE(tcp_server->logger, "handling packet id %u for %u", c_id, con_id);

            if (c_id >= NUM_CLIENT_CONNECTIONS) {
                return -1;
            }

            if (con->connections[c_id].status == 0) {
                return -1;
            }

            if (con->connections[c_id].status != 2) {
                return 0;
            }

            const uint32_t index = con->connections[c_id].index;
            const uint8_t other_c_id = con->connections[c_id].other_id + NUM_RESERVED_PORTS;
            VLA(uint8_t, new_data, length);
            memcpy(new_data, data, length);
            new_data[0] = other_c_id;
            const int ret = write_packet_tcp_secure_connection(tcp_server->logger,
                            &tcp_server->accepted_connection_array[index].con, new_data, length, false);

            if (ret == -1) {
                return -1;
            }

            return 0;
        }
    }

    return 0;
}

static int confirm_tcp_connection(TCP_Server *_Nonnull tcp_server, TCP_Secure_Connection *_Nonnull con, const uint8_t *_Nonnull data, uint16_t length)
{
    const int index = add_accepted(tcp_server, con);

    if (index == -1) {
        LOGGER_DEBUG(tcp_server->logger, "dropping connection %u: not accepted", (unsigned int)con->identifier);
        kill_tcp_secure_connection(tcp_server, con);
        return -1;
    }

    ev_mod(tcp_server->ev, tcp_server->accepted_connection_array[index].watch, EV_READ,
           tcp_socket_key(TCP_SOCKET_CONFIRMED, index));

    wipe_secure_connection(con);

    if (handle_tcp_packet(tcp_server, index, data, length) == -1) {
        LOGGER_DEBUG(tcp_server->logger, "dropping connection %u: data packet (len=%d) not handled",
                     (unsigned int)con->identifier, length);
        kill_accepted(tcp_server, index);
        return -1;
    }

    return index;
}

/**
 * @return index on success
 * @retval -1 on failure
 */
static int accept_connection(TCP_Server *_Nonnull tcp_server, Socket sock)
{
    if (!sock_valid(sock)) {
        return -1;
    }

    if (!set_socket_nonblock(tcp_server->ns, sock)) {
        kill_sock(tcp_server->ns, sock);
        return -1;
    }

    if (!set_socket_nosigpipe(tcp_server->ns, sock)) {
        kill_sock(tcp_server->ns, sock);
        return -1;
    }

    const uint16_t index = tcp_server->incoming_connection_queue_index % MAX_INCOMING_CONNECTIONS;

    TCP_Secure_Connection *conn = &tcp_server->incoming_connection_queue[index];

    if (conn->status != TCP_STATUS_NO_STATUS) {
        LOGGER_DEBUG(tcp_server->logger, "connection %d dropped before accepting", index);
        kill_tcp_secure_connection(tcp_server, conn);
    }

    conn->watch = ev_add(tcp_server->ev, sock, EV_READ, handle_tcp_server_event, tcp_server,
                         tcp_socket_key(TCP_SOCKET_INCOMING, index));

    if (conn->watch == nullptr) {
        LOGGER_ERROR(tcp_server->logger, "failed to watch incoming connection %d", index);
        kill_sock(tcp_server->ns, sock);
        return -1;
    }

    conn->status = TCP_STATUS_CONNECTED;
    conn->con.ns = tcp_server->ns;
    conn->con.mem = tcp_server->mem;
    conn->con.rng = tcp_server->rng;
    conn->con.sock = sock;
    conn->next_packet_length = 0;

    ++tcp_server->incoming_connection_queue_index;
    return index;
}

static Socket new_listening_tcp_socket(const Logger *_Nonnull logger, const Memory *_Nonnull mem, const Network *_Nonnull ns, Family family, uint16_t port)
{
    const Socket sock = net_socket(ns, family, TOX_SOCK_STREAM, TOX_PROTO_TCP);

    if (!sock_valid(sock)) {
        LOGGER_ERROR(logger, "TCP socket creation failed (family = %d)", family.value);
        return net_invalid_socket();
    }

    bool ok = set_socket_nonblock(ns, sock);

    if (ok && net_family_is_ipv6(family)) {
        ok = set_socket_dualstack(ns, sock);
    }

    if (ok) {
        ok = set_socket_reuseaddr(ns, sock);
    }

    ok = ok && bind_to_port(ns, sock, family, port) && (net_listen(ns, sock, TCP_MAX_BACKLOG) == 0);

    if (!ok) {
        Net_Strerror error_str;
        LOGGER_WARNING(logger, "could not bind to TCP port %d (family = %d): %s",
                       port, family.value, net_strerror(net_error(), &error_str));
        kill_sock(ns, sock);
        return net_invalid_socket();
    }

    LOGGER_DEBUG(logger, "successfully bound to TCP port %d", port);
    return sock;
}

TCP_Server *new_tcp_server(const Logger *logger, const Memory *mem, const Random *rng, const Network *ns,
                           const Mono_Time *mono_time, Ev *ev, bool ipv6_enabled, uint16_t num_sockets,
                           const uint16_t *ports, const uint8_t *secret_key, Onion *onion, Forwarding *forwarding)
{
    if (num_sockets == 0 || ports == nullptr) {
        LOGGER_ERROR(logger, "no sockets");
        return nullptr;
    }

    if (ns == nullptr) {
        LOGGER_ERROR(logger, "NULL network");
        return nullptr;
    }

    TCP_Server *temp = (TCP_Server *)mem_alloc(mem, sizeof(TCP_Server));

    if (temp == nullptr) {
        LOGGER_ERROR(logger, "TCP server allocation failed");
        return nullptr;
    }

    Net_Profile *np = netprof_new(logger, mem);

    if (np == nullptr) {
        mem_delete(mem, temp);
        return nullptr;
    }

    temp->net_profile = np;
    temp->logger = logger;
    temp->mem = mem;
    temp->ns = ns;
    temp->rng = rng;
    temp->mono_time = mono_time;
    temp->ev = ev;

    Socket *socks_listening = (Socket *)mem_valloc(mem, num_sockets, sizeof(Socket));
    Ev_Watch **watches_listening = (Ev_Watch **)mem_valloc(mem, num_sockets, sizeof(Ev_Watch *));

    if (socks_listening == nullptr || watches_listening == nullptr) {
        LOGGER_ERROR(logger, "socket allocation failed");
        netprof_kill(mem, temp->net_profile);
        mem_delete(mem, socks_listening);
        mem_delete(mem, watches_listening);
        mem_delete(mem, temp);
        return nullptr;
    }

    temp->socks_listening = socks_listening;
    temp->watches_listening = watches_listening;

    const Family family = ipv6_enabled ? net_family_ipv6() : net_family_ipv4();

    for (uint32_t i = 0; i < num_sockets; ++i) {
        const Socket sock = new_listening_tcp_socket(logger, mem, ns, family, ports[i]);

        if (!sock_valid(sock)) {
            continue;
        }

        temp->socks_listening[temp->num_listening_socks] = sock;
        ++temp->num_listening_socks;
    }

    if (temp->num_listening_socks == 0) {
        netprof_kill(mem, temp->net_profile);
        mem_delete(mem, temp->socks_listening);
        mem_delete(mem, temp->watches_listening);
        mem_delete(mem, temp);
        return nullptr;
    }

    if (onion != nullptr) {
        temp->onion = onion;
        set_callback_handle_recv_1(onion, &handle_onion_recv_1, temp);
    }

    if (forwarding != nullptr) {
        temp->forwarding = forwarding;
        set_callback_forward_reply(forwarding, &handle_forward_reply_tcp, temp);
    }

    memcpy(temp->secret_key, secret_key, CRYPTO_SECRET_KEY_SIZE);
    crypto_derive_public_key(temp->public_key, temp->secret_key);

    bs_list_init(&temp->accepted_key_list, mem, CRYPTO_PUBLIC_KEY_SIZE, 8, memcmp);

    for (uint32_t i = 0; i < temp->num_listening_socks; ++i) {
        temp->watches_listening[i] = ev_add(ev, temp->socks_listening[i], EV_READ, handle_tcp_server_event, temp,
                                            tcp_socket_key(TCP_SOCKET_LISTENING, i));

        if (temp->watches_listening[i] == nullptr) {
            LOGGER_ERROR(logger, "failed to watch a listening TCP socket");
            kill_tcp_server(temp);
            return nullptr;
        }
    }

    return temp;
}

static int do_incoming(TCP_Server *_Nonnull tcp_server, uint32_t i)
{
    TCP_Secure_Connection *const conn = &tcp_server->incoming_connection_queue[i];

    if (conn->status != TCP_STATUS_CONNECTED) {
        return -1;
    }

    LOGGER_TRACE(tcp_server->logger, "handling incoming TCP connection %u", i);

    const int ret = read_connection_handshake(tcp_server->logger, conn, tcp_server->secret_key);

    if (ret == -1) {
        LOGGER_TRACE(tcp_server->logger, "incoming connection %u dropped due to failed handshake", i);
        kill_tcp_secure_connection(tcp_server, conn);
        return -1;
    }

    if (ret != 1) {
        return -1;
    }

    const int index_new = tcp_server->unconfirmed_connection_queue_index % MAX_INCOMING_CONNECTIONS;
    TCP_Secure_Connection *conn_old = conn;
    TCP_Secure_Connection *conn_new = &tcp_server->unconfirmed_connection_queue[index_new];

    if (conn_new->status != TCP_STATUS_NO_STATUS) {
        LOGGER_ERROR(tcp_server->logger, "incoming connection %u would overwrite existing", i);
        kill_tcp_secure_connection(tcp_server, conn_new);
    }

    move_secure_connection(conn_new, conn_old);
    ++tcp_server->unconfirmed_connection_queue_index;

    ev_mod(tcp_server->ev, conn_new->watch, EV_READ, tcp_socket_key(TCP_SOCKET_UNCONFIRMED, index_new));

    return index_new;
}

static int do_unconfirmed(TCP_Server *_Nonnull tcp_server, uint32_t i)
{
    TCP_Secure_Connection *const conn = &tcp_server->unconfirmed_connection_queue[i];

    if (conn->status != TCP_STATUS_UNCONFIRMED) {
        return -1;
    }

    LOGGER_TRACE(tcp_server->logger, "handling unconfirmed TCP connection %u", i);

    uint8_t packet[MAX_PACKET_SIZE];
    const int len = read_packet_tcp_secure_connection(tcp_server->logger, &conn->con, &conn->next_packet_length, conn->recv_nonce, packet, sizeof(packet));

    if (len == 0) {
        return -1;
    }

    if (len == -1) {
        kill_tcp_secure_connection(tcp_server, conn);
        return -1;
    }

    return confirm_tcp_connection(tcp_server, conn, packet, len);
}

static bool tcp_process_secure_packet(TCP_Server *_Nonnull tcp_server, uint32_t i)
{
    assert(i < tcp_server->size_accepted_connections);
    TCP_Secure_Connection *const conn = &tcp_server->accepted_connection_array[i];

    uint8_t packet[MAX_PACKET_SIZE];
    const int len = read_packet_tcp_secure_connection(tcp_server->logger, &conn->con, &conn->next_packet_length, conn->recv_nonce, packet, sizeof(packet));
    LOGGER_TRACE(tcp_server->logger, "processing packet for %u: %d", i, len);

    if (len == 0) {
        return false;
    }

    if (len == -1) {
        kill_accepted(tcp_server, i);
        return false;
    }

    if (handle_tcp_packet(tcp_server, i, packet, len) == -1) {
        LOGGER_TRACE(tcp_server->logger, "dropping connection %u: data packet (len=%d) not handled", i, len);
        kill_accepted(tcp_server, i);
        return false;
    }

    return true;
}

static void do_confirmed_recv(TCP_Server *_Nonnull tcp_server, uint32_t i)
{
    while (tcp_process_secure_packet(tcp_server, i)) {
        /* Keep reading until an error occurs or there is no more data to read. */
    }
}

static void do_tcp_confirmed(TCP_Server *_Nonnull tcp_server)
{
    const Mono_Time *mono_time = tcp_server->mono_time;

    if (tcp_server->last_run_pinged == mono_time_get(mono_time)) {
        return;
    }

    tcp_server->last_run_pinged = mono_time_get(mono_time);

    for (uint32_t i = 0; i < tcp_server->size_accepted_connections; ++i) {
        TCP_Secure_Connection *conn = &tcp_server->accepted_connection_array[i];

        if (conn->status != TCP_STATUS_CONFIRMED) {
            continue;
        }

        if (mono_time_is_timeout(mono_time, conn->last_pinged, TCP_PING_FREQUENCY)) {
            uint8_t ping[1 + sizeof(uint64_t)];
            ping[0] = TCP_PACKET_PING;
            uint64_t ping_id = random_u64(conn->con.rng);

            if (ping_id == 0) {
                ++ping_id;
            }

            memcpy(ping + 1, &ping_id, sizeof(uint64_t));
            const int ret = write_packet_tcp_secure_connection(tcp_server->logger, &conn->con, ping, sizeof(ping), true);

            if (ret == 1) {
                conn->last_pinged = mono_time_get(mono_time);
                conn->ping_id = ping_id;
            } else {
                if (mono_time_is_timeout(mono_time, conn->last_pinged, TCP_PING_FREQUENCY + TCP_PING_TIMEOUT)) {
                    kill_accepted(tcp_server, i);
                    continue;
                }
            }
        }

        if (conn->ping_id != 0 && mono_time_is_timeout(mono_time, conn->last_pinged, TCP_PING_TIMEOUT)) {
            kill_accepted(tcp_server, i);
            continue;
        }

        send_pending_data(tcp_server->logger, &conn->con);
    }
}

/** @brief Reads from a connection, moving it on to the next state for as long as it can. */
static void read_tcp_connection(TCP_Server *_Nonnull tcp_server, uint8_t type, uint32_t index)
{
    uint8_t state = type;
    uint32_t i = index;

    if (state == TCP_SOCKET_INCOMING) {
        const int index_new = do_incoming(tcp_server, i);

        if (index_new == -1) {
            return;
        }

        LOGGER_TRACE(tcp_server->logger, "incoming connection %u was accepted as %d", i, index_new);
        state = TCP_SOCKET_UNCONFIRMED;
        i = index_new;
    }

    if (state == TCP_SOCKET_UNCONFIRMED) {
        const int index_new = do_unconfirmed(tcp_server, i);

        if (index_new == -1) {
            return;
        }

        LOGGER_TRACE(tcp_server->logger, "unconfirmed connection %u was confirmed as %d", i, index_new);
        state = TCP_SOCKET_CONFIRMED;
        i = index_new;
    }

    assert(state == TCP_SOCKET_CONFIRMED);
    do_confirmed_recv(tcp_server, i);
}

/** @brief Handles the events of one of the server's sockets, named by `tcp_socket_key`. */
static void handle_tcp_server_event(void *obj, uint32_t key, Ev_Events events)
{
    TCP_Server *tcp_server = (TCP_Server *)obj;
    const uint8_t type = key >> TCP_SOCKET_KEY_INDEX_BITS;
    const uint32_t index = key & TCP_SOCKET_KEY_INDEX_MASK;

    if ((events & EV_ERROR) != 0) {
        switch (type) {
            case TCP_SOCKET_LISTENING: {
                LOGGER_ERROR(tcp_server->logger, "listening socket %u failed", index);
                break;
            }

            case TCP_SOCKET_INCOMING: {
                LOGGER_TRACE(tcp_server->logger, "incoming connection %u dropped", index);
                kill_tcp_secure_connection(tcp_server, &tcp_server->incoming_connection_queue[index]);
                break;
            }

            case TCP_SOCKET_UNCONFIRMED: {
                LOGGER_TRACE(tcp_server->logger, "unconfirmed connection %u dropped", index);
                kill_tcp_secure_connection(tcp_server, &tcp_server->unconfirmed_connection_queue[index]);
                break;
            }

            case TCP_SOCKET_CONFIRMED: {
                LOGGER_TRACE(tcp_server->logger, "confirmed connection %u dropped", index);
                kill_accepted(tcp_server, index);
                break;
            }
        }

        return;
    }

    if ((events & EV_READ) == 0) {
        return;
    }

    if (type != TCP_SOCKET_LISTENING) {
        read_tcp_connection(tcp_server, type, index);
        return;
    }

    for (uint32_t i = 0; i < MAX_INCOMING_CONNECTIONS; ++i) {
        const Socket sock = net_accept(tcp_server->ns, tcp_server->socks_listening[index]);

        if (!sock_valid(sock)) {
            break;
        }

        const int index_new = accept_connection(tcp_server, sock);

        if (index_new != -1) {
            // The handshake may have come with the connection.
            read_tcp_connection(tcp_server, TCP_SOCKET_INCOMING, index_new);
        }
    }
}

void do_tcp_server(TCP_Server *tcp_server)
{
    do_tcp_confirmed(tcp_server);
}

void kill_tcp_server(TCP_Server *tcp_server)
{
    if (tcp_server == nullptr) {
        return;
    }

    for (uint32_t i = 0; i < tcp_server->num_listening_socks; ++i) {
        ev_del(tcp_server->ev, tcp_server->watches_listening[i]);
        kill_sock(tcp_server->ns, tcp_server->socks_listening[i]);
    }

    if (tcp_server->onion != nullptr) {
        set_callback_handle_recv_1(tcp_server->onion, nullptr, nullptr);
    }

    if (tcp_server->forwarding != nullptr) {
        set_callback_forward_reply(tcp_server->forwarding, nullptr, nullptr);
    }

    bs_list_free(&tcp_server->accepted_key_list);

    for (uint32_t i = 0; i < MAX_INCOMING_CONNECTIONS; ++i) {
        kill_tcp_secure_connection(tcp_server, &tcp_server->incoming_connection_queue[i]);
        kill_tcp_secure_connection(tcp_server, &tcp_server->unconfirmed_connection_queue[i]);
    }

    free_accepted_connection_array(tcp_server);

    crypto_memzero(tcp_server->secret_key, sizeof(tcp_server->secret_key));

    netprof_kill(tcp_server->mem, tcp_server->net_profile);
    mem_delete(tcp_server->mem, tcp_server->socks_listening);
    mem_delete(tcp_server->mem, tcp_server->watches_listening);
    mem_delete(tcp_server->mem, tcp_server);
}

const Net_Profile *tcp_server_get_net_profile(const TCP_Server *tcp_server)
{
    if (tcp_server == nullptr) {
        return nullptr;
    }

    return tcp_server->net_profile;
}
