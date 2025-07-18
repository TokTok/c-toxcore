/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2025 The TokTok team.
 * Copyright © 2015 Tox project.
 */

/**
 * Handles TCP relay connections between two Tox clients.
 */
#ifndef C_TOXCORE_TOXCORE_TCP_CONNECTION_H
#define C_TOXCORE_TOXCORE_TCP_CONNECTION_H

#include <stdbool.h>
#include <stdint.h>

#include "DHT.h"  // for Node_format
#include "TCP_client.h"
#include "TCP_common.h"
#include "attributes.h"
#include "crypto_core.h"
#include "forwarding.h"
#include "logger.h"
#include "mem.h"
#include "mono_time.h"
#include "net_profile.h"
#include "network.h"

#define TCP_CONN_NONE 0
#define TCP_CONN_VALID 1

/** NOTE: only used by TCP_con */
#define TCP_CONN_CONNECTED 2

/** Connection is not connected but can be quickly reconnected in case it is needed. */
#define TCP_CONN_SLEEPING 3

#define TCP_CONNECTIONS_STATUS_NONE 0
#define TCP_CONNECTIONS_STATUS_REGISTERED 1
#define TCP_CONNECTIONS_STATUS_ONLINE 2

#define MAX_FRIEND_TCP_CONNECTIONS 6

/** Time until connection to friend gets killed (if it doesn't get locked within that time) */
#define TCP_CONNECTION_ANNOUNCE_TIMEOUT TCP_CONNECTION_TIMEOUT

/** @brief The amount of recommended connections for each friend
 * NOTE: Must be at most (MAX_FRIEND_TCP_CONNECTIONS / 2)
 */
#define RECOMMENDED_FRIEND_TCP_CONNECTIONS (MAX_FRIEND_TCP_CONNECTIONS / 2)

/** Number of TCP connections used for onion purposes. */
#define NUM_ONION_TCP_CONNECTIONS RECOMMENDED_FRIEND_TCP_CONNECTIONS

typedef struct TCP_Conn_to {
    uint32_t tcp_connection;
    uint8_t status;
    uint8_t connection_id;
} TCP_Conn_to;

typedef struct TCP_Connection_to {
    uint8_t status;
    uint8_t public_key[CRYPTO_PUBLIC_KEY_SIZE]; /* The dht public key of the peer */

    TCP_Conn_to connections[MAX_FRIEND_TCP_CONNECTIONS];

    int id; /* id used in callbacks. */
} TCP_Connection_to;

typedef struct TCP_con {
    uint8_t status;
    TCP_Client_Connection *_Nullable connection;
    uint64_t connected_time;
    uint32_t lock_count;
    uint32_t sleep_count;
    bool onion;

    /* Only used when connection is sleeping. */
    IP_Port ip_port;
    uint8_t relay_pk[CRYPTO_PUBLIC_KEY_SIZE];
    bool unsleep; /* set to 1 to unsleep connection. */
} TCP_con;

typedef struct TCP_Connections TCP_Connections;

const uint8_t *_Nonnull tcp_connections_public_key(const TCP_Connections *_Nonnull tcp_c);

uint32_t tcp_connections_count(const TCP_Connections *_Nonnull tcp_c);

/** @brief Returns the number of connected TCP relays. */
uint32_t tcp_connected_relays_count(const TCP_Connections *_Nonnull tcp_c);

/** @brief Returns true if we know of a valid TCP relay with the passed public key. */
bool tcp_relay_is_valid(const TCP_Connections *_Nonnull tcp_c, const uint8_t *_Nonnull relay_pk);

/** @brief Send a packet to the TCP connection.
 *
 * return -1 on failure.
 * return 0 on success.
 */
int send_packet_tcp_connection(const TCP_Connections *_Nonnull tcp_c, int connections_number, const uint8_t *_Nonnull packet, uint16_t length);

/** @brief Return a TCP connection number for use in send_tcp_onion_request.
 *
 * TODO(irungentoo): This number is just the index of an array that the elements
 * can change without warning.
 *
 * return TCP connection number on success.
 * return -1 on failure.
 */
int get_random_tcp_onion_conn_number(const TCP_Connections *_Nonnull tcp_c);

/** @brief Put IP_Port of a random onion TCP connection in ip_port.
 *
 * return true on success.
 * return false on failure.
 */
bool tcp_get_random_conn_ip_port(const TCP_Connections *_Nonnull tcp_c, IP_Port *_Nonnull ip_port);

/** @brief Send an onion packet via the TCP relay corresponding to tcp_connections_number.
 *
 * return 0 on success.
 * return -1 on failure.
 */
int tcp_send_onion_request(TCP_Connections *_Nonnull tcp_c, uint32_t tcp_connections_number, const uint8_t *_Nonnull data, uint16_t length);

/** @brief Set if we want TCP_connection to allocate some connection for onion use.
 *
 * If status is 1, allocate some connections. if status is 0, don't.
 *
 * return 0 on success.
 * return -1 on failure.
 */
int set_tcp_onion_status(TCP_Connections *_Nonnull tcp_c, bool status);

/**
 * Send a forward request to the TCP relay with IP_Port tcp_forwarder,
 * requesting to forward data via a chain of dht nodes starting with dht_node.
 * A chain_length of 0 means that dht_node is the final destination of data.
 *
 * return 0 on success.
 * return -1 on failure.
 */
int tcp_send_forward_request(const Logger *_Nonnull logger, TCP_Connections *_Nonnull tcp_c, const IP_Port *_Nonnull tcp_forwarder, const IP_Port *_Nonnull dht_node,
                             const uint8_t *_Nonnull chain_keys, uint16_t chain_length, const uint8_t *_Nonnull data, uint16_t data_length);

/** @brief Send an oob packet via the TCP relay corresponding to tcp_connections_number.
 *
 * return 0 on success.
 * return -1 on failure.
 */
int tcp_send_oob_packet(const TCP_Connections *_Nonnull tcp_c, unsigned int tcp_connections_number, const uint8_t *_Nonnull public_key, const uint8_t *_Nonnull packet, uint16_t length);

typedef int tcp_data_cb(void *_Nonnull object, int crypt_connection_id, const uint8_t *_Nonnull packet, uint16_t length, void *_Nullable userdata);

int tcp_send_oob_packet_using_relay(const TCP_Connections *_Nonnull tcp_c, const uint8_t *_Nonnull relay_pk, const uint8_t *_Nonnull public_key, const uint8_t *_Nonnull packet,
                                    uint16_t length);

/** @brief Set the callback for TCP data packets. */
void set_packet_tcp_connection_callback(TCP_Connections *_Nonnull tcp_c, tcp_data_cb *_Nonnull tcp_data_callback, void *_Nonnull object);

typedef int tcp_onion_cb(void *_Nullable object, const uint8_t *_Nonnull data, uint16_t length, void *_Nullable userdata);

/** @brief Set the callback for TCP onion packets. */
void set_onion_packet_tcp_connection_callback(TCP_Connections *_Nonnull tcp_c, tcp_onion_cb *_Nullable tcp_onion_callback, void *_Nullable object);
/** @brief Set the callback for TCP forwarding packets. */
void set_forwarding_packet_tcp_connection_callback(TCP_Connections *_Nonnull tcp_c,
        forwarded_response_cb *_Nullable tcp_forwarded_response_callback,
        void *_Nullable object);
typedef int tcp_oob_cb(void *_Nonnull object, const uint8_t *_Nonnull public_key, unsigned int tcp_connections_number,
                       const uint8_t *_Nonnull packet, uint16_t length, void *_Nullable userdata);

/** @brief Set the callback for TCP oob data packets. */
void set_oob_packet_tcp_connection_callback(TCP_Connections *_Nonnull tcp_c, tcp_oob_cb *_Nonnull tcp_oob_callback, void *_Nonnull object);

/** @brief Encode tcp_connections_number as a custom ip_port.
 *
 * return ip_port.
 */
IP_Port tcp_connections_number_to_ip_port(unsigned int tcp_connections_number);

/** @brief Decode ip_port created by tcp_connections_number_to_ip_port to tcp_connections_number.
 *
 * return true on success.
 * return false if ip_port is invalid.
 */
bool ip_port_to_tcp_connections_number(const IP_Port *_Nonnull ip_port, unsigned int *_Nonnull tcp_connections_number);

/** @brief Create a new TCP connection to public_key.
 *
 * public_key must be the counterpart to the secret key that the other peer used with `new_tcp_connections()`.
 *
 * id is the id in the callbacks for that connection.
 *
 * return connections_number on success.
 * return -1 on failure.
 */
int new_tcp_connection_to(TCP_Connections *_Nonnull tcp_c, const uint8_t *_Nonnull public_key, int id);

/**
 * @retval 0 on success.
 * @retval -1 on failure.
 */
int kill_tcp_connection_to(TCP_Connections *_Nonnull tcp_c, int connections_number);

/** @brief Set connection status.
 *
 * status of 1 means we are using the connection.
 * status of 0 means we are not using it.
 *
 * Unused tcp connections will be disconnected from but kept in case they are needed.
 *
 * return 0 on success.
 * return -1 on failure.
 */
int set_tcp_connection_to_status(const TCP_Connections *_Nonnull tcp_c, int connections_number, bool status);

/**
 * @return number of online tcp relays tied to the connection on success.
 * @retval 0 on failure.
 */
uint32_t tcp_connection_to_online_tcp_relays(const TCP_Connections *_Nonnull tcp_c, int connections_number);

/** @brief Add a TCP relay tied to a connection.
 *
 * NOTE: This can only be used during the tcp_oob_callback.
 *
 * return 0 on success.
 * return -1 on failure.
 */
int add_tcp_number_relay_connection(const TCP_Connections *_Nonnull tcp_c, int connections_number, unsigned int tcp_connections_number);

/** @brief Add a TCP relay tied to a connection.
 *
 * This should be called with the same relay by two peers who want to create a TCP connection with each other.
 *
 * return 0 on success.
 * return -1 on failure.
 */
int add_tcp_relay_connection(TCP_Connections *_Nonnull tcp_c, int connections_number, const IP_Port *_Nonnull ip_port, const uint8_t *_Nonnull relay_pk);

/** @brief Add a TCP relay to the TCP_Connections instance.
 *
 * return 0 on success.
 * return -1 on failure.
 */
int add_tcp_relay_global(TCP_Connections *_Nonnull tcp_c, const IP_Port *_Nonnull ip_port, const uint8_t *_Nonnull relay_pk);

/** @brief Copy a maximum of max_num TCP relays we are connected to to tcp_relays.
 *
 * NOTE that the family of the copied ip ports will be set to TCP_INET or TCP_INET6.
 *
 * return number of relays copied to tcp_relays on success.
 * return 0 on failure.
 */
uint32_t tcp_copy_connected_relays(const TCP_Connections *_Nonnull tcp_c, Node_format *_Nonnull tcp_relays, uint16_t max_num);

/** @brief Copy a maximum of `max_num` TCP relays we are connected to starting at idx.
 *
 * @param idx is the index in the TCP relay array for `tcp_c` designated.
 *   If idx is greater than the array length a modulo operation is performed.
 *
 * Returns the number of relays successfully copied.
 */
uint32_t tcp_copy_connected_relays_index(const TCP_Connections *_Nonnull tcp_c, Node_format *_Nonnull tcp_relays, uint16_t max_num, uint32_t idx);

/** @brief Returns a new TCP_Connections object associated with the secret_key.
 *
 * In order for others to connect to this instance `new_tcp_connection_to()` must be called with the
 * public_key associated with secret_key.
 *
 * Returns NULL on failure.
 */
TCP_Connections *_Nullable new_tcp_connections(const Logger *_Nonnull logger, const Memory *_Nonnull mem, const Random *_Nonnull rng, const Network *_Nonnull ns, Mono_Time *_Nonnull mono_time,
        const uint8_t *_Nonnull secret_key, const TCP_Proxy_Info *_Nonnull proxy_info, Net_Profile *_Nonnull tcp_np);

int kill_tcp_relay_connection(TCP_Connections *_Nonnull tcp_c, int tcp_connections_number);

void do_tcp_connections(const Logger *_Nonnull logger, TCP_Connections *_Nonnull tcp_c, void *_Nullable userdata);
void kill_tcp_connections(TCP_Connections *_Nullable tcp_c);
#endif /* C_TOXCORE_TOXCORE_TCP_CONNECTION_H */
