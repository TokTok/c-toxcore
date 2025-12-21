/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2025 The TokTok team.
 * Copyright © 2013 Tox project.
 */

#ifndef C_TOXCORE_TOXCORE_NET_CRYPTO_IMPL_H
#define C_TOXCORE_TOXCORE_NET_CRYPTO_IMPL_H

#include "net_crypto.h"

#include "DHT.h"
#include "TCP_client.h"
#include "TCP_connection.h"
#include "attributes.h"
#include "crypto_core.h"
#include "list.h"
#include "logger.h"
#include "mem.h"
#include "mono_time.h"
#include "net_profile.h"
#include "network.h"

typedef struct Packet_Data {
    uint64_t sent_time;
    uint16_t length;
    uint8_t data[MAX_CRYPTO_DATA_SIZE];
} Packet_Data;

typedef struct Packets_Array {
    Packet_Data *buffer[CRYPTO_PACKET_BUFFER_SIZE];
    uint32_t  buffer_start;
    uint32_t  buffer_end; /* packet numbers in array: `{buffer_start, buffer_end)` */
} Packets_Array;

typedef enum Crypto_Conn_State {
    /* the connection slot is free. This value is 0 so it is valid after
     * `crypto_memzero(...)` of the parent struct
     */
    CRYPTO_CONN_FREE = 0,
    CRYPTO_CONN_NO_CONNECTION,       /* the connection is allocated, but not yet used */
    CRYPTO_CONN_COOKIE_REQUESTING,   /* we are sending cookie request packets */
    CRYPTO_CONN_HANDSHAKE_SENT,      /* we are sending handshake packets */
    /* we are sending handshake packets.
     * we have received one from the other, but no data */
    CRYPTO_CONN_NOT_CONFIRMED,
    CRYPTO_CONN_ESTABLISHED,         /* the connection is established */
} Crypto_Conn_State;

typedef struct Crypto_Connection {
    uint8_t public_key[CRYPTO_PUBLIC_KEY_SIZE]; /* The real public key of the peer. */
    uint8_t recv_nonce[CRYPTO_NONCE_SIZE]; /* Nonce of received packets. */
    uint8_t sent_nonce[CRYPTO_NONCE_SIZE]; /* Nonce of sent packets. */
    uint8_t sessionpublic_key[CRYPTO_PUBLIC_KEY_SIZE]; /* Our public key for this session. */
    uint8_t sessionsecret_key[CRYPTO_SECRET_KEY_SIZE]; /* Our private key for this session. */
    uint8_t peersessionpublic_key[CRYPTO_PUBLIC_KEY_SIZE]; /* The public key of the peer. */
    uint8_t shared_key[CRYPTO_SHARED_KEY_SIZE]; /* The precomputed shared key from encrypt_precompute. */
    Crypto_Conn_State status; /* See Crypto_Conn_State documentation */
    uint64_t cookie_request_number; /* number used in the cookie request packets for this connection */
    uint8_t dht_public_key[CRYPTO_PUBLIC_KEY_SIZE]; /* The dht public key of the peer */

    uint8_t *temp_packet; /* Where the cookie request/handshake packet is stored while it is being sent. */
    uint16_t temp_packet_length;
    uint64_t temp_packet_sent_time; /* The time at which the last temp_packet was sent in ms. */
    uint32_t temp_packet_num_sent;

    IP_Port ip_portv4; /* The ip and port to contact this guy directly.*/
    IP_Port ip_portv6;
    uint64_t direct_lastrecv_timev4; /* The Time at which we last received a direct packet in ms. */
    uint64_t direct_lastrecv_timev6;

    uint64_t last_tcp_sent; /* Time the last TCP packet was sent. */

    Packets_Array send_array;
    Packets_Array recv_array;

    connection_status_cb *connection_status_callback;
    void *connection_status_callback_object;
    int connection_status_callback_id;

    connection_data_cb *connection_data_callback;
    void *connection_data_callback_object;
    int connection_data_callback_id;

    connection_lossy_data_cb *connection_lossy_data_callback;
    void *connection_lossy_data_callback_object;
    int connection_lossy_data_callback_id;

    uint64_t last_request_packet_sent;
    uint64_t direct_send_attempt_time;

    uint32_t packet_counter;
    double packet_recv_rate;
    uint64_t packet_counter_set;

    double packet_send_rate;
    uint32_t packets_left;
    uint64_t last_packets_left_set;
    double last_packets_left_rem;

    double packet_send_rate_requested;
    uint32_t packets_left_requested;
    uint64_t last_packets_left_requested_set;
    double last_packets_left_requested_rem;

    uint32_t last_sendqueue_size[CONGESTION_QUEUE_ARRAY_SIZE];
    uint32_t last_sendqueue_counter;
    long signed int last_num_packets_sent[CONGESTION_LAST_SENT_ARRAY_SIZE];
    long signed int last_num_packets_resent[CONGESTION_LAST_SENT_ARRAY_SIZE];
    uint32_t packets_sent;
    uint32_t packets_resent;
    uint64_t last_congestion_event;
    uint64_t rtt_time;

    /* TCP_connection connection_number */
    unsigned int connection_number_tcp;

    bool maximum_speed_reached;

    dht_pk_cb *dht_pk_callback;
    void *dht_pk_callback_object;
    uint32_t dht_pk_callback_number;
} Crypto_Connection;

struct Net_Crypto {
    const Logger *log;
    const Memory *mem;
    const Random *rng;
    Mono_Time *mono_time;
    const Network *ns;
    Networking_Core *net;

    DHT *dht;
    TCP_Connections *tcp_c;

    Crypto_Connection *crypto_connections;

    uint32_t crypto_connections_length; /* Length of connections array. */

    /* Our public and secret keys. */
    uint8_t self_public_key[CRYPTO_PUBLIC_KEY_SIZE];
    uint8_t self_secret_key[CRYPTO_SECRET_KEY_SIZE];

    /* The secret key used for cookies */
    uint8_t secret_symmetric_key[CRYPTO_SYMMETRIC_KEY_SIZE];

    new_connection_cb *new_connection_callback;
    void *new_connection_callback_object;

    /* The current optimal sleep time */
    uint32_t current_sleep_time;

    BS_List ip_port_list;
};

Crypto_Connection *get_crypto_connection(const Net_Crypto *_Nonnull c, int crypt_connection_id);
int handle_data_packet(const Net_Crypto *_Nonnull c, int crypt_connection_id, uint8_t *_Nonnull data, const uint8_t *_Nonnull packet, uint16_t length);

#endif /* C_TOXCORE_TOXCORE_NET_CRYPTO_IMPL_H */

