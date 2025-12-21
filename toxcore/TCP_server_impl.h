#ifndef C_TOXCORE_TOXCORE_TCP_SERVER_IMPL_H
#define C_TOXCORE_TOXCORE_TCP_SERVER_IMPL_H

#include "TCP_server.h"
#include "network.h"
#include "mono_time.h"
#include "TCP_common.h"
#include "list.h"
#include "forwarding.h"
#include "onion.h"

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
} TCP_Secure_Connection;

typedef struct TCP_Secure_Connection TCP_Secure_Connection;

struct TCP_Server {
    const Logger *logger;
    const Memory *mem;
    const Random *rng;
    const Network *ns;
    Onion *onion;
    Forwarding *forwarding;

#ifdef TCP_SERVER_USE_EPOLL
    int efd;
    uint64_t last_run_pinged;
#endif /* TCP_SERVER_USE_EPOLL */
    Socket *socks_listening;
    unsigned int num_listening_socks;

    uint8_t public_key[CRYPTO_PUBLIC_KEY_SIZE];
    uint8_t secret_key[CRYPTO_SECRET_KEY_SIZE];
    TCP_Secure_Connection incoming_connection_queue[MAX_INCOMING_CONNECTIONS];
    uint16_t incoming_connection_queue_index;
    TCP_Secure_Connection unconfirmed_connection_queue[MAX_INCOMING_CONNECTIONS];
    uint16_t unconfirmed_connection_queue_index;

    TCP_Secure_Connection *accepted_connection_array;
    uint32_t size_accepted_connections;
    uint32_t num_accepted_connections;

    uint64_t counter;

    BS_List accepted_key_list;

    /* Network profile for all TCP server packets. */
    Net_Profile *net_profile;
};

/* FOR TESTING ONLY */

int handle_onion_recv_1(void *_Nonnull object, const IP_Port *_Nonnull dest, const uint8_t *_Nonnull data, uint16_t length);
int kill_accepted(TCP_Server *tcp_server, int index);
int add_accepted(TCP_Server *tcp_server, const Mono_Time *mono_time, TCP_Secure_Connection *con);

#endif /* C_TOXCORE_TOXCORE_TCP_SERVER_IMPL_H */
