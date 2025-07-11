/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2025 The TokTok team.
 * Copyright © 2013 Tox project.
 */

/**
 * Implementation of the onion part of docs/Prevent_Tracking.txt
 */
#ifndef C_TOXCORE_TOXCORE_ONION_H
#define C_TOXCORE_TOXCORE_ONION_H

#include "DHT.h"
#include "attributes.h"
#include "crypto_core.h"
#include "logger.h"
#include "mem.h"
#include "mono_time.h"
#include "network.h"
#include "shared_key_cache.h"

typedef int onion_recv_1_cb(void *object, const IP_Port *dest, const uint8_t *data, uint16_t length);

typedef struct Onion {
    const Logger *log;
    const Mono_Time *mono_time;
    const Random *rng;
    const Memory *mem;
    DHT *dht;
    Networking_Core *net;
    uint8_t secret_symmetric_key[CRYPTO_SYMMETRIC_KEY_SIZE];
    uint64_t timestamp;

    Shared_Key_Cache *shared_keys_1;
    Shared_Key_Cache *shared_keys_2;
    Shared_Key_Cache *shared_keys_3;

    onion_recv_1_cb *recv_1_function;
    void *callback_object;
} Onion;

#define ONION_MAX_PACKET_SIZE 1400

#define ONION_RETURN_1 (CRYPTO_NONCE_SIZE + SIZE_IPPORT + CRYPTO_MAC_SIZE)
#define ONION_RETURN_2 (CRYPTO_NONCE_SIZE + SIZE_IPPORT + CRYPTO_MAC_SIZE + ONION_RETURN_1)
#define ONION_RETURN_3 (CRYPTO_NONCE_SIZE + SIZE_IPPORT + CRYPTO_MAC_SIZE + ONION_RETURN_2)

#define ONION_SEND_BASE (CRYPTO_PUBLIC_KEY_SIZE + SIZE_IPPORT + CRYPTO_MAC_SIZE)
#define ONION_SEND_3 (CRYPTO_NONCE_SIZE + ONION_SEND_BASE + ONION_RETURN_2)
#define ONION_SEND_2 (CRYPTO_NONCE_SIZE + ONION_SEND_BASE*2 + ONION_RETURN_1)
#define ONION_SEND_1 (CRYPTO_NONCE_SIZE + ONION_SEND_BASE*3)

#define ONION_MAX_DATA_SIZE (ONION_MAX_PACKET_SIZE - (ONION_SEND_1 + 1))
#define ONION_RESPONSE_MAX_DATA_SIZE (ONION_MAX_PACKET_SIZE - (1 + ONION_RETURN_3))

#define ONION_PATH_LENGTH 3

typedef struct Onion_Path {
    uint8_t shared_key1[CRYPTO_SHARED_KEY_SIZE];
    uint8_t shared_key2[CRYPTO_SHARED_KEY_SIZE];
    uint8_t shared_key3[CRYPTO_SHARED_KEY_SIZE];

    uint8_t public_key1[CRYPTO_PUBLIC_KEY_SIZE];
    uint8_t public_key2[CRYPTO_PUBLIC_KEY_SIZE];
    uint8_t public_key3[CRYPTO_PUBLIC_KEY_SIZE];

    IP_Port     ip_port1;
    uint8_t     node_public_key1[CRYPTO_PUBLIC_KEY_SIZE];

    IP_Port     ip_port2;
    uint8_t     node_public_key2[CRYPTO_PUBLIC_KEY_SIZE];

    IP_Port     ip_port3;
    uint8_t     node_public_key3[CRYPTO_PUBLIC_KEY_SIZE];

    uint32_t path_num;
} Onion_Path;

/** @brief Create a new onion path.
 *
 * Create a new onion path out of nodes (nodes is a list of ONION_PATH_LENGTH nodes)
 *
 * new_path must be an empty memory location of at least Onion_Path size.
 *
 * return -1 on failure.
 * return 0 on success.
 */
int create_onion_path(non_null() const Random *rng, non_null() const DHT *dht, non_null() Onion_Path *new_path, non_null() const Node_format *nodes);

/** @brief Dump nodes in onion path to nodes of length num_nodes.
 *
 * return -1 on failure.
 * return 0 on success.
 */
int onion_path_to_nodes(non_null() Node_format *nodes, unsigned int num_nodes, non_null() const Onion_Path *path);

/** @brief Create a onion packet.
 *
 * Use Onion_Path path to create packet for data of length to dest.
 * Maximum length of data is ONION_MAX_DATA_SIZE.
 * packet should be at least ONION_MAX_PACKET_SIZE big.
 *
 * return -1 on failure.
 * return length of created packet on success.
 */
int create_onion_packet(non_null() const Memory *mem, non_null() const Random *rng, non_null() uint8_t *packet, uint16_t max_packet_length, non_null() const Onion_Path *path,
                        non_null() const IP_Port *dest, non_null() const uint8_t *data, uint16_t length);

/** @brief Create a onion packet to be sent over tcp.
 *
 * Use Onion_Path path to create packet for data of length to dest.
 * Maximum length of data is ONION_MAX_DATA_SIZE.
 * packet should be at least ONION_MAX_PACKET_SIZE big.
 *
 * return -1 on failure.
 * return length of created packet on success.
 */
int create_onion_packet_tcp(non_null() const Memory *mem, non_null() const Random *rng, non_null() uint8_t *packet, uint16_t max_packet_length, non_null() const Onion_Path *path,
                            non_null() const IP_Port *dest, non_null() const uint8_t *data, uint16_t length);

/** @brief Create and send a onion response sent initially to dest with.
 * Maximum length of data is ONION_RESPONSE_MAX_DATA_SIZE.
 *
 * return -1 on failure.
 * return 0 on success.
 */
int send_onion_response(non_null() const Logger *log, non_null() const Networking_Core *net, non_null() const IP_Port *dest, non_null() const uint8_t *data, uint16_t length,
                        non_null() const uint8_t *ret);

/** @brief Function to handle/send received decrypted versions of the packet created by create_onion_packet.
 *
 * return 0 on success.
 * return 1 on failure.
 *
 * Used to handle these packets that are received in a non traditional way (by TCP for example).
 *
 * Source family must be set to something else than TOX_AF_INET6 or TOX_AF_INET so that the callback gets called
 * when the response is received.
 */
int onion_send_1(non_null() const Onion *onion, non_null() const uint8_t *plain, uint16_t len, non_null() const IP_Port *source, non_null() const uint8_t *nonce);

/** Set the callback to be called when the dest ip_port doesn't have TOX_AF_INET6 or TOX_AF_INET as the family. */
void set_callback_handle_recv_1(non_null() Onion *onion, nullable() onion_recv_1_cb *function, nullable() void *object);
Onion *new_onion(non_null() const Logger *log, non_null() const Memory *mem, non_null() const Mono_Time *mono_time, non_null() const Random *rng, non_null() DHT *dht);

void kill_onion(nullable() Onion *onion);
#endif /* C_TOXCORE_TOXCORE_ONION_H */
