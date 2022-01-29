/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2020 The TokTok team.
 * Copyright © 2013 Tox project.
 */

#ifndef C_TOXCORE_TOXCORE_TOX_PRIVATE_H
#define C_TOXCORE_TOXCORE_TOX_PRIVATE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "DHT.h"

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
 * :: DHT network queries.
 *
 ******************************************************************************/



typedef struct Tox_Dht_Node {
    void *data;
} Tox_Dht_Node;

/**
 * The minimum size of an IP string buffer in bytes.
 */
#define TOX_DHT_NODE_IP_STRING_SIZE      96

//!TOKSTYLE-
uint32_t tox_dht_node_ip_string_size(void);
//!TOKSTYLE+

/**
 * The size of a DHT node public key in bytes.
 */
#define TOX_DHT_NODE_PUBLIC_KEY_SIZE     32

//!TOKSTYLE-
uint32_t tox_dht_node_public_key_size(void);
//!TOKSTYLE+

/**
 * @param dht_node A node received from a get nodes response. This node must be
 *   freed by the caller using the tox_dht_node_free function.
 */
typedef void tox_dht_get_nodes_response_cb(Tox *tox, Tox_Dht_Node *dht_node, void *user_data);


/**
 * Set the callback for the `dht_get_nodes_response` event. Pass NULL to unset.
 *
 * This event is triggered when a get nodes response is received from a DHT peer.
 */
void tox_callback_dht_get_nodes_response(Tox *tox, tox_dht_get_nodes_response_cb *callback);


typedef enum Tox_Err_Dht_Get_Nodes {
    /**
     * The function returned successfully.
     */
    TOX_ERR_DHT_GET_NODES_OK,

    /**
     * One of the arguments to the function was NULL when it was not expected.
     */
    TOX_ERR_DHT_GET_NODES_NULL,

    /**
     * The get nodes request failed. This may occur if the packet failed to send
     * or the node contained invalid data.
     */
    TOX_ERR_DHT_GET_NODES_FAIL,
} Tox_Err_Dht_Get_Nodes;

/**
 * This function sends a get nodes request to a DHT node for its peers that
 * are "close" to the passed public key according to the distance metric used
 * by the DHT implementation.
 *
 * @param dest_node The node that we're sending the request to. This node must
 *   have been obtained from a `dht_get_nodes_response` event.
 * @param public_key The public key that we wish to query. This key must be
 *   at least `TOX_DHT_NODE_PUBLIC_KEY_SIZE` bytes in length.
 *
 * @return true on success.
 */
bool tox_dht_get_nodes(const Tox *tox, const Tox_Dht_Node *dest_node, const uint8_t *public_key,
                       Tox_Err_Dht_Get_Nodes *error);

/**
 * Return the port being used by a DHT node.
 *
 * @param dht_node The DHT node being queried. If this parameter is NULL, the
 *   function returns 0.
 */
uint16_t tox_dht_node_get_port(const Tox_Dht_Node *dht_node);

/**
 * Write a DHT node's public key to to a byte array.
 *
 * @param dht_node The DHT node being queried.
 * @param public_key The byte array being written to. This array must have room for
 *   at least TOX_DHT_NODE_PUBLIC_KEY_SIZE bytes.
 *
 * If either of these parameters are NULL, the function has no effect.
 */
void tox_dht_node_get_public_key(const Tox_Dht_Node *dht_node, uint8_t *public_key);

/**
 * Write a DHT node's IP address to a NULL terminated char array.
 *
 * @param dht_node The DHT node being queried. If this parameter is NULL, the
 *   function has no effect.
 * @param ip_str The char array being written to. This array must have room for
 *   at least TOX_DHT_NODE_IP_STRING_SIZE chars.
 *
 * @return the number of chars written to ip_str, not including the terminating
 *   NULL byte.
 */
size_t tox_dht_node_get_ip_string(const Tox_Dht_Node *dht_node, char *ip_str, size_t length);

/**
 * Frees all dynamically allocated memory associated a DHT node.
 *
 * @param dht_node The node being freed. If this parameter is NULL, the function
 *   has no effect.
 */
void tox_dht_node_free(Tox_Dht_Node *dht_node);

#ifdef __cplusplus
}
#endif

#endif // C_TOXCORE_TOXCORE_TOX_PRIVATE_H
