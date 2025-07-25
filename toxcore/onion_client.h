/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2025 The TokTok team.
 * Copyright © 2013 Tox project.
 */

/**
 * Implementation of the client part of docs/Prevent_Tracking.txt (The part that
 * uses the onion stuff to connect to the friend)
 */
#ifndef C_TOXCORE_TOXCORE_ONION_CLIENT_H
#define C_TOXCORE_TOXCORE_ONION_CLIENT_H

#include <stdbool.h>

#include "DHT.h"
#include "attributes.h"
#include "crypto_core.h"
#include "logger.h"
#include "mem.h"
#include "mono_time.h"
#include "net_crypto.h"
#include "network.h"
#include "onion_announce.h"
#include "ping_array.h"

#define MAX_ONION_CLIENTS 8
#define MAX_ONION_CLIENTS_ANNOUNCE 12 // Number of nodes to announce ourselves to.
#define ONION_NODE_PING_INTERVAL 15
#define ONION_NODE_TIMEOUT ONION_NODE_PING_INTERVAL

/** The interval in seconds at which to tell our friends where we are */
#define ONION_DHTPK_SEND_INTERVAL 30
#define DHT_DHTPK_SEND_INTERVAL 20

#define NUMBER_ONION_PATHS 6

/**
 * The timeout the first time the path is added and
 * then for all the next consecutive times
 */
#define ONION_PATH_FIRST_TIMEOUT 4
#define ONION_PATH_TIMEOUT 10
#define ONION_PATH_MAX_LIFETIME 1200
#define ONION_PATH_MAX_NO_RESPONSE_USES 4

#define MAX_STORED_PINGED_NODES 9
#define MIN_NODE_PING_TIME 10

#define ONION_NODE_MAX_PINGS 3

#define MAX_PATH_NODES 32

#define GCA_MAX_DATA_LENGTH GCA_PUBLIC_ANNOUNCE_MAX_SIZE

/**
 * If no announce response packets are received within this interval tox will
 * be considered offline. We give time for a node to be pinged often enough
 * that it times out, which leads to the network being thoroughly tested as it
 * is replaced.
 */
#define ONION_OFFLINE_TIMEOUT (ONION_NODE_PING_INTERVAL * (ONION_NODE_MAX_PINGS+2))

/** Onion data packet ids. */
#define ONION_DATA_FRIEND_REQ CRYPTO_PACKET_FRIEND_REQ
#define ONION_DATA_DHTPK CRYPTO_PACKET_DHTPK

typedef struct Onion_Client Onion_Client;

DHT *_Nonnull onion_get_dht(const Onion_Client *_Nonnull onion_c);
Net_Crypto *_Nonnull onion_get_net_crypto(const Onion_Client *_Nonnull onion_c);

/** @brief Add a node to the path_nodes bootstrap array.
 *
 * If a node with the given public key was already in the bootstrap array, this function has no
 * effect and returns successfully. There is currently no way to update the IP/port for a bootstrap
 * node, so if it changes, the Onion_Client must be recreated.
 *
 * @param onion_c The onion client object.
 * @param ip_port IP/port for the bootstrap node.
 * @param public_key DHT public key for the bootstrap node.
 *
 * @retval false on failure
 * @retval true on success
 */
bool onion_add_bs_path_node(Onion_Client *_Nonnull onion_c, const IP_Port *_Nonnull ip_port, const uint8_t *_Nonnull public_key);

/** @brief Put up to max_num nodes in nodes.
 *
 * return the number of nodes.
 */
uint16_t onion_backup_nodes(const Onion_Client *_Nonnull onion_c, Node_format *_Nonnull nodes, uint16_t max_num);

/** @brief Get the friend_num of a friend.
 *
 * return -1 on failure.
 * return friend number on success.
 */
int onion_friend_num(const Onion_Client *_Nonnull onion_c, const uint8_t *_Nonnull public_key);

/** @brief Add a friend who we want to connect to.
 *
 * return -1 on failure.
 * return the friend number on success or if the friend was already added.
 */
int onion_addfriend(Onion_Client *_Nonnull onion_c, const uint8_t *_Nonnull public_key);

/** @brief Delete a friend.
 *
 * return -1 on failure.
 * return the deleted friend number on success.
 */
int onion_delfriend(Onion_Client *_Nonnull onion_c, int friend_num);

/** @brief Set if friend is online or not.
 *
 * NOTE: This function is there and should be used so that we don't send
 * useless packets to the friend if they are online.
 *
 * return -1 on failure.
 * return 0 on success.
 */
int onion_set_friend_online(Onion_Client *_Nonnull onion_c, int friend_num, bool is_online);

/** @brief Get the ip of friend friendnum and put it in ip_port
 *
 * @retval -1 if public_key does NOT refer to a friend
 * @retval  0 if public_key refers to a friend and we failed to find the friend (yet)
 * @retval  1 if public_key refers to a friend and we found them
 */
int onion_getfriendip(const Onion_Client *_Nonnull onion_c, int friend_num, IP_Port *_Nonnull ip_port);

typedef int recv_tcp_relay_cb(void *_Nonnull object, uint32_t number, const IP_Port *_Nonnull ip_port, const uint8_t *_Nonnull public_key);

/** @brief Set the function for this friend that will be callbacked with object and number
 * when that friend gives us one of the TCP relays they are connected to.
 *
 * object and number will be passed as argument to this function.
 *
 * return -1 on failure.
 * return 0 on success.
 */
int recv_tcp_relay_handler(Onion_Client *_Nonnull onion_c, int friend_num, recv_tcp_relay_cb *_Nonnull callback, void *_Nonnull object, uint32_t number);

typedef void onion_dht_pk_cb(void *_Nonnull object, int32_t number, const uint8_t *_Nonnull dht_public_key, void *_Nullable userdata);

/** @brief Set the function for this friend that will be callbacked with object and number
 * when that friend gives us their DHT temporary public key.
 *
 * object and number will be passed as argument to this function.
 *
 * return -1 on failure.
 * return 0 on success.
 */
int onion_dht_pk_callback(Onion_Client *_Nonnull onion_c, int friend_num, onion_dht_pk_cb *_Nonnull function, void *_Nonnull object, uint32_t number);

/** @brief Set a friend's DHT public key.
 *
 * return -1 on failure.
 * return 0 on success.
 */
int onion_set_friend_dht_pubkey(Onion_Client *_Nonnull onion_c, int friend_num, const uint8_t *_Nonnull dht_key);

/** @brief Copy friends DHT public key into dht_key.
 *
 * return 0 on failure (no key copied).
 * return 1 on success (key copied).
 */
unsigned int onion_getfriend_dht_pubkey(const Onion_Client *_Nonnull onion_c, int friend_num, uint8_t *_Nonnull dht_key);

#define ONION_DATA_IN_RESPONSE_MIN_SIZE (CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_MAC_SIZE)

// TODO(Jfreegman): This is not the correct value; data this large will be dropped by the onion client.
#define ONION_CLIENT_MAX_DATA_SIZE (MAX_DATA_REQUEST_SIZE - ONION_DATA_IN_RESPONSE_MIN_SIZE)

/** @brief Send data of length length to friendnum.
 * Maximum length of data is ONION_CLIENT_MAX_DATA_SIZE.
 * This data will be received by the friend using the Onion_Data_Handlers callbacks.
 *
 * Even if this function succeeds, the friend might not receive any data.
 *
 * return the number of packets sent on success
 * return -1 on failure.
 */
int send_onion_data(Onion_Client *_Nonnull onion_c, int friend_num, const uint8_t *_Nonnull data, uint16_t length);

typedef int oniondata_handler_cb(void *_Nullable object, const uint8_t *_Nonnull source_pubkey, const uint8_t *_Nonnull data,
                                 uint16_t length, void *_Nullable userdata);

/** Function to call when onion data packet with contents beginning with byte is received. */
void oniondata_registerhandler(Onion_Client *_Nonnull onion_c, uint8_t byte, oniondata_handler_cb *_Nullable cb, void *_Nullable object);
typedef bool onion_group_announce_cb(Onion_Client *_Nonnull onion_c, uint32_t sendback_num, const uint8_t *_Nonnull data,
                                     size_t data_length, void *_Nullable user_data);

/** Function to call when the onion gets a group announce response. */
void onion_group_announce_register(Onion_Client *_Nonnull onion_c, onion_group_announce_cb *_Nullable func, void *_Nullable user_data);
void do_onion_client(Onion_Client *_Nonnull onion_c);

Onion_Client *_Nullable new_onion_client(const Logger *_Nonnull logger, const Memory *_Nonnull mem, const Random *_Nonnull rng, const Mono_Time *_Nonnull mono_time, Net_Crypto *_Nonnull c);

void kill_onion_client(Onion_Client *_Nullable onion_c);
typedef enum Onion_Connection_Status {
    /** We are not connected to the network. */
    ONION_CONNECTION_STATUS_NONE = 0,
    /** We are connected with TCP only. */
    ONION_CONNECTION_STATUS_TCP = 1,
    /** We are also connected with UDP. */
    ONION_CONNECTION_STATUS_UDP = 2,
} Onion_Connection_Status;

Onion_Connection_Status onion_connection_status(const Onion_Client *_Nonnull onion_c);

typedef struct Onion_Friend Onion_Friend;

uint16_t onion_get_friend_count(const Onion_Client *_Nonnull onion_c);
Onion_Friend *_Nullable onion_get_friend(const Onion_Client *_Nonnull onion_c, uint16_t friend_num);
const uint8_t *_Nullable onion_friend_get_gc_public_key(const Onion_Friend *_Nonnull onion_friend);
const uint8_t *_Nullable onion_friend_get_gc_public_key_num(const Onion_Client *_Nonnull onion_c, uint32_t num);
void onion_friend_set_gc_public_key(Onion_Friend *_Nonnull onion_friend, const uint8_t *_Nonnull public_key);
void onion_friend_set_gc_data(Onion_Friend *_Nonnull onion_friend, const uint8_t *_Nullable gc_data, uint16_t gc_data_length);
bool onion_friend_is_groupchat(const Onion_Friend *_Nonnull onion_friend);

#endif /* C_TOXCORE_TOXCORE_ONION_CLIENT_H */
