/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2025 The TokTok team.
 * Copyright © 2014 Tox project.
 */

/**
 * Connection to friends.
 */
#ifndef C_TOXCORE_TOXCORE_FRIEND_CONNECTION_H
#define C_TOXCORE_TOXCORE_FRIEND_CONNECTION_H

#include <stdint.h>

#include "DHT.h"
#include "attributes.h"
#include "logger.h"
#include "mem.h"
#include "mono_time.h"
#include "net_crypto.h"
#include "network.h"
#include "onion_client.h"

#define MAX_FRIEND_CONNECTION_CALLBACKS 2
#define MESSENGER_CALLBACK_INDEX 0
#define GROUPCHAT_CALLBACK_INDEX 1

#define PACKET_ID_ALIVE 16
#define PACKET_ID_SHARE_RELAYS 17
#define PACKET_ID_FRIEND_REQUESTS 18

/** Interval between the sending of ping packets. */
#define FRIEND_PING_INTERVAL 8

/** If no packets are received from friend in this time interval, kill the connection. */
#define FRIEND_CONNECTION_TIMEOUT (FRIEND_PING_INTERVAL * 4)

/** Time before friend is removed from the DHT after last hearing about him. */
#define FRIEND_DHT_TIMEOUT BAD_NODE_TIMEOUT

#define FRIEND_MAX_STORED_TCP_RELAYS (MAX_FRIEND_TCP_CONNECTIONS * 4)

/** Max number of tcp relays sent to friends */
#define MAX_SHARED_RELAYS RECOMMENDED_FRIEND_TCP_CONNECTIONS

/** How often we share our TCP relays with each friend connection */
#define SHARE_RELAYS_INTERVAL (60 * 2)

typedef enum Friendconn_Status {
    FRIENDCONN_STATUS_NONE,
    FRIENDCONN_STATUS_CONNECTING,
    FRIENDCONN_STATUS_CONNECTED,
} Friendconn_Status;

typedef struct Friend_Connections Friend_Connections;

Net_Crypto *friendconn_net_crypto(non_null() const Friend_Connections *fr_c);

/** @return friendcon_id corresponding to the real public key on success.
 * @retval -1 on failure.
 */
int getfriend_conn_id_pk(non_null() const Friend_Connections *fr_c, non_null() const uint8_t *real_pk);

/** @brief Increases lock_count for the connection with friendcon_id by 1.
 *
 * @retval 0 on success.
 * @retval -1 on failure.
 */
int friend_connection_lock(non_null() const Friend_Connections *fr_c, int friendcon_id);

/**
 * @retval FRIENDCONN_STATUS_CONNECTED if the friend is connected.
 * @retval FRIENDCONN_STATUS_CONNECTING if the friend isn't connected.
 * @retval FRIENDCONN_STATUS_NONE on failure.
 */
unsigned int friend_con_connected(non_null() const Friend_Connections *fr_c, int friendcon_id);

/** @brief Copy public keys associated to friendcon_id.
 *
 * @retval 0 on success.
 * @retval -1 on failure.
 */
int get_friendcon_public_keys(nullable() uint8_t *real_pk, nullable() uint8_t *dht_temp_pk, non_null() const Friend_Connections *fr_c, int friendcon_id);
/** Set temp dht key for connection. */
void set_dht_temp_pk(non_null() Friend_Connections *fr_c, int friendcon_id, non_null() const uint8_t *dht_temp_pk, non_null() void *userdata);

typedef int global_status_cb(void *object, int friendcon_id, bool status, void *userdata);

typedef int fc_status_cb(void *object, int friendcon_id, bool status, void *userdata);
typedef int fc_data_cb(void *object, int friendcon_id, const uint8_t *data, uint16_t length, void *userdata);
typedef int fc_lossy_data_cb(void *object, int friendcon_id, const uint8_t *data, uint16_t length, void *userdata);

/** Set global status callback for friend connections. */
void set_global_status_callback(non_null() Friend_Connections *fr_c, nullable() global_status_cb *global_status_callback, nullable() void *object);
/** @brief Set the callbacks for the friend connection.
 * @param index is the index (0 to (MAX_FRIEND_CONNECTION_CALLBACKS - 1)) we
 *   want the callback to set in the array.
 *
 * @retval 0 on success.
 * @retval -1 on failure
 */
int friend_connection_callbacks(non_null() const Friend_Connections *fr_c, int friendcon_id, unsigned int index,
                                nullable() fc_status_cb *status_callback,
                                nullable() fc_data_cb *data_callback,
                                nullable() fc_lossy_data_cb *lossy_data_callback,
                                nullable() void *object, int number);
/** @brief return the crypt_connection_id for the connection.
 *
 * @return crypt_connection_id on success.
 * @retval -1 on failure.
 */
int friend_connection_crypt_connection_id(non_null() const Friend_Connections *fr_c, int friendcon_id);

/** @brief Create a new friend connection.
 * If one to that real public key already exists, increase lock count and return it.
 *
 * @retval -1 on failure.
 * @return connection id on success.
 */
int new_friend_connection(non_null() Friend_Connections *fr_c, non_null() const uint8_t *real_public_key);

/** @brief Kill a friend connection.
 *
 * @retval -1 on failure.
 * @retval 0 on success.
 */
int kill_friend_connection(non_null() Friend_Connections *fr_c, int friendcon_id);

/** @brief Send a Friend request packet.
 *
 * @retval -1 if failure.
 * @retval  0 if it sent the friend request directly to the friend.
 * @return the number of peers it was routed through if it did not send it directly.
 */
int send_friend_request_packet(non_null() Friend_Connections *fr_c, int friendcon_id, uint32_t nospam_num, non_null() const uint8_t *data, uint16_t length);

typedef int fr_request_cb(
    void *object, const uint8_t *source_pubkey, const uint8_t *data, uint16_t length, void *userdata);

/** @brief Set friend request callback.
 *
 * This function will be called every time a friend request packet is received.
 */
void set_friend_request_callback(non_null() Friend_Connections *fr_c, non_null() fr_request_cb *fr_request_callback, non_null() void *object);

/** Create new friend_connections instance. */
Friend_Connections *new_friend_connections(non_null() const Logger *logger, non_null() const Memory *mem, non_null() const Mono_Time *mono_time, non_null() const Network *ns,
        non_null() Onion_Client *onion_c, bool local_discovery_enabled);

/** main friend_connections loop. */
void do_friend_connections(non_null() Friend_Connections *fr_c, non_null() void *userdata);

/** Free everything related with friend_connections. */
void kill_friend_connections(nullable() Friend_Connections *fr_c);
typedef struct Friend_Conn Friend_Conn;

Friend_Conn *get_conn(non_null() const Friend_Connections *fr_c, int friendcon_id);
int friend_conn_get_onion_friendnum(non_null() const Friend_Conn *fc);
const IP_Port *friend_conn_get_dht_ip_port(non_null() const Friend_Conn *fc);

#endif /* C_TOXCORE_TOXCORE_FRIEND_CONNECTION_H */
