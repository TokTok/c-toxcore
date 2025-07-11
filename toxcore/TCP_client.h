/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2025 The TokTok team.
 * Copyright © 2014 Tox project.
 */

/**
 * Implementation of the TCP relay client part of Tox.
 */
#ifndef C_TOXCORE_TOXCORE_TCP_CLIENT_H
#define C_TOXCORE_TOXCORE_TCP_CLIENT_H

#include "attributes.h"
#include "crypto_core.h"
#include "forwarding.h"
#include "logger.h"
#include "mem.h"
#include "mono_time.h"
#include "net_profile.h"
#include "network.h"

#define TCP_CONNECTION_TIMEOUT 10

typedef enum TCP_Proxy_Type {
    TCP_PROXY_NONE,
    TCP_PROXY_HTTP,
    TCP_PROXY_SOCKS5,
} TCP_Proxy_Type;

typedef struct TCP_Proxy_Info {
    IP_Port ip_port;
    uint8_t proxy_type; // a value from TCP_PROXY_TYPE
} TCP_Proxy_Info;

typedef enum TCP_Client_Status {
    TCP_CLIENT_NO_STATUS,
    TCP_CLIENT_PROXY_HTTP_CONNECTING,
    TCP_CLIENT_PROXY_SOCKS5_CONNECTING,
    TCP_CLIENT_PROXY_SOCKS5_UNCONFIRMED,
    TCP_CLIENT_CONNECTING,
    TCP_CLIENT_UNCONFIRMED,
    TCP_CLIENT_CONFIRMED,
    TCP_CLIENT_DISCONNECTED,
} TCP_Client_Status;

typedef struct TCP_Client_Connection TCP_Client_Connection;

const uint8_t *tcp_con_public_key(non_null() const TCP_Client_Connection *con);
IP_Port tcp_con_ip_port(non_null() const TCP_Client_Connection *con);
TCP_Client_Status tcp_con_status(non_null() const TCP_Client_Connection *con);

void *tcp_con_custom_object(non_null() const TCP_Client_Connection *con);
uint32_t tcp_con_custom_uint(non_null() const TCP_Client_Connection *con);
void tcp_con_set_custom_object(non_null() TCP_Client_Connection *con, non_null() void *object);
void tcp_con_set_custom_uint(non_null() TCP_Client_Connection *con, uint32_t value);

/** Create new TCP connection to ip_port/public_key */
TCP_Client_Connection *new_tcp_connection(
    non_null() const Logger *logger, non_null() const Memory *mem, non_null() const Mono_Time *mono_time, non_null() const Random *rng, non_null() const Network *ns,
    non_null() const IP_Port *ip_port, non_null() const uint8_t *public_key, non_null() const uint8_t *self_public_key, non_null() const uint8_t *self_secret_key,
    nullable() const TCP_Proxy_Info *proxy_info, nullable() Net_Profile *net_profile);
/** Run the TCP connection */
void do_tcp_connection(non_null() const Logger *logger, non_null() const Mono_Time *mono_time,
                       non_null() TCP_Client_Connection *tcp_connection, nullable() void *userdata);
/** Kill the TCP connection */
void kill_tcp_connection(nullable() TCP_Client_Connection *tcp_connection);
typedef int tcp_onion_response_cb(void *object, const uint8_t *data, uint16_t length, void *userdata);

/**
 * @retval 1 on success.
 * @retval 0 if could not send packet.
 * @retval -1 on failure (connection must be killed).
 */
int send_onion_request(non_null() const Logger *logger, non_null() TCP_Client_Connection *con, non_null() const uint8_t *data, uint16_t length);
void onion_response_handler(non_null() TCP_Client_Connection *con, non_null() tcp_onion_response_cb *onion_callback, non_null() void *object);

int send_forward_request_tcp(non_null() const Logger *logger, non_null() TCP_Client_Connection *con, non_null() const IP_Port *dest, non_null() const uint8_t *data, uint16_t length);
void forwarding_handler(non_null() TCP_Client_Connection *con, non_null() forwarded_response_cb *forwarded_response_callback, non_null() void *object);

typedef int tcp_routing_response_cb(void *object, uint8_t connection_id, const uint8_t *public_key);
typedef int tcp_routing_status_cb(void *object, uint32_t number, uint8_t connection_id, uint8_t status);

/**
 * @retval 1 on success.
 * @retval 0 if could not send packet.
 * @retval -1 on failure (connection must be killed).
 */
int send_routing_request(non_null() const Logger *logger, non_null() TCP_Client_Connection *con, non_null() const uint8_t *public_key);
void routing_response_handler(non_null() TCP_Client_Connection *con, non_null() tcp_routing_response_cb *response_callback, non_null() void *object);
void routing_status_handler(non_null() TCP_Client_Connection *con, non_null() tcp_routing_status_cb *status_callback, non_null() void *object);

/**
 * @retval 1 on success.
 * @retval 0 if could not send packet.
 * @retval -1 on failure (connection must be killed).
 */
int send_disconnect_request(non_null() const Logger *logger, non_null() TCP_Client_Connection *con, uint8_t con_id);

/** @brief Set the number that will be used as an argument in the callbacks related to con_id.
 *
 * When not set by this function, the number is -1.
 *
 * return 0 on success.
 * return -1 on failure.
 */
int set_tcp_connection_number(non_null() TCP_Client_Connection *con, uint8_t con_id, uint32_t number);

typedef int tcp_routing_data_cb(void *object, uint32_t number, uint8_t connection_id, const uint8_t *data,
                                uint16_t length, void *userdata);

/**
 * @retval 1 on success.
 * @retval 0 if could not send packet.
 * @retval -1 on failure.
 */
int send_data(non_null() const Logger *logger, non_null() TCP_Client_Connection *con, uint8_t con_id, non_null() const uint8_t *data, uint16_t length);
void routing_data_handler(non_null() TCP_Client_Connection *con, non_null() tcp_routing_data_cb *data_callback, non_null() void *object);

typedef int tcp_oob_data_cb(void *object, const uint8_t *public_key, const uint8_t *data, uint16_t length,
                            void *userdata);

/**
 * @retval 1 on success.
 * @retval 0 if could not send packet.
 * @retval -1 on failure.
 */
int send_oob_packet(non_null() const Logger *logger, non_null() TCP_Client_Connection *con, non_null() const uint8_t *public_key, non_null() const uint8_t *data, uint16_t length);
void oob_data_handler(non_null() TCP_Client_Connection *con, non_null() tcp_oob_data_cb *oob_data_callback, non_null() void *object);

#endif /* C_TOXCORE_TOXCORE_TCP_CLIENT_H */
