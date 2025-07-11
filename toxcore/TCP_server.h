/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2025 The TokTok team.
 * Copyright © 2014 Tox project.
 */

/**
 * Implementation of the TCP relay server part of Tox.
 */
#ifndef C_TOXCORE_TOXCORE_TCP_SERVER_H
#define C_TOXCORE_TOXCORE_TCP_SERVER_H

#include "attributes.h"
#include "crypto_core.h"
#include "forwarding.h"
#include "logger.h"
#include "mem.h"
#include "mono_time.h"
#include "net_profile.h"
#include "network.h"
#include "onion.h"

#define MAX_INCOMING_CONNECTIONS 256

#define TCP_MAX_BACKLOG MAX_INCOMING_CONNECTIONS

#define ARRAY_ENTRY_SIZE 6

typedef enum TCP_Status {
    TCP_STATUS_NO_STATUS,
    TCP_STATUS_CONNECTED,
    TCP_STATUS_UNCONFIRMED,
    TCP_STATUS_CONFIRMED,
} TCP_Status;

typedef struct TCP_Server TCP_Server;

const uint8_t *tcp_server_public_key(non_null() const TCP_Server *tcp_server);
size_t tcp_server_listen_count(non_null() const TCP_Server *tcp_server);

/** Create new TCP server instance. */
TCP_Server *new_tcp_server(non_null() const Logger *logger, non_null() const Memory *mem, non_null() const Random *rng, non_null() const Network *ns,
                           bool ipv6_enabled, uint16_t num_sockets, non_null() const uint16_t *ports,
                           non_null() const uint8_t *secret_key, nullable() Onion *onion, nullable() Forwarding *forwarding);
/** Run the TCP_server */
void do_tcp_server(non_null() TCP_Server *tcp_server, non_null() const Mono_Time *mono_time);

/** Kill the TCP server */
void kill_tcp_server(nullable() TCP_Server *tcp_server);
/** @brief Returns a pointer to the net profile associated with `tcp_server`.
 *
 * Returns null if `tcp_server` is null.
 */
const Net_Profile *tcp_server_get_net_profile(nullable() const TCP_Server *tcp_server);
#endif /* C_TOXCORE_TOXCORE_TCP_SERVER_H */
