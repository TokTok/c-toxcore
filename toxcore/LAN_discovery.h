/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2025 The TokTok team.
 * Copyright © 2013 Tox project.
 */

/**
 * LAN discovery implementation.
 */
#ifndef C_TOXCORE_TOXCORE_LAN_DISCOVERY_H
#define C_TOXCORE_TOXCORE_LAN_DISCOVERY_H

#include "attributes.h"
#include "mem.h"
#include "network.h"

/**
 * Interval in seconds between LAN discovery packet sending.
 */
#define LAN_DISCOVERY_INTERVAL         10

typedef struct Broadcast_Info Broadcast_Info;

/**
 * Send a LAN discovery pcaket to the broadcast address with port port.
 *
 * @return true on success, false on failure.
 */
bool lan_discovery_send(non_null() const Networking_Core *net, non_null() const Broadcast_Info *broadcast, non_null() const uint8_t *dht_pk, uint16_t port);

/**
 * Discovers broadcast devices and IP addresses.
 */
Broadcast_Info *lan_discovery_init(non_null() const Memory *mem, non_null() const Network *ns);

/**
 * Free all resources associated with the broadcast info.
 */
void lan_discovery_kill(nullable() Broadcast_Info *broadcast);
/**
 * Is IP a local ip or not.
 */
bool ip_is_local(non_null() const IP *ip);

/**
 * Checks if a given IP isn't routable.
 *
 * @return true if ip is a LAN ip, false if it is not.
 */
bool ip_is_lan(non_null() const IP *ip);

#endif /* C_TOXCORE_TOXCORE_LAN_DISCOVERY_H */
