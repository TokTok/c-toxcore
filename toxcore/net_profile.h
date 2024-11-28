/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2023-2024 The TokTok team.
 */

/**
 * Functions for the network profile.
 */
#ifndef C_TOXCORE_TOXCORE_NET_PROFILE_H
#define C_TOXCORE_TOXCORE_NET_PROFILE_H

#include <stddef.h>
#include <stdint.h>

#include "attributes.h"
#include "logger.h"
#include "mem.h"

/* The max number of packet ID's (must fit inside one byte) */
#define NET_PROF_MAX_PACKET_IDS 256

/* If passed to a netprof function as a nullptr the function will have no effect. */
typedef struct Net_Profile Net_Profile;

/** Specifies whether the query is for sent or received packets. */
typedef enum Packet_Direction {
    PACKET_DIRECTION_SEND,
    PACKET_DIRECTION_RECV,
} Packet_Direction;

/**
 * Records a sent or received packet of type `id` and size `length` to the given profile.
 */
nullable(1)
void netprof_record_packet(Net_Profile *profile, uint8_t id, size_t length, Packet_Direction dir);

/**
 * Returns the number of sent or received packets of type `id` for the given profile.
 */
nullable(1)
uint64_t netprof_get_packet_count_id(const Net_Profile *profile, uint8_t id, Packet_Direction dir);

/**
 * Returns the total number of sent or received packets for the given profile.
 */
nullable(1)
uint64_t netprof_get_packet_count_total(const Net_Profile *profile, Packet_Direction dir);

/**
 * Returns the number of bytes sent or received of packet type `id` for the given profile.
 */
nullable(1)
uint64_t netprof_get_bytes_id(const Net_Profile *profile, uint8_t id, Packet_Direction dir);

/**
 * Returns the total number of bytes sent or received for the given profile.
 */
nullable(1)
uint64_t netprof_get_bytes_total(const Net_Profile *profile, Packet_Direction dir);

/**
 * Returns a new net_profile object. The caller is responsible for freeing the
 * returned memory via `netprof_kill`.
 */
non_null()
Net_Profile *netprof_new(const Logger *log, const Memory *mem);

/**
 * Kills a net_profile object and frees all associated memory.
 */
non_null(1) nullable(2)
void netprof_kill(const Memory *mem, Net_Profile *net_profile);

#endif  /* C_TOXCORE_TOXCORE_NET_PROFILE_H */
