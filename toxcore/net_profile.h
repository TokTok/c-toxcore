/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2022 The TokTok team.
 */

/*
 * Functions for the network profile.
 */
#ifndef C_TOXCORE_TOXCORE_NET_PROFILE_H
#define C_TOXCORE_TOXCORE_NET_PROFILE_H

#include <stdint.h>
#include <stdlib.h>

#include "attributes.h"

/* The max number of packet ID's (should always be >= 256) */
#define NET_PROF_MAX_PACKET_IDS 256

typedef struct Net_Profile {
    uint64_t packets_recv[NET_PROF_MAX_PACKET_IDS];
    uint64_t packets_sent[NET_PROF_MAX_PACKET_IDS];

    uint64_t total_packets_recv;
    uint64_t total_packets_sent;

    uint64_t bytes_recv[NET_PROF_MAX_PACKET_IDS];
    uint64_t bytes_sent[NET_PROF_MAX_PACKET_IDS];

    uint64_t total_bytes_recv;
    uint64_t total_bytes_sent;
} Net_Profile;

/** Specifies whether the query is for sent or received packets. */
typedef enum Packet_Direction {
    DIR_SENT,
    DIR_RECV,
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

#endif  // C_TOXCORE_TOXCORE_NET_PROFILE_H
