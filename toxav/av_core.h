/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2026 The TokTok team.
 */

/** @file
 * @brief The A/V core: toxav.h without a Tox instance.
 *
 * The core implements the toxav.h functions that don't create, kill or
 * return a Tox instance. It reaches friends only through the functions in
 * Av_Core_Network, and the packets they send come in through
 * av_core_receive_packet. toxav_compat.c binds it to a Tox instance.
 */
#ifndef C_TOXCORE_TOXAV_AV_CORE_H
#define C_TOXCORE_TOXAV_AV_CORE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "toxav.h"

#include "../toxcore/logger.h"
#include "../toxcore/mem.h"
#include "../toxcore/mono_time.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Sends a packet to a friend.
 *
 * @param data The packet, starting with its packet ID.
 *
 * @return true if the packet was sent.
 */
typedef bool av_core_send_packet_cb(ToxAV *_Nonnull av, Tox_Friend_Number friend_number, const uint8_t *_Nonnull data, size_t length,
                                    void *_Nonnull user_data);

/** Tells whether a friend exists, or whether it's connected. */
typedef bool av_core_friend_query_cb(Tox_Friend_Number friend_number, void *_Nonnull user_data);

/** How the core reaches friends. */
typedef struct Av_Core_Network {
    av_core_send_packet_cb *_Nonnull send_lossy;
    av_core_send_packet_cb *_Nonnull send_lossless;
    av_core_friend_query_cb *_Nonnull friend_exists;
    av_core_friend_query_cb *_Nonnull friend_connected;
    void *_Nonnull user_data;
} Av_Core_Network;

/**
 * @brief Creates an A/V session.
 *
 * @param log Where the session logs. It must outlive the session.
 * @param current_time The monotonic clock, or NULL for the system's.
 *
 * @return NULL if memory allocation failed.
 */
ToxAV *_Nullable av_core_new(const Memory *_Nonnull mem, const Logger *_Nonnull log, mono_time_current_time_cb *_Nullable current_time,
                             void *_Nullable current_time_user_data, const Av_Core_Network *_Nonnull network);

/** @brief Ends all calls, like toxav_kill, and frees the session. */
void av_core_kill(ToxAV *_Nullable av);

/** @brief The user data the session passes to its network functions. */
void *_Nonnull av_core_network_user_data(const ToxAV *_Nonnull av);

/** @brief Handles a packet from a friend, starting with its packet ID. */
void av_core_receive_packet(ToxAV *_Nonnull av, Tox_Friend_Number friend_number, const uint8_t *_Nonnull data, size_t length);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* C_TOXCORE_TOXAV_AV_CORE_H */
