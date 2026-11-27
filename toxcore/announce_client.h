/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2020-2021 The TokTok team.
 */

#ifndef C_TOXCORE_TOXCORE_ANNOUNCE_CLIENT_H
#define C_TOXCORE_TOXCORE_ANNOUNCE_CLIENT_H

#include "DHT.h"
#include "announce.h"
#include "attributes.h"
#include "forwarding.h"
#include "logger.h"
#include "mem.h"
#include "mono_time.h"
#include "net_crypto.h"
#include "network.h"
#include "rng.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct Announce_Client Announce_Client;

Announce_Client *_Nullable new_announce_client(const Logger *_Nonnull log, const Memory *_Nonnull mem, const Random *_Nonnull rng,
        Mono_Time *_Nonnull mono_time, Forwarding *_Nonnull forwarding,
        DHT *_Nonnull dht, Networking_Core *_Nonnull net,
        Net_Crypto *_Nonnull c, const Announcements *_Nullable announcements);

/* Replaces any existing announce/search for this key. */
bool announce_client_add_announce(Announce_Client *_Nonnull announce_client,
                                  const uint8_t *_Nonnull data_public_key, uint16_t width,
                                  const uint8_t *_Nonnull data_secret_key, const uint8_t *_Nonnull data, uint16_t length);

typedef bool should_retrieve_cb(void *_Nullable object, const uint8_t *_Nonnull hash);

/* Replaces any existing announce/search for this key. */
bool announce_client_add_search(Announce_Client *_Nonnull announce_client,
                                const uint8_t *_Nonnull data_public_key, uint16_t width,
                                should_retrieve_cb *_Nullable should_retrieve_callback,
                                announce_on_retrieve_cb *_Nullable on_retrieve_callback,
                                uint64_t search_started_time,
                                void *_Nullable callbacks_object);

bool announce_client_delete(Announce_Client *_Nonnull announce_client, const uint8_t *_Nonnull data_public_key);

/**
 * Return true if the announcement for this key is stored on at least half of
 * the nodes of its lookup.
 */
bool announce_client_is_announced(const Announce_Client *_Nonnull announce_client, const uint8_t *_Nonnull data_public_key);

void do_announce_client(Announce_Client *_Nonnull announce_client);

void kill_announce_client(Announce_Client *_Nullable announce_client);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* C_TOXCORE_TOXCORE_ANNOUNCE_CLIENT_H */
