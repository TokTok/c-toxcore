/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2020-2021 The TokTok team.
 */

#ifndef C_TOXCORE_TOXCORE_ANNOUNCE_CLIENT_H
#define C_TOXCORE_TOXCORE_ANNOUNCE_CLIENT_H

#include "announce.h"
#include "forwarding.h"
#include "net_crypto.h"

typedef struct Announce_Client Announce_Client;

non_null(1, 2, 3) nullable(4)
Announce_Client *new_announce_client(Mono_Time *mono_time, Forwarding *forwarding,
                                     Net_Crypto *c, const Announcements *announcements);

/* Replaces any existing announce/search for this key. */
non_null()
bool add_announce(Announce_Client *announce_client,
                  const uint8_t *data_public_key, uint16_t width,
                  const uint8_t *data_secret_key, const uint8_t *data, uint16_t length);

typedef bool should_retrieve_cb(void *object, const uint8_t *hash);

/* Replaces any existing announce/search for this key. */
non_null(1, 2) nullable(4, 5, 7)
bool add_search(Announce_Client *announce_client,
                const uint8_t *data_public_key, uint16_t width,
                should_retrieve_cb *should_retrieve_callback,
                on_retrieve_cb *on_retrieve_callback,
                uint64_t search_started_time,
                void *callbacks_object);

non_null()
bool delete_search_or_announce(Announce_Client *announce_client, const uint8_t *data_public_key);

non_null()
void do_announce_client(Announce_Client *announce_client);

non_null()
void kill_announce_client(Announce_Client *announce_client);

#endif
