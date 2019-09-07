/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2020-2021 The TokTok team.
 */

#ifndef C_TOXCORE_TOXCORE_ANNOUNCE_H
#define C_TOXCORE_TOXCORE_ANNOUNCE_H

#include "forwarding.h"

#define MAX_ANNOUNCEMENT_SIZE 512

typedef void on_retrieve_cb(void *object, const uint8_t *data, uint16_t length);

uint8_t response_of_request_type(uint8_t request_type);

typedef struct Announcements Announcements;

non_null()
Announcements *new_announcements(const Logger *log, Mono_Time *mono_time, Forwarding *forwarding);

/* If data is stored, run `on_retrieve_callback` on it.
 * Return true if data is stored, false otherwise.
 */
non_null(1, 2, 3) nullable(4)
bool on_stored(const Announcements *announce, const uint8_t *data_public_key,
               on_retrieve_cb on_retrieve_callback, void *object);

non_null()
void set_synch_offset(Announcements *announce, int32_t synch_offset);

non_null()
void kill_announcements(Announcements *announce);

#endif
