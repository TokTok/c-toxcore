/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2020-2025 The TokTok team.
 */

#ifndef C_TOXCORE_TOXCORE_ANNOUNCE_H
#define C_TOXCORE_TOXCORE_ANNOUNCE_H

#include <stdint.h>

#include "attributes.h"
#include "crypto_core.h"
#include "forwarding.h"
#include "logger.h"
#include "mem.h"
#include "mono_time.h"

#define MAX_ANNOUNCEMENT_SIZE 512

typedef void announce_on_retrieve_cb(void *object, const uint8_t *data, uint16_t length);

uint8_t announce_response_of_request_type(uint8_t request_type);

typedef struct Announcements Announcements;

Announcements *new_announcements(non_null() const Logger *log, non_null() const Memory *mem, non_null() const Random *rng, non_null() const Mono_Time *mono_time, non_null() Forwarding *forwarding);

/**
 * @brief If data is stored, run `on_retrieve_callback` on it.
 *
 * @return true if data is stored, false otherwise.
 */
bool announce_on_stored(non_null() const Announcements *announce, non_null() const uint8_t *data_public_key,
                        nullable() announce_on_retrieve_cb *on_retrieve_callback, nullable() void *object);
void announce_set_synch_offset(non_null() Announcements *announce, int32_t synch_offset);

void kill_announcements(nullable() Announcements *announce);
/* The declarations below are not public, they are exposed only for tests. */

/** @private
 * Return xor of first ANNOUNCE_BUCKET_PREFIX_LENGTH bits from one bit after
 * base and pk first differ
 */
uint16_t announce_get_bucketnum(non_null() const uint8_t *base, non_null() const uint8_t *pk);

/** @private */
bool announce_store_data(non_null() Announcements *announce, non_null() const uint8_t *data_public_key,
                         nullable() const uint8_t *data, uint32_t length, uint32_t timeout);
/** @private */
#define MAX_MAX_ANNOUNCEMENT_TIMEOUT 900
#define MIN_MAX_ANNOUNCEMENT_TIMEOUT 10
#define MAX_ANNOUNCEMENT_TIMEOUT_UPTIME_RATIO 4

/** @private
 * For efficient lookup and updating, entries are stored as a hash table keyed
 * to the first ANNOUNCE_BUCKET_PREFIX_LENGTH bits starting from one bit after
 * the first bit in which data public key first differs from the dht key, with
 * (2-adically) closest keys preferentially stored within a given bucket. A
 * given key appears at most once (even if timed out).
 */
#define ANNOUNCE_BUCKET_SIZE 8
#define ANNOUNCE_BUCKET_PREFIX_LENGTH 5
#define ANNOUNCE_BUCKETS 32 // ANNOUNCE_BUCKETS = 2 ** ANNOUNCE_BUCKET_PREFIX_LENGTH

#endif /* C_TOXCORE_TOXCORE_ANNOUNCE_H */
