/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2019-2021 The TokTok team.
 */
#ifndef C_TOXCORE_TOXCORE_TIMED_AUTH_H
#define C_TOXCORE_TOXCORE_TIMED_AUTH_H

#include "crypto_core.h"
#include "mono_time.h"

#define TIMED_AUTH_SIZE CRYPTO_HMAC_SIZE

/* Put timed authentication code of data in timed_auth. */
void generate_timed_auth(const Mono_Time *mono_time, uint16_t timeout, const uint8_t *key,
                                const uint8_t *data, uint16_t length, uint8_t *timed_auth);

/* Check timed_auth. This succeeds if timed_auth was generated by
 * generate_timed_auth at most timeout seconds ago, and fails if at least
 * `2*timeout` seconds ago.
 *
 * return true on success, false otherwise.
 */
bool check_timed_auth(const Mono_Time *mono_time, uint16_t timeout, const uint8_t *key, const uint8_t *data,
                             uint16_t length, const uint8_t *timed_auth);
#endif
