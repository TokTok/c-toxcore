/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2022-2026 The TokTok team.
 */

#ifndef C_TOXCORE_TOXCORE_CLOCK_H
#define C_TOXCORE_TOXCORE_CLOCK_H

#include <stdint.h>

#include "attributes.h"

#ifdef __cplusplus
extern "C" {
#endif

/** @brief Return monotonic time in milliseconds. */
typedef uint64_t clock_monotonic_ms_cb(void *_Nullable self);

/** @brief Return real system time (Unix epoch) in milliseconds. */
typedef uint64_t clock_real_ms_cb(void *_Nullable self);

/** @brief Update the cached time (if applicable). */
typedef void clock_update_cb(void *_Nullable self);

/** @brief Virtual function table for Clock. */
typedef struct Clock_Funcs {
    clock_monotonic_ms_cb *_Nonnull monotonic_ms;
    clock_real_ms_cb *_Nonnull real_ms;
    clock_update_cb *_Nullable update;
} Clock_Funcs;

/** @brief Clock object. */
typedef struct Clock {
    const Clock_Funcs *_Nonnull funcs;
    void *_Nullable user_data;
} Clock;

/** @brief Return current monotonic time in milliseconds (ms). */
uint64_t clock_monotonic_ms(const Clock *_Nonnull clock);

/** @brief Return current monotonic time in seconds (s). */
uint64_t clock_monotonic_s(const Clock *_Nonnull clock);

/** @brief Return current real system time (Unix epoch) in milliseconds (ms). */
uint64_t clock_real_ms(const Clock *_Nonnull clock);

/** @brief Return current real system time (Unix epoch) in seconds (s). */
uint64_t clock_real_s(const Clock *_Nonnull clock);

/** @brief Return true iff timestamp is at least timeout seconds in the past. */
bool clock_is_timeout(const Clock *_Nonnull clock, uint64_t timestamp, uint64_t timeout);

/** @brief Update the clock; subsequent calls to clock_monotonic_ms or
 *  clock_real_ms will use the time at the call to clock_update (if the clock
 *  supports caching).
 */
void clock_update(Clock *_Nonnull clock);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* C_TOXCORE_TOXCORE_CLOCK_H */
