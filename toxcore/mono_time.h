/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2020 The TokTok team.
 * Copyright © 2014 Tox project.
 */
#ifndef C_TOXCORE_TOXCORE_MONO_TIME_H
#define C_TOXCORE_TOXCORE_MONO_TIME_H

#include <stdbool.h>
#include <stdint.h>

#include "attributes.h"
#include "mem.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * The timer portion of the toxcore event loop.
 *
 * We update the time exactly once per tox_iterate call. Programs built on lower
 * level APIs such as the DHT bootstrap node must update the time manually in
 * each iteration.
 *
 * Time is kept per Tox instance, not globally, even though "time" as a concept
 * is global. This is because by definition `mono_time` represents the time at
 * the start of an iteration, and also by definition the time when all network
 * events for the current iteration occurred. This affects mainly two situations:
 *
 * 1. Two timers started in the same iteration: e.g. two timers set to expire in
 *    10 seconds will both expire at the same time, i.e. about 10 seconds later.
 *    If the time were global, `mono_time` would be a random number that is
 *    either the time at the start of an iteration, or 1 second later (since the
 *    timer resolution is 1 second). This can happen when one update happens at
 *    e.g. 10:00:00.995 and a few milliseconds later a concurrently running
 *    instance updates the time at 10:00:01.005, making one timer expire a
 *    second after the other.
 * 2. One timer based on an event: if we want to encode a behaviour of a timer
 *    expiring e.g. 10 seconds after a network event occurred, we simply start a
 *    timer in the event handler. If a concurrent instance updates the time
 *    underneath us, it may instead expire 9 seconds after the event.
 *
 * Both these situations cause incorrect behaviour randomly. In practice,
 * toxcore is somewhat robust against strange timer behaviour, but the
 * implementation should at least theoretically match the specification.
 */
typedef struct Mono_Time Mono_Time;

typedef uint64_t mono_time_current_time_cb(void *_Nullable user_data);

Mono_Time *_Nullable mono_time_new(const Memory *_Nonnull mem, mono_time_current_time_cb *_Nullable current_time_callback, void *_Nullable user_data);
void mono_time_free(const Memory *_Nonnull mem, Mono_Time *_Nullable mono_time);
/**
 * Update mono_time; subsequent calls to mono_time_get or mono_time_is_timeout
 * will use the time at the call to mono_time_update.
 */
void mono_time_update(Mono_Time *_Nonnull mono_time);

/** @brief Return current monotonic time in milliseconds (ms).
 *
 * The starting point is UNIX epoch as measured by `time()` in `mono_time_new()`.
 */
uint64_t mono_time_get_ms(const Mono_Time *_Nonnull mono_time);

/** @brief Return a monotonically increasing time in seconds.
 *
 * The starting point is UNIX epoch as measured by `time()` in `mono_time_new()`.
 */
uint64_t mono_time_get(const Mono_Time *_Nonnull mono_time);

/**
 * Return true iff timestamp is at least timeout seconds in the past.
 */
bool mono_time_is_timeout(const Mono_Time *_Nonnull mono_time, uint64_t timestamp, uint64_t timeout);

/** @brief Return current monotonic time in milliseconds (ms).
 *
 * The starting point is unspecified and in particular is likely not comparable
 * to the return value of `mono_time_get_ms()`.
 */
uint64_t current_time_monotonic(const Mono_Time *_Nonnull mono_time);

/**
 * Override implementation of `current_time_monotonic()` (for tests).
 *
 * The caller is obligated to ensure that `current_time_monotonic()` continues
 * to increase monotonically.
 */
void mono_time_set_current_time_callback(Mono_Time *_Nonnull mono_time,
        mono_time_current_time_cb *_Nullable current_time_callback, void *_Nullable user_data);
#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* C_TOXCORE_TOXCORE_MONO_TIME_H */
