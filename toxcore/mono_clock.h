/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2022-2026 The TokTok team.
 */

#ifndef C_TOXCORE_TOXCORE_MONO_CLOCK_H
#define C_TOXCORE_TOXCORE_MONO_CLOCK_H

#include "clock.h"
#include "mem.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct Mono_Clock Mono_Clock;

/** @brief Create a new cached monotonic clock.
 *
 * If @p source_clock is NULL, the system clock (@ref os_clock) is used.
 */
Mono_Clock *_Nullable mono_clock_new(const Memory *_Nonnull mem, const Clock *_Nullable source_clock);

/** @brief Free a Mono_Clock instance. */
void mono_clock_free(const Memory *_Nonnull mem, Mono_Clock *_Nullable clock);

/** @brief Return the Clock interface for this Mono_Clock. */
const Clock *_Nonnull mono_clock_get_clock(const Mono_Clock *_Nonnull clock);

/** @brief Return the Clock interface for this Mono_Clock (non-const). */
Clock *_Nonnull mono_clock_get_clock_mutable(Mono_Clock *_Nonnull clock);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* C_TOXCORE_TOXCORE_MONO_CLOCK_H */
