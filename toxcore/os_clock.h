/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2022-2026 The TokTok team.
 */

#ifndef C_TOXCORE_TOXCORE_OS_CLOCK_H
#define C_TOXCORE_TOXCORE_OS_CLOCK_H

#include "clock.h"

#ifdef __cplusplus
extern "C" {
#endif

extern const Clock os_clock_obj;

/** @brief System clock.
 *
 * Uses the system's high-resolution monotonic and real-time clocks.
 */
const Clock *_Nonnull os_clock(void);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* C_TOXCORE_TOXCORE_OS_CLOCK_H */
