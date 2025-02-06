/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2022-2025 The TokTok team.
 */

#ifndef C_TOXCORE_TOXCORE_OS_RANDOM_H
#define C_TOXCORE_TOXCORE_OS_RANDOM_H

#include "tox_random.h"

#ifdef __cplusplus
extern "C" {
#endif

extern const Tox_Random os_random_obj;

/** @brief System random number generator.
 *
 * Uses libsodium's CSPRNG (on Linux, `/dev/urandom`).
 */
const Tox_Random *os_random(void);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* C_TOXCORE_TOXCORE_OS_RANDOM_H */
