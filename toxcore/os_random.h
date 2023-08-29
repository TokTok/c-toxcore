/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2022-2023 The TokTok team.
 */

#ifndef C_TOXCORE_TOXCORE_OS_RANDOM_H
#define C_TOXCORE_TOXCORE_OS_RANDOM_H

#include "tox_random.h"

#ifdef __cplusplus
extern "C" {
#endif

const Tox_Random *os_random(void);

#ifdef __cplusplus
}
#endif

#endif // C_TOXCORE_TOXCORE_OS_RANDOM_H
