/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2022-2023 The TokTok team.
 */

#ifndef C_TOXCORE_TOXCORE_OS_MEMORY_H
#define C_TOXCORE_TOXCORE_OS_MEMORY_H

#include "tox_memory.h"

#ifdef __cplusplus
extern "C" {
#endif

const Tox_Memory *os_memory(void);

#ifdef __cplusplus
}
#endif

#endif // C_TOXCORE_TOXCORE_OS_MEMORY_H
