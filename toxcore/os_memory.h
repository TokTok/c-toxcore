/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2022-2025 The TokTok team.
 */

#ifndef C_TOXCORE_TOXCORE_OS_MEMORY_H
#define C_TOXCORE_TOXCORE_OS_MEMORY_H

#include "tox_memory.h"

#ifdef __cplusplus
extern "C" {
#endif

extern const Tox_Memory os_memory_obj;

const Tox_Memory *os_memory(void);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* C_TOXCORE_TOXCORE_OS_MEMORY_H */
