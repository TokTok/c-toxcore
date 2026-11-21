/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2026 The TokTok team.
 */

#ifndef C_TOXCORE_TOXCORE_OS_SECURE_MEMORY_H
#define C_TOXCORE_TOXCORE_OS_SECURE_MEMORY_H

#include "mem.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Memory allocator for secrets, based on `sodium_malloc`.
 *
 * Memory is locked (not swapped to disk) if the system allows it, surrounded
 * by guard pages, and zeroed when freed. Every allocation uses at least 4
 * pages. Reallocation is not supported.
 */
const Memory *_Nonnull os_secure_memory(void);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* C_TOXCORE_TOXCORE_OS_SECURE_MEMORY_H */
