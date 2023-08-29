/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2022-2023 The TokTok team.
 */

#ifndef C_TOXCORE_TOXCORE_OS_SYSTEM_H
#define C_TOXCORE_TOXCORE_OS_SYSTEM_H

#include "tox_system.h"
#include "tox_system_impl.h"

#ifdef __cplusplus
extern "C" {
#endif

/** @brief Default operating-system-backed `Tox_System`.
 *
 * Only `Tox_Time` does not have a subsystem here, and instead is created in
 * `mono_time`.
 *
 * This function, and by extension all the subsystem functions, does not
 * allocate any dynamic memory.
 */
const Tox_System *os_system(void);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* C_TOXCORE_TOXCORE_OS_SYSTEM_H */
