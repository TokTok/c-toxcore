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
 * If any of the parameters are NULL, they are set to the OS instance of that
 * subsystem. Only `Tox_Time` does not have a subsystem here, and instead is
 * created in `mono_time`.
 *
 * This function, and by extension all the subsystem functions, does not
 * allocate any dynamic memory.
 */
nullable(1, 2, 3, 4, 5)
Tox_System os_system(const Tox_Log *log, const Tox_Memory *mem, const Tox_Network *ns, const Tox_Random *rng, const Tox_Time *tm);

#ifdef __cplusplus
}
#endif

#endif // C_TOXCORE_TOXCORE_OS_SYSTEM_H
