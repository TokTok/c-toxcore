/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2022-2023 The TokTok team.
 */

#ifndef C_TOXCORE_TOXCORE_TOX_SYSTEM_IMPL_H
#define C_TOXCORE_TOXCORE_TOX_SYSTEM_IMPL_H

#include "tox_log.h"
#include "tox_memory.h"
#include "tox_network.h"
#include "tox_random.h"
#include "tox_system.h"
#include "tox_time.h"

#ifdef __cplusplus
extern "C" {
#endif

struct Tox_System {
    const Tox_Log *log;
    const Tox_Memory *mem;
    const Tox_Network *ns;
    const Tox_Random *rng;
    const Tox_Time *tm;
};

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* C_TOXCORE_TOXCORE_TOX_SYSTEM_IMPL_H */
