/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2022-2023 The TokTok team.
 */

#ifndef C_TOXCORE_TOXCORE_TOX_SYSTEM_IMPL_H
#define C_TOXCORE_TOXCORE_TOX_SYSTEM_IMPL_H

#include "tox_system.h"

#ifdef __cplusplus
extern "C" {
#endif

struct Tox_System {
    const Tox_Logger *log;
    const Tox_Memory *mem;
    const Tox_Network *ns;
    const Tox_Random *rng;
    const Tox_Time *tm;
};

#ifdef __cplusplus
}
#endif

#endif // C_TOXCORE_TOXCORE_TOX_SYSTEM_IMPL_H
