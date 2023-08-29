/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2022-2023 The TokTok team.
 */

#ifndef C_TOXCORE_TOXCORE_TOX_SYSTEM_H
#define C_TOXCORE_TOXCORE_TOX_SYSTEM_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "tox_memory.h"
#include "tox_network.h"
#include "tox_random.h"
#include "tox_time.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct Tox_System Tox_System;

Tox_System *tox_system_new(const Tox_Memory *mem, const Tox_Network *ns, const Tox_Random *rng, const Tox_Time *tm);
void tox_system_free(Tox_System *sys);

#ifdef __cplusplus
}
#endif

#endif // C_TOXCORE_TOXCORE_TOX_SYSTEM_H
