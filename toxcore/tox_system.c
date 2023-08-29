/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2022-2023 The TokTok team.
 */
#include "tox_system.h"

#include "ccompat.h"
#include "tox_system_impl.h"

Tox_System *tox_system_new(const Tox_Log *log, const Tox_Memory *mem, const Tox_Network *ns, const Tox_Random *rng, const Tox_Time *tm)
{
    Tox_System *sys = (Tox_System *)tox_memory_alloc(mem, sizeof(Tox_System));

    if (sys == nullptr) {
        return nullptr;
    }

    sys->log = log;
    sys->mem = mem;
    sys->ns = ns;
    sys->rng = rng;
    sys->tm = tm;

    return sys;
}

void tox_system_free(Tox_System *sys)
{
    if (sys == nullptr) {
        return;
    }
    tox_memory_dealloc(sys->mem, sys);
}
