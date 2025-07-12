/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2022-2025 The TokTok team.
 */
#include "tox_system.h"

#include "ccompat.h"
#include "tox_memory.h"
#include "tox_system_impl.h"

Tox_System *tox_system_new(const struct Tox_Log *log, const struct Tox_Memory *mem, const struct Tox_Network *ns, const struct Tox_Random *rng, const struct Tox_Time *tm)
{
    Tox_System *sys = (Tox_System *)tox_memory_alloc(mem, sizeof(struct Tox_System));

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
    if (sys == nullptr || sys->mem == nullptr) {
        return;
    }
    tox_memory_dealloc(sys->mem, sys);
}

const struct Tox_Log *tox_system_get_log(const Tox_System *sys)
{
    return sys->log;
}

const struct Tox_Memory *tox_system_get_memory(const Tox_System *sys)
{
    return sys->mem;
}

const struct Tox_Network *tox_system_get_network(const Tox_System *sys)
{
    return sys->ns;
}

const struct Tox_Random *tox_system_get_random(const Tox_System *sys)
{
    return sys->rng;
}

const struct Tox_Time *tox_system_get_time(const Tox_System *sys)
{
    return sys->tm;
}
