/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2022-2023 The TokTok team.
 */
#include "tox_time.h"

#include "ccompat.h"
#include "tox_time_impl.h"

Tox_Time *tox_time_new(const Tox_Time_Funcs *funcs, void *user_data, const Tox_Memory *mem)
{
    Tox_Time *tm = (Tox_Time *)tox_memory_alloc(mem, sizeof(Tox_Time));

    if (tm == nullptr) {
        return nullptr;
    }

    tm->funcs = funcs;
    tm->user_data = user_data;

    tm->mem = mem;

    return tm;
}

void tox_time_free(Tox_Time *tm)
{
    if (tm == nullptr) {
        return;
    }
    tox_memory_dealloc(tm->mem, tm);
}

uint64_t tox_time_monotonic(const Tox_Time *tm)
{
    return tm->funcs->monotonic_callback(tm->user_data);
}
