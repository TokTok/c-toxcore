/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2022-2023 The TokTok team.
 */
#include "os_system.h"

#include "ccompat.h"
#include "os_logger.h"
#include "os_memory.h"
#include "os_network.h"
#include "os_random.h"
#include "tox_system_impl.h"

Tox_System os_system(const Tox_Logger *log, const Tox_Memory *mem, const Tox_Network *ns, const Tox_Random *rng, const Tox_Time *tm)
{
    const Tox_System sys = {
        log != nullptr ? log : os_logger(),
        mem != nullptr ? mem : os_memory(),
        ns != nullptr ? ns : os_network(),
        rng != nullptr ? rng : os_random(),
        tm, // no os_time, mono_time has it.
    };

    return sys;
}
