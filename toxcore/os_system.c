/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2022-2023 The TokTok team.
 */
#include "os_system.h"

#include "ccompat.h"
#include "os_log.h"
#include "os_memory.h"
#include "os_network.h"
#include "os_random.h"
#include "tox_system.h"
#include "tox_system_impl.h"

static const Tox_System os_system_obj = {
    &os_log_obj,
    &os_memory_obj,
    &os_network_obj,
    &os_random_obj,
    nullptr,
};

const Tox_System *os_system(void)
{
    const Tox_System *sys = &os_system_obj;

    if (sys->log != os_log()
            || sys->mem != os_memory()
            || sys->ns != os_network()
            || sys->rng != os_random()) {
        return nullptr;
    }

    return sys;
}
