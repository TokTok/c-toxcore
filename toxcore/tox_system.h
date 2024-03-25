/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2022-2023 The TokTok team.
 */

#ifndef C_TOXCORE_TOXCORE_TOX_SYSTEM_H
#define C_TOXCORE_TOXCORE_TOX_SYSTEM_H

#include "tox_attributes.h"
#include "tox_log.h"
#include "tox_memory.h"
#include "tox_network.h"
#include "tox_random.h"
#include "tox_time.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Operating system functions used by Tox.
 *
 * This struct is opaque and generally shouldn't be used in clients, but in
 * combination with tox_private.h, it allows tests to inject non-IO (hermetic)
 * versions of low level network, RNG, and time keeping functions.
 */
typedef struct Tox_System Tox_System;

non_null()
Tox_System *tox_system_new(const Tox_Log *log, const Tox_Memory *mem, const Tox_Network *ns, const Tox_Random *rng, const Tox_Time *tm);

nullable(1)
void tox_system_free(Tox_System *sys);

non_null()
const Tox_Log *tox_system_get_log(const Tox_System *sys);

non_null()
const Tox_Memory *tox_system_get_memory(const Tox_System *sys);

non_null()
const Tox_Network *tox_system_get_network(const Tox_System *sys);

non_null()
const Tox_Random *tox_system_get_random(const Tox_System *sys);

non_null()
const Tox_Time *tox_system_get_time(const Tox_System *sys);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* C_TOXCORE_TOXCORE_TOX_SYSTEM_H */
