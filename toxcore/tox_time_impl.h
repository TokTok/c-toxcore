/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2022-2023 The TokTok team.
 */

#ifndef C_TOXCORE_TOXCORE_TOX_TIME_IMPL_H
#define C_TOXCORE_TOXCORE_TOX_TIME_IMPL_H

#include "tox_memory.h"
#include "tox_time.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef uint64_t tox_time_monotonic_cb(void *self);

struct Tox_Time_Funcs {
    tox_time_monotonic_cb *monotonic_callback;
};

struct Tox_Time {
    const Tox_Time_Funcs *funcs;
    void *user_data;

    const Tox_Memory *mem;
};

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* C_TOXCORE_TOXCORE_TOX_TIME_IMPL_H */
