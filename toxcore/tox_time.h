/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2022-2023 The TokTok team.
 */

#ifndef C_TOXCORE_TOXCORE_TOX_TIME_H
#define C_TOXCORE_TOXCORE_TOX_TIME_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "tox_attributes.h"
#include "tox_memory.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct Tox_Time_Funcs Tox_Time_Funcs;

typedef struct Tox_Time Tox_Time;

tox_non_null(1, 3) tox_nullable(2)
Tox_Time *tox_time_new(const Tox_Time_Funcs *funcs, void *user_data, const Tox_Memory *mem);

tox_nullable(1)
void tox_time_free(Tox_Time *tm);

tox_non_null()
uint64_t tox_time_monotonic(const Tox_Time *tm);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* C_TOXCORE_TOXCORE_TOX_TIME_H */
