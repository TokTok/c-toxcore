/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2022-2023 The TokTok team.
 */

#ifndef C_TOXCORE_TOXCORE_TOX_RANDOM_H
#define C_TOXCORE_TOXCORE_TOX_RANDOM_H

#include <stdbool.h>
#include <stdint.h>

#include "tox_memory.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct Tox_Random_Funcs Tox_Random_Funcs;

typedef struct Tox_Random Tox_Random;

non_null(1, 3) nullable(2)
Tox_Random *tox_random_new(const Tox_Random_Funcs *funcs, void *user_data, const Tox_Memory *mem);

nullable(1) void tox_random_free(Tox_Random *rng);

non_null() void tox_random_bytes(const Tox_Random *rng, uint8_t *bytes, uint32_t length);
non_null() uint32_t tox_random_uniform(const Tox_Random *rng, uint32_t upper_bound);

#ifdef __cplusplus
}
#endif

#endif // C_TOXCORE_TOXCORE_TOX_RANDOM_H
