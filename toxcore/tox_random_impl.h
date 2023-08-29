/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2022-2023 The TokTok team.
 */

#ifndef C_TOXCORE_TOXCORE_TOX_RANDOM_IMPL_H
#define C_TOXCORE_TOXCORE_TOX_RANDOM_IMPL_H

#include "tox_memory.h"
#include "tox_random.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef void tox_random_bytes_cb(void *self, uint8_t *bytes, uint32_t length);
typedef uint32_t tox_random_uniform_cb(void *self, uint32_t upper_bound);

struct Tox_Random_Funcs {
    tox_random_bytes_cb *bytes_callback;
    tox_random_uniform_cb *uniform_callback;
};

struct Tox_Random {
    const Tox_Random_Funcs *funcs;
    void *user_data;

    const Tox_Memory *mem;
};

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* C_TOXCORE_TOXCORE_TOX_RANDOM_IMPL_H */
