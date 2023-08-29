/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2022-2023 The TokTok team.
 */
#include "tox_random.h"

#include "ccompat.h"
#include "tox_random_impl.h"

Tox_Random *tox_random_new(const Tox_Random_Funcs *funcs, void *user_data, const Tox_Memory *mem)
{
    Tox_Random *rng = (Tox_Random *)tox_memory_alloc(mem, sizeof(Tox_Random));

    if (rng == nullptr) {
        return nullptr;
    }

    rng->funcs = funcs;
    rng->user_data = user_data;

    rng->mem = mem;

    return rng;
}

void tox_random_free(Tox_Random *rng)
{
    tox_memory_dealloc(rng->mem, rng);
}

void tox_random_bytes(const Tox_Random *rng, uint8_t *bytes, uint32_t length)
{
    rng->funcs->bytes_callback(rng->user_data, bytes, length);
}

uint32_t tox_random_uniform(const Tox_Random *rng, uint32_t upper_bound)
{
    return rng->funcs->uniform_callback(rng->user_data, upper_bound);
}
