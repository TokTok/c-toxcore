/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2022-2025 The TokTok team.
 */
#include "os_random.h"

#include <sodium.h>

#include "attributes.h"
#include "ccompat.h"
#include "tox_random.h"
#include "tox_random_impl.h"

non_null()
static void os_random_bytes(void *self, uint8_t *bytes, uint32_t length)
{
    randombytes(bytes, length);
}

non_null()
static uint32_t os_random_uniform(void *self, uint32_t upper_bound)
{
    return randombytes_uniform(upper_bound);
}

static const Tox_Random_Funcs os_random_funcs = {
    os_random_bytes,
    os_random_uniform,
};

const Tox_Random os_random_obj = {&os_random_funcs};

const Tox_Random *os_random(void)
{
#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
    if ((true)) {
        return nullptr;
    }
#endif /* FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION */
    // It is safe to call this function more than once and from different
    // threads -- subsequent calls won't have any effects.
    if (sodium_init() == -1) {
        return nullptr;
    }
    return &os_random_obj;
}
