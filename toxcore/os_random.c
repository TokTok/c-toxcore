/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2022-2023 The TokTok team.
 */
#include "os_random.h"

#ifndef VANILLA_NACL
// We use libsodium by default.
#include <sodium.h>
#else
#include <randombytes.h>
#endif

#include "ccompat.h"
#include "tox_random_impl.h"

non_null()
static void os_random_bytes(void *self, uint8_t *bytes, uint32_t length)
{
    randombytes(bytes, length);
}

non_null()
static uint32_t os_random_uniform(void *self, uint32_t upper_bound)
{
#ifdef VANILLA_NACL
    if (upper_bound == 0) {
        return 0;
    }

    uint32_t randnum;
    os_random_bytes(self, (uint8_t *)&randnum, sizeof(randnum));
    return randnum % upper_bound;
#else
    return randombytes_uniform(upper_bound);
#endif
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
#endif
#ifndef VANILLA_NACL
    // It is safe to call this function more than once and from different
    // threads -- subsequent calls won't have any effects.
    if (sodium_init() == -1) {
        return nullptr;
    }
#endif
    return &os_random_obj;
}
