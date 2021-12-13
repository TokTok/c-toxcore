/* SPDX-License-Identifier: ISC
 * Copyright © 2016-2021 The TokTok team.
 */

#include "crypto_core.h"

#ifndef VANILLA_NACL
// We use libsodium by default.
#include <sodium.h>
#else
#include <string.h>
#endif


void crypto_memzero(void *data, size_t length)
{
#ifndef VANILLA_NACL
    sodium_memzero(data, length);
#else
    memset(data, 0, length);
#endif
}

bool crypto_memlock(void *data, size_t length)
{
#ifndef VANILLA_NACL

    if (sodium_mlock(data, length) != 0) {
        return false;
    }

    return true;
#else
    return false;
#endif
}

bool crypto_memunlock(void *data, size_t length)
{
#ifndef VANILLA_NACL

    if (sodium_munlock(data, length) != 0) {
        return false;
    }

    return true;
#else
    return false;
#endif
}

#ifndef VANILLA_NACL
/**
 * Locks `length` bytes of memory pointed to by `data`.
 *
 * Return 0 on success.
 * Return -1 on failure.
 */
int crypto_memlock(void *data, size_t length)
{
    if (sodium_mlock(data, length) != 0) {
        return -1;
    }

    return 0;
}

/**
 * Unlocks `length` bytes of memory pointed to by `data`.
 *
 * This function call has the side effect of zeroing the specified memory chunk
 * whether or not it succeeds.
 *
 * Return 0 on success.
 * Return -1 on failure.
 */
int crypto_memunlock(void *data, size_t length)
{
    if (sodium_munlock(data, length) != 0) {
        return -1;
    }

    return 0;
}
#endif  // VANILLA_NACL
