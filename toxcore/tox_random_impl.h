/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2022-2025 The TokTok team.
 */

#ifndef C_TOXCORE_TOXCORE_TOX_RANDOM_IMPL_H
#define C_TOXCORE_TOXCORE_TOX_RANDOM_IMPL_H

#include "tox_memory.h"
#include "tox_random.h"

#ifdef __cplusplus
extern "C" {
#endif

/** @brief Fill a byte array with random bytes.
 *
 * This is the key generator callback and as such must be a cryptographically
 * secure pseudo-random number generator (CSPRNG). The security of Tox heavily
 * depends on the security of this RNG.
 */
typedef void tox_random_bytes_cb(void *self, uint8_t *bytes, uint32_t length);

/** @brief Generate a random integer between 0 and @p upper_bound.
 *
 * Should produce a uniform random distribution, but Tox security does not
 * depend on this being correct. In principle, it could even be a non-CSPRNG.
 */
typedef uint32_t tox_random_uniform_cb(void *self, uint32_t upper_bound);

/** @brief Virtual function table for Random. */
struct Tox_Random_Funcs {
    tox_random_bytes_cb *bytes_callback;
    tox_random_uniform_cb *uniform_callback;
};

/** @brief Random number generator object.
 *
 * Can be used by test code and fuzzers to make toxcore behave in specific
 * well-defined (non-random) ways. Production code ought to use libsodium's
 * CSPRNG and use `os_random` below.
 */
struct Tox_Random {
    const Tox_Random_Funcs *funcs;
    void *user_data;

    const Tox_Memory *mem;
};

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* C_TOXCORE_TOXCORE_TOX_RANDOM_IMPL_H */
