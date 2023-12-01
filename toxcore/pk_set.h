/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2023 The TokTok team.
 */

#ifndef C_TOXCORE_TOXCORE_PK_SET_H
#define C_TOXCORE_TOXCORE_PK_SET_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "attributes.h"
#include "mem.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Set of public keys.
 *
 * Can grow beyond the initial capacity if needed. Does not store the public
 * keys, but rather pointers to them, which means you must not store pointers
 * to keys you don't own the memory for over the lifetime of this object.
 *
 * Can only store up to 256 keys. After that, no keys are added.
 */
typedef struct Pk_Set Pk_Set;

/** @brief Create a new public key set. */
non_null() Pk_Set *pk_set_new(const Memory *mem, uint16_t initial_capacity);
/** @brief Free public key set and associated memory. */
nullable(1) void pk_set_free(Pk_Set *pks);

/** @brief Add a pointer to a public key to the set.
 *
 * Fails on allocation failure (if resize was needed). Use the `pk_set_contains`
 * function to distinguish this from the failure case of key already being in the set.
 *
 * @retval true if the key was added.
 * @retval false if either memory allocation failed or the key was already in the set.
 */
non_null() bool pk_set_add(Pk_Set *pks, const uint8_t *pk);

/** @brief Checks whether a key is already in the set.
 *
 * Note that this uses a linear search, which is fast enough for the small
 * sets we use this data structure for.
 */
non_null() bool pk_set_contains(Pk_Set *pks, const uint8_t *pk);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif // C_TOXCORE_TOXCORE_PK_SET_H
