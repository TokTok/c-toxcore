/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2023 The TokTok team.
 */

/**
 * Public Key set.
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

typedef struct Pk_Set Pk_Set;

non_null() Pk_Set *pk_set_new(const Memory *mem, uint16_t initial_capacity);
nullable(1) void pk_set_free(Pk_Set *pks);

non_null() bool pk_set_add(Pk_Set *pks, const uint8_t *pk);
non_null() bool pk_set_contains(Pk_Set *pks, const uint8_t *pk);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif // C_TOXCORE_TOXCORE_PK_SET_H
