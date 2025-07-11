/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2025 The TokTok team.
 * Copyright © 2013 Tox project.
 */

#ifndef C_TOXCORE_TOXCORE_CRYPTO_CORE_PACK_H
#define C_TOXCORE_TOXCORE_CRYPTO_CORE_PACK_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "attributes.h"
#include "bin_pack.h"
#include "bin_unpack.h"
#include "crypto_core.h"

#ifdef __cplusplus
extern "C" {
#endif

bool pack_extended_public_key(non_null() const Extended_Public_Key *key, non_null() Bin_Pack *bp);
bool pack_extended_secret_key(non_null() const Extended_Secret_Key *key, non_null() Bin_Pack *bp);
bool unpack_extended_public_key(non_null() Extended_Public_Key *key, non_null() Bin_Unpack *bu);
bool unpack_extended_secret_key(non_null() Extended_Secret_Key *key, non_null() Bin_Unpack *bu);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* C_TOXCORE_TOXCORE_CRYPTO_CORE_PACK_H */
