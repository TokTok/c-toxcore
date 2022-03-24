/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2022 The TokTok team.
 */

#ifndef C_TOXCORE_TOXCORE_BIN_PACK_H
#define C_TOXCORE_TOXCORE_BIN_PACK_H

#include <stdbool.h>
#include <stdint.h>

#include "../third_party/cmp/cmp.h"
#include "attributes.h"

non_null() void bin_pack_array(cmp_ctx_t *ctx, size_t size);
non_null() void bin_pack_bool(cmp_ctx_t *ctx, bool val);
non_null() void bin_pack_u16(cmp_ctx_t *ctx, uint16_t val);
non_null() void bin_pack_u32(cmp_ctx_t *ctx, uint32_t val);
non_null() void bin_pack_u64(cmp_ctx_t *ctx, uint64_t val);
non_null() void bin_pack_bytes(cmp_ctx_t *ctx, const uint8_t *data, size_t length);

#endif // C_TOXCORE_TOXCORE_BIN_PACK_H
