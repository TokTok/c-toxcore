/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2022 The TokTok team.
 */

#include "bin_pack.h"

void bin_pack_array(cmp_ctx_t *ctx, size_t size)
{
    cmp_write_array(ctx, size);
}

void bin_pack_bool(cmp_ctx_t *ctx, bool val)
{
    cmp_write_bool(ctx, val);
}

void bin_pack_u16(cmp_ctx_t *ctx, uint16_t val)
{
    cmp_write_u16(ctx, val);
}

void bin_pack_u32(cmp_ctx_t *ctx, uint32_t val)
{
    cmp_write_u32(ctx, val);
}

void bin_pack_u64(cmp_ctx_t *ctx, uint64_t val)
{
    cmp_write_u64(ctx, val);
}

void bin_pack_bytes(cmp_ctx_t *ctx, const uint8_t *data, size_t length)
{
    cmp_write_bin(ctx, data, length);
}
