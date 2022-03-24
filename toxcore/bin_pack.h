/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2022 The TokTok team.
 */

#ifndef C_TOXCORE_TOXCORE_BIN_PACK_H
#define C_TOXCORE_TOXCORE_BIN_PACK_H

#include <stdbool.h>
#include <stdint.h>

#include "attributes.h"

typedef struct Bin_Pack Bin_Pack;

typedef void bin_pack_cb(Bin_Pack *bp, const void *obj);

non_null() void bin_pack_obj(bin_pack_cb *callback, const void *obj, uint8_t *buf, uint32_t buf_size);
non_null() uint32_t bin_pack_obj_size(bin_pack_cb *callback, const void *obj);

non_null() void bin_pack_array(Bin_Pack *bp, uint32_t size);
non_null() void bin_pack_bool(Bin_Pack *bp, bool val);
non_null() void bin_pack_u16(Bin_Pack *bp, uint16_t val);
non_null() void bin_pack_u32(Bin_Pack *bp, uint32_t val);
non_null() void bin_pack_u64(Bin_Pack *bp, uint64_t val);
non_null() void bin_pack_bytes(Bin_Pack *bp, const uint8_t *data, uint32_t length);

#endif // C_TOXCORE_TOXCORE_BIN_PACK_H
