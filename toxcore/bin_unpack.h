/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2022 The TokTok team.
 */

#ifndef C_TOXCORE_TOXCORE_BIN_UNPACK_H
#define C_TOXCORE_TOXCORE_BIN_UNPACK_H

#include <stdbool.h>
#include <stdint.h>

#include "attributes.h"

typedef struct Bin_Unpack Bin_Unpack;

non_null()
Bin_Unpack *bin_unpack_new(const uint8_t *buf, uint32_t buf_size);
nullable(1)
void bin_unpack_free(Bin_Unpack *bu);

non_null() bool bin_unpack_array(Bin_Unpack *bu, uint32_t *size);
non_null() bool bin_unpack_array_fixed(Bin_Unpack *bu, uint32_t min_size);
non_null() bool bin_unpack_bool(Bin_Unpack *bu, bool *val);
non_null() bool bin_unpack_u08(Bin_Unpack *bu, uint8_t *val);
non_null() bool bin_unpack_u16(Bin_Unpack *bu, uint16_t *val);
non_null() bool bin_unpack_u32(Bin_Unpack *bu, uint32_t *val);
non_null() bool bin_unpack_u64(Bin_Unpack *bu, uint64_t *val);
non_null() bool bin_unpack_bytes(Bin_Unpack *bu, uint8_t **data_ptr, uint32_t *data_length_ptr);
non_null() bool bin_unpack_bytes_fixed(Bin_Unpack *bu, uint8_t *data, uint32_t data_length);

#endif  // C_TOXCORE_TOXCORE_BIN_UNPACK_H
