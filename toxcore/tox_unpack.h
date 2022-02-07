/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2022 The TokTok team.
 */

#ifndef C_TOXCORE_TOXCORE_TOX_UNPACK_H
#define C_TOXCORE_TOXCORE_TOX_UNPACK_H

#include <msgpack.h>
#include <stdint.h>

#include "tox.h"

bool tox_unpack_u32(uint32_t *val, const msgpack_object *obj);
bool tox_unpack_u64(uint64_t *val, const msgpack_object *obj);
bool tox_unpack_bin(uint8_t **data, size_t *data_length, const msgpack_object *obj);

bool tox_unpack_message_type(Tox_Message_Type *val, const msgpack_object *obj);

#endif  // C_TOXCORE_TOXCORE_TOX_UNPACK_H
