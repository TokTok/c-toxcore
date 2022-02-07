/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2022 The TokTok team.
 */

#include "tox_unpack.h"

#include <msgpack.h>

#include "ccompat.h"

bool tox_unpack_u32(uint32_t *val, const msgpack_object *obj)
{
    if (obj->type != MSGPACK_OBJECT_POSITIVE_INTEGER || obj->via.u64 > UINT32_MAX) {
        return false;
    }

    *val = (uint32_t)obj->via.u64;
    return true;
}

bool tox_unpack_u64(uint64_t *val, const msgpack_object *obj)
{
    if (obj->type != MSGPACK_OBJECT_POSITIVE_INTEGER) {
        return false;
    }

    *val = obj->via.u64;
    return true;
}

bool tox_unpack_bin(uint8_t **data_ptr, size_t *data_length_ptr, const msgpack_object *obj)
{
    if (obj->type != MSGPACK_OBJECT_BIN) {
        return false;
    }

    const uint32_t data_length = obj->via.bin.size;
    uint8_t *const data = (uint8_t *)malloc(data_length);

    if (data == nullptr) {
        return false;
    }

    memcpy(data, obj->via.bin.ptr, data_length);

    *data_ptr = data;
    *data_length_ptr = data_length;
    return true;
}
