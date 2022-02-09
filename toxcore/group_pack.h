/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2020 The TokTok team.
 * Copyright © 2015 Tox project.
 */

/**
 * Packer and unpacker functions for saving and loading groups.
 */

#ifndef GROUP_PACK_H
#define GROUP_PACK_H

#include <msgpack.h>
#include <stdbool.h>

#include "group_common.h"

/**
 * Packs group data from `chat` into `mp` in binary format. Parallel to the
 * `gc_load_unpack_group` function.
 */
void gc_save_pack_group(const GC_Chat *chat, msgpack_packer *mp);

/**
 * Unpacks binary group data from `obj` into `chat`. Parallel to the `gc_save_pack_group`
 * function.
 *
 * Return true if unpacking is successful.
 */
bool gc_load_unpack_group(GC_Chat *chat, const msgpack_object *obj);

#endif // GROUP_PACK_H
