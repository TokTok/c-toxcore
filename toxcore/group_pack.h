/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2020 The TokTok team.
 * Copyright © 2015 Tox project.
 */

/**
 * Packer and unpacker functions for saving and loading groups.
 */

#ifndef C_TOXCORE_TOXCORE_GROUP_PACK_H
#define C_TOXCORE_TOXCORE_GROUP_PACK_H

#include <stdbool.h>

#include "attributes.h"
#include "bin_pack.h"
#include "bin_unpack.h"
#include "group_common.h"

/**
 * Packs group data from `chat` into `mp` in binary format. Parallel to the
 * `gc_load_unpack_group` function.
 */
void gc_save_pack_group(non_null() const GC_Chat *chat, non_null() Bin_Pack *bp);

/**
 * Unpacks binary group data from `obj` into `chat`. Parallel to the `gc_save_pack_group`
 * function.
 *
 * Return true if unpacking is successful.
 */
bool gc_load_unpack_group(non_null() GC_Chat *chat, non_null() Bin_Unpack *bu);

bool group_privacy_state_from_int(uint8_t value, non_null() Group_Privacy_State *out_enum);
bool group_voice_state_from_int(uint8_t value, non_null() Group_Voice_State *out_enum);

#endif /* C_TOXCORE_TOXCORE_GROUP_PACK_H */
