/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2022 The TokTok team.
 */

#include "events_alloc.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "../bin_pack.h"
#include "../bin_unpack.h"
#include "../ccompat.h"
#include "../tox.h"
#include "../tox_events.h"
#include "../tox_private.h"
#include "event_macros.h"


/*****************************************************
 *
 * :: struct and accessors
 *
 *****************************************************/


struct Tox_Event_Friend_Name {
    uint32_t friend_number;
    uint8_t *name;
    uint32_t name_length;
};

EV_ACCESS_VALUE(Friend_Name, friend_name, uint32_t, friend_number)
EV_ACCESS_ARRAY(Friend_Name, friend_name, uint8_t, name)

non_null()
static void tox_event_friend_name_construct(Tox_Event_Friend_Name *friend_name)
{
    *friend_name = (Tox_Event_Friend_Name) {
        0
    };
}
non_null()
static void tox_event_friend_name_destruct(Tox_Event_Friend_Name *friend_name, const Memory *mem)
{
    mem_delete(mem, friend_name->name);
}

bool tox_event_friend_name_pack(
    const Tox_Event_Friend_Name *event, Bin_Pack *bp)
{
    assert(event != nullptr);
    return bin_pack_array(bp, 2)
           && bin_pack_u32(bp, TOX_EVENT_FRIEND_NAME)
           && bin_pack_array(bp, 2)
           && bin_pack_u32(bp, event->friend_number)
           && bin_pack_bin(bp, event->name, event->name_length);
}

non_null()
static bool tox_event_friend_name_unpack_into(
    Tox_Event_Friend_Name *event, Bin_Unpack *bu)
{
    assert(event != nullptr);
    if (!bin_unpack_array_fixed(bu, 2)) {
        return false;
    }

    return bin_unpack_u32(bu, &event->friend_number)
           && bin_unpack_bin(bu, &event->name, &event->name_length);
}

EV_FUNCS(Friend_Name, friend_name, FRIEND_NAME)


/*****************************************************
 *
 * :: event handler
 *
 *****************************************************/


void tox_events_handle_friend_name(Tox *tox, uint32_t friend_number, const uint8_t *name, size_t length,
                                   void *user_data)
{
    Tox_Event_Friend_Name *friend_name = tox_event_friend_name_alloc(user_data);

    if (friend_name == nullptr) {
        return;
    }

    const Tox_System *sys = tox_get_system(tox);

    tox_event_friend_name_set_friend_number(friend_name, friend_number);
    tox_event_friend_name_set_name(friend_name, name, length, sys->mem);
}
