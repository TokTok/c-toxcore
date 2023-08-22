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
#include "event_macros.h"


/*****************************************************
 *
 * :: struct and accessors
 *
 *****************************************************/


struct Tox_Event_Friend_Typing {
    uint32_t friend_number;
    bool typing;
};

EV_ACCESS_VALUE(Friend_Typing, friend_typing, uint32_t, friend_number)
EV_ACCESS_VALUE(Friend_Typing, friend_typing, bool, typing)

non_null()
static void tox_event_friend_typing_construct(Tox_Event_Friend_Typing *friend_typing)
{
    *friend_typing = (Tox_Event_Friend_Typing) {
        0
    };
}
non_null()
static void tox_event_friend_typing_destruct(Tox_Event_Friend_Typing *friend_typing, const Memory *mem)
{
    return;
}

bool tox_event_friend_typing_pack(
    const Tox_Event_Friend_Typing *event, Bin_Pack *bp)
{
    assert(event != nullptr);
    return bin_pack_array(bp, 2)
           && bin_pack_u32(bp, TOX_EVENT_FRIEND_TYPING)
           && bin_pack_array(bp, 2)
           && bin_pack_u32(bp, event->friend_number)
           && bin_pack_bool(bp, event->typing);
}

non_null()
static bool tox_event_friend_typing_unpack_into(
    Tox_Event_Friend_Typing *event, Bin_Unpack *bu)
{
    assert(event != nullptr);
    if (!bin_unpack_array_fixed(bu, 2)) {
        return false;
    }

    return bin_unpack_u32(bu, &event->friend_number)
           && bin_unpack_bool(bu, &event->typing);
}

EV_FUNCS(Friend_Typing, friend_typing, FRIEND_TYPING)


/*****************************************************
 *
 * :: event handler
 *
 *****************************************************/


void tox_events_handle_friend_typing(Tox *tox, uint32_t friend_number, bool typing, void *user_data)
{
    Tox_Event_Friend_Typing *friend_typing = tox_event_friend_typing_alloc(user_data);

    if (friend_typing == nullptr) {
        return;
    }

    tox_event_friend_typing_set_friend_number(friend_typing, friend_number);
    tox_event_friend_typing_set_typing(friend_typing, typing);
}
