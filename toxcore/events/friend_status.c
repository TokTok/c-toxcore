/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2022 The TokTok team.
 */

#include "events_alloc.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include "../bin_unpack.h"

#include "../bin_pack.h"
#include "../ccompat.h"
#include "../tox.h"
#include "../tox_events.h"
#include "../tox_unpack.h"
#include "event_macros.h"


/*****************************************************
 *
 * :: struct and accessors
 *
 *****************************************************/


struct Tox_Event_Friend_Status {
    uint32_t friend_number;
    Tox_User_Status status;
};

EV_ACCESS_VALUE(Friend_Status, friend_status, uint32_t, friend_number)
EV_ACCESS_VALUE(Friend_Status, friend_status, Tox_User_Status, status)

non_null()
static void tox_event_friend_status_construct(Tox_Event_Friend_Status *friend_status)
{
    *friend_status = (Tox_Event_Friend_Status) {
        0
    };
}
non_null()
static void tox_event_friend_status_destruct(Tox_Event_Friend_Status *friend_status, const Memory *mem)
{
    return;
}

bool tox_event_friend_status_pack(
    const Tox_Event_Friend_Status *event, Bin_Pack *bp)
{
    assert(event != nullptr);
    return bin_pack_array(bp, 2)
           && bin_pack_u32(bp, TOX_EVENT_FRIEND_STATUS)
           && bin_pack_array(bp, 2)
           && bin_pack_u32(bp, event->friend_number)
           && bin_pack_u32(bp, event->status);
}

non_null()
static bool tox_event_friend_status_unpack_into(
    Tox_Event_Friend_Status *event, Bin_Unpack *bu)
{
    assert(event != nullptr);
    if (!bin_unpack_array_fixed(bu, 2)) {
        return false;
    }

    return bin_unpack_u32(bu, &event->friend_number)
           && tox_unpack_user_status(bu, &event->status);
}

EV_FUNCS(Friend_Status, friend_status, FRIEND_STATUS)


/*****************************************************
 *
 * :: event handler
 *
 *****************************************************/


void tox_events_handle_friend_status(Tox *tox, uint32_t friend_number, Tox_User_Status status,
                                     void *user_data)
{
    Tox_Event_Friend_Status *friend_status = tox_event_friend_status_alloc(user_data);

    if (friend_status == nullptr) {
        return;
    }

    tox_event_friend_status_set_friend_number(friend_status, friend_number);
    tox_event_friend_status_set_status(friend_status, status);
}
