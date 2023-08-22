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
#include "../tox_unpack.h"
#include "event_macros.h"


/*****************************************************
 *
 * :: struct and accessors
 *
 *****************************************************/


struct Tox_Event_Conference_Invite {
    uint32_t friend_number;
    Tox_Conference_Type type;
    uint8_t *cookie;
    uint32_t cookie_length;
};

EV_ACCESS_VALUE(Conference_Invite, conference_invite, uint32_t, friend_number)
EV_ACCESS_VALUE(Conference_Invite, conference_invite, Tox_Conference_Type, type)
EV_ACCESS_ARRAY(Conference_Invite, conference_invite, uint8_t, cookie)

non_null()
static void tox_event_conference_invite_construct(Tox_Event_Conference_Invite *conference_invite)
{
    *conference_invite = (Tox_Event_Conference_Invite) {
        0
    };
}
non_null()
static void tox_event_conference_invite_destruct(Tox_Event_Conference_Invite *conference_invite, const Memory *mem)
{
    mem_delete(mem, conference_invite->cookie);
}

bool tox_event_conference_invite_pack(
    const Tox_Event_Conference_Invite *event, Bin_Pack *bp)
{
    assert(event != nullptr);
    return bin_pack_array(bp, 2)
           && bin_pack_u32(bp, TOX_EVENT_CONFERENCE_INVITE)
           && bin_pack_array(bp, 3)
           && bin_pack_u32(bp, event->friend_number)
           && bin_pack_u32(bp, event->type)
           && bin_pack_bin(bp, event->cookie, event->cookie_length);
}

non_null()
static bool tox_event_conference_invite_unpack_into(
    Tox_Event_Conference_Invite *event, Bin_Unpack *bu)
{
    assert(event != nullptr);
    if (!bin_unpack_array_fixed(bu, 3)) {
        return false;
    }

    return bin_unpack_u32(bu, &event->friend_number)
           && tox_unpack_conference_type(bu, &event->type)
           && bin_unpack_bin(bu, &event->cookie, &event->cookie_length);
}

EV_FUNCS(Conference_Invite, conference_invite, CONFERENCE_INVITE)


/*****************************************************
 *
 * :: event handler
 *
 *****************************************************/


void tox_events_handle_conference_invite(Tox *tox, uint32_t friend_number, Tox_Conference_Type type,
        const uint8_t *cookie, size_t length, void *user_data)
{
    Tox_Event_Conference_Invite *conference_invite = tox_event_conference_invite_alloc(user_data);

    if (conference_invite == nullptr) {
        return;
    }

    const Tox_System *sys = tox_get_system(tox);

    tox_event_conference_invite_set_friend_number(conference_invite, friend_number);
    tox_event_conference_invite_set_type(conference_invite, type);
    tox_event_conference_invite_set_cookie(conference_invite, cookie, length, sys->mem);
}
