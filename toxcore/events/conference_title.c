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


struct Tox_Event_Conference_Title {
    uint32_t conference_number;
    uint32_t peer_number;
    uint8_t *title;
    uint32_t title_length;
};

EV_ACCESS_VALUE(Conference_Title, conference_title, uint32_t, conference_number)
EV_ACCESS_VALUE(Conference_Title, conference_title, uint32_t, peer_number)
EV_ACCESS_ARRAY(Conference_Title, conference_title, uint8_t, title)

non_null()
static void tox_event_conference_title_construct(Tox_Event_Conference_Title *conference_title)
{
    *conference_title = (Tox_Event_Conference_Title) {
        0
    };
}
non_null()
static void tox_event_conference_title_destruct(Tox_Event_Conference_Title *conference_title, const Memory *mem)
{
    mem_delete(mem, conference_title->title);
}

bool tox_event_conference_title_pack(
    const Tox_Event_Conference_Title *event, Bin_Pack *bp)
{
    assert(event != nullptr);
    return bin_pack_array(bp, 2)
           && bin_pack_u32(bp, TOX_EVENT_CONFERENCE_TITLE)
           && bin_pack_array(bp, 3)
           && bin_pack_u32(bp, event->conference_number)
           && bin_pack_u32(bp, event->peer_number)
           && bin_pack_bin(bp, event->title, event->title_length);
}

non_null()
static bool tox_event_conference_title_unpack_into(
    Tox_Event_Conference_Title *event, Bin_Unpack *bu)
{
    assert(event != nullptr);
    if (!bin_unpack_array_fixed(bu, 3)) {
        return false;
    }

    return bin_unpack_u32(bu, &event->conference_number)
           && bin_unpack_u32(bu, &event->peer_number)
           && bin_unpack_bin(bu, &event->title, &event->title_length);
}

EV_FUNCS(Conference_Title, conference_title, CONFERENCE_TITLE)


/*****************************************************
 *
 * :: event handler
 *
 *****************************************************/


void tox_events_handle_conference_title(Tox *tox, uint32_t conference_number, uint32_t peer_number,
                                        const uint8_t *title, size_t length, void *user_data)
{
    Tox_Event_Conference_Title *conference_title = tox_event_conference_title_alloc(user_data);

    if (conference_title == nullptr) {
        return;
    }

    const Tox_System *sys = tox_get_system(tox);

    tox_event_conference_title_set_conference_number(conference_title, conference_number);
    tox_event_conference_title_set_peer_number(conference_title, peer_number);
    tox_event_conference_title_set_title(conference_title, title, length, sys->mem);
}
