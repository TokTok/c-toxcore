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


struct Tox_Event_Conference_Connected {
    uint32_t conference_number;
};

EV_ACCESS_VALUE(Conference_Connected, conference_connected, uint32_t, conference_number)

non_null()
static void tox_event_conference_connected_construct(Tox_Event_Conference_Connected *conference_connected)
{
    *conference_connected = (Tox_Event_Conference_Connected) {
        0
    };
}
non_null()
static void tox_event_conference_connected_destruct(Tox_Event_Conference_Connected *conference_connected, const Memory *mem)
{
    return;
}

bool tox_event_conference_connected_pack(
    const Tox_Event_Conference_Connected *event, Bin_Pack *bp)
{
    assert(event != nullptr);
    return bin_pack_array(bp, 2)
           && bin_pack_u32(bp, TOX_EVENT_CONFERENCE_CONNECTED)
           && bin_pack_u32(bp, event->conference_number);
}

static bool tox_event_conference_connected_unpack_into(
    Tox_Event_Conference_Connected *event, Bin_Unpack *bu)
{
    assert(event != nullptr);
    return bin_unpack_u32(bu, &event->conference_number);
}

EV_FUNCS(Conference_Connected, conference_connected, CONFERENCE_CONNECTED)


/*****************************************************
 *
 * :: event handler
 *
 *****************************************************/

void tox_events_handle_conference_connected(Tox *tox, uint32_t conference_number, void *user_data)
{
    Tox_Event_Conference_Connected *conference_connected = tox_event_conference_connected_alloc(user_data);

    if (conference_connected == nullptr) {
        return;
    }

    tox_event_conference_connected_set_conference_number(conference_connected, conference_number);
}
