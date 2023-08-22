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


struct Tox_Event_Conference_Peer_List_Changed {
    uint32_t conference_number;
};

EV_ACCESS_VALUE(Conference_Peer_List_Changed, conference_peer_list_changed, uint32_t, conference_number)

non_null()
static void tox_event_conference_peer_list_changed_construct(Tox_Event_Conference_Peer_List_Changed
        *conference_peer_list_changed)
{
    *conference_peer_list_changed = (Tox_Event_Conference_Peer_List_Changed) {
        0
    };
}
non_null()
static void tox_event_conference_peer_list_changed_destruct(Tox_Event_Conference_Peer_List_Changed *conference_peer_list_changed, const Memory *mem)
{
    return;
}

bool tox_event_conference_peer_list_changed_pack(
    const Tox_Event_Conference_Peer_List_Changed *event, Bin_Pack *bp)
{
    assert(event != nullptr);
    return bin_pack_array(bp, 2)
           && bin_pack_u32(bp, TOX_EVENT_CONFERENCE_PEER_LIST_CHANGED)
           && bin_pack_u32(bp, event->conference_number);
}

non_null()
static bool tox_event_conference_peer_list_changed_unpack_into(
    Tox_Event_Conference_Peer_List_Changed *event, Bin_Unpack *bu)
{
    assert(event != nullptr);
    return bin_unpack_u32(bu, &event->conference_number);
}

EV_FUNCS(Conference_Peer_List_Changed, conference_peer_list_changed, CONFERENCE_PEER_LIST_CHANGED)


/*****************************************************
 *
 * :: event handler
 *
 *****************************************************/


void tox_events_handle_conference_peer_list_changed(Tox *tox, uint32_t conference_number, void *user_data)
{
    Tox_Event_Conference_Peer_List_Changed *conference_peer_list_changed = tox_event_conference_peer_list_changed_alloc(user_data);

    if (conference_peer_list_changed == nullptr) {
        return;
    }

    tox_event_conference_peer_list_changed_set_conference_number(conference_peer_list_changed, conference_number);
}
