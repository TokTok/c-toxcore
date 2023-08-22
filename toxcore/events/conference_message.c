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


struct Tox_Event_Conference_Message {
    uint32_t conference_number;
    uint32_t peer_number;
    Tox_Message_Type type;
    uint8_t *message;
    uint32_t message_length;
};

EV_ACCESS_VALUE(Conference_Message, conference_message, uint32_t, conference_number)
EV_ACCESS_VALUE(Conference_Message, conference_message, uint32_t, peer_number)
EV_ACCESS_VALUE(Conference_Message, conference_message, Tox_Message_Type, type)
EV_ACCESS_ARRAY(Conference_Message, conference_message, uint8_t, message)

non_null()
static void tox_event_conference_message_construct(Tox_Event_Conference_Message *conference_message)
{
    *conference_message = (Tox_Event_Conference_Message) {
        0
    };
}
non_null()
static void tox_event_conference_message_destruct(Tox_Event_Conference_Message *conference_message, const Memory *mem)
{
    mem_delete(mem, conference_message->message);
}

bool tox_event_conference_message_pack(
    const Tox_Event_Conference_Message *event, Bin_Pack *bp)
{
    assert(event != nullptr);
    return bin_pack_array(bp, 2)
           && bin_pack_u32(bp, TOX_EVENT_CONFERENCE_MESSAGE)
           && bin_pack_array(bp, 4)
           && bin_pack_u32(bp, event->conference_number)
           && bin_pack_u32(bp, event->peer_number)
           && bin_pack_u32(bp, event->type)
           && bin_pack_bin(bp, event->message, event->message_length);
}

non_null()
static bool tox_event_conference_message_unpack_into(
    Tox_Event_Conference_Message *event, Bin_Unpack *bu)
{
    assert(event != nullptr);
    if (!bin_unpack_array_fixed(bu, 4)) {
        return false;
    }

    return bin_unpack_u32(bu, &event->conference_number)
           && bin_unpack_u32(bu, &event->peer_number)
           && tox_unpack_message_type(bu, &event->type)
           && bin_unpack_bin(bu, &event->message, &event->message_length);
}

EV_FUNCS(Conference_Message, conference_message, CONFERENCE_MESSAGE)


/*****************************************************
 *
 * :: event handler
 *
 *****************************************************/


void tox_events_handle_conference_message(Tox *tox, uint32_t conference_number, uint32_t peer_number,
        Tox_Message_Type type, const uint8_t *message, size_t length, void *user_data)
{
    Tox_Event_Conference_Message *conference_message = tox_event_conference_message_alloc(user_data);

    if (conference_message == nullptr) {
        return;
    }

    const Tox_System *sys = tox_get_system(tox);

    tox_event_conference_message_set_conference_number(conference_message, conference_number);
    tox_event_conference_message_set_peer_number(conference_message, peer_number);
    tox_event_conference_message_set_type(conference_message, type);
    tox_event_conference_message_set_message(conference_message, message, length, sys->mem);
}
