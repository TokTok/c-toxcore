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


struct Tox_Event_Friend_Status_Message {
    uint32_t friend_number;
    uint8_t *message;
    uint32_t message_length;
};

EV_ACCESS_VALUE(Friend_Status_Message, friend_status_message, uint32_t, friend_number)
EV_ACCESS_ARRAY(Friend_Status_Message, friend_status_message, uint8_t, message)

non_null()
static void tox_event_friend_status_message_construct(Tox_Event_Friend_Status_Message *friend_status_message)
{
    *friend_status_message = (Tox_Event_Friend_Status_Message) {
        0
    };
}
non_null()
static void tox_event_friend_status_message_destruct(Tox_Event_Friend_Status_Message *friend_status_message, const Memory *mem)
{
    mem_delete(mem, friend_status_message->message);
}

bool tox_event_friend_status_message_pack(
    const Tox_Event_Friend_Status_Message *event, Bin_Pack *bp)
{
    assert(event != nullptr);
    return bin_pack_array(bp, 2)
           && bin_pack_u32(bp, TOX_EVENT_FRIEND_STATUS_MESSAGE)
           && bin_pack_array(bp, 2)
           && bin_pack_u32(bp, event->friend_number)
           && bin_pack_bin(bp, event->message, event->message_length);
}

non_null()
static bool tox_event_friend_status_message_unpack_into(
    Tox_Event_Friend_Status_Message *event, Bin_Unpack *bu)
{
    assert(event != nullptr);
    if (!bin_unpack_array_fixed(bu, 2)) {
        return false;
    }

    return bin_unpack_u32(bu, &event->friend_number)
           && bin_unpack_bin(bu, &event->message, &event->message_length);
}

EV_FUNCS(Friend_Status_Message, friend_status_message, FRIEND_STATUS_MESSAGE)


/*****************************************************
 *
 * :: event handler
 *
 *****************************************************/


void tox_events_handle_friend_status_message(Tox *tox, uint32_t friend_number, const uint8_t *message,
        size_t length, void *user_data)
{
    Tox_Event_Friend_Status_Message *friend_status_message = tox_event_friend_status_message_alloc(user_data);

    if (friend_status_message == nullptr) {
        return;
    }

    const Tox_System *sys = tox_get_system(tox);

    tox_event_friend_status_message_set_friend_number(friend_status_message, friend_number);
    tox_event_friend_status_message_set_message(friend_status_message, message, length, sys->mem);
}
