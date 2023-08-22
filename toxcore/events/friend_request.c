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


struct Tox_Event_Friend_Request {
    uint8_t public_key[TOX_PUBLIC_KEY_SIZE];
    uint8_t *message;
    uint32_t message_length;
};

EV_ACCESS_FIXED(Friend_Request, friend_request, uint8_t, public_key, TOX_PUBLIC_KEY_SIZE)
EV_ACCESS_ARRAY(Friend_Request, friend_request, uint8_t, message)

non_null()
static void tox_event_friend_request_construct(Tox_Event_Friend_Request *friend_request)
{
    *friend_request = (Tox_Event_Friend_Request) {
        0
    };
}
non_null()
static void tox_event_friend_request_destruct(Tox_Event_Friend_Request *friend_request, const Memory *mem)
{
    mem_delete(mem, friend_request->message);
}

bool tox_event_friend_request_pack(
    const Tox_Event_Friend_Request *event, Bin_Pack *bp)
{
    assert(event != nullptr);
    return bin_pack_array(bp, 2)
           && bin_pack_u32(bp, TOX_EVENT_FRIEND_REQUEST)
           && bin_pack_array(bp, 2)
           && bin_pack_bin(bp, event->public_key, TOX_PUBLIC_KEY_SIZE)
           && bin_pack_bin(bp, event->message, event->message_length);
}

non_null()
static bool tox_event_friend_request_unpack_into(
    Tox_Event_Friend_Request *event, Bin_Unpack *bu)
{
    assert(event != nullptr);
    if (!bin_unpack_array_fixed(bu, 2)) {
        return false;
    }

    return bin_unpack_bin_fixed(bu, event->public_key, TOX_PUBLIC_KEY_SIZE)
           && bin_unpack_bin(bu, &event->message, &event->message_length);
}

EV_FUNCS(Friend_Request, friend_request, FRIEND_REQUEST)


/*****************************************************
 *
 * :: event handler
 *
 *****************************************************/


void tox_events_handle_friend_request(Tox *tox, const uint8_t *public_key, const uint8_t *message, size_t length,
                                      void *user_data)
{
    Tox_Event_Friend_Request *friend_request = tox_event_friend_request_alloc(user_data);

    if (friend_request == nullptr) {
        return;
    }

    const Tox_System *sys = tox_get_system(tox);

    tox_event_friend_request_set_public_key(friend_request, public_key);
    tox_event_friend_request_set_message(friend_request, message, length, sys->mem);
}
