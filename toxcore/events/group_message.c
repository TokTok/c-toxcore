/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2023 The TokTok team.
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
#include "../tox_unpack.h"


/*****************************************************
 *
 * :: struct and accessors
 *
 *****************************************************/


struct Tox_Event_Group_Message {
    uint32_t group_number;
    uint32_t peer_id;
    Tox_Message_Type type;
    uint8_t *message;
    uint32_t message_length;
    uint32_t message_id;
};

non_null()
static void tox_event_group_message_construct(Tox_Event_Group_Message *group_message)
{
    *group_message = (Tox_Event_Group_Message) {
        0
    };
}
non_null()
static void tox_event_group_message_destruct(Tox_Event_Group_Message *group_message)
{
    free(group_message->message);
}

non_null()
static void tox_event_group_message_set_group_number(Tox_Event_Group_Message *group_message,
        uint32_t group_number)
{
    assert(group_message != nullptr);
    group_message->group_number = group_number;
}
uint32_t tox_event_group_message_get_group_number(const Tox_Event_Group_Message *group_message)
{
    assert(group_message != nullptr);
    return group_message->group_number;
}

non_null()
static void tox_event_group_message_set_peer_id(Tox_Event_Group_Message *group_message,
        uint32_t peer_id)
{
    assert(group_message != nullptr);
    group_message->peer_id = peer_id;
}
uint32_t tox_event_group_message_get_peer_id(const Tox_Event_Group_Message *group_message)
{
    assert(group_message != nullptr);
    return group_message->peer_id;
}

non_null()
static void tox_event_group_message_set_type(Tox_Event_Group_Message *group_message,
        Tox_Message_Type type)
{
    assert(group_message != nullptr);
    group_message->type = type;
}
Tox_Message_Type tox_event_group_message_get_type(const Tox_Event_Group_Message *group_message)
{
    assert(group_message != nullptr);
    return group_message->type;
}

non_null()
static bool tox_event_group_message_set_message(Tox_Event_Group_Message *group_message,
        const uint8_t *message, uint32_t message_length)
{
    assert(group_message != nullptr);

    if (group_message->message != nullptr) {
        free(group_message->message);
        group_message->message = nullptr;
        group_message->message_length = 0;
    }

    group_message->message = (uint8_t *)malloc(message_length);

    if (group_message->message == nullptr) {
        return false;
    }

    memcpy(group_message->message, message, message_length);
    group_message->message_length = message_length;
    return true;
}
size_t tox_event_group_message_get_message_length(const Tox_Event_Group_Message *group_message)
{
    assert(group_message != nullptr);
    return group_message->message_length;
}
const uint8_t *tox_event_group_message_get_message(const Tox_Event_Group_Message *group_message)
{
    assert(group_message != nullptr);
    return group_message->message;
}

non_null()
static void tox_event_group_message_set_message_id(Tox_Event_Group_Message *group_message,
        uint32_t message_id)
{
    assert(group_message != nullptr);
    group_message->message_id = message_id;
}
uint32_t tox_event_group_message_get_message_id(const Tox_Event_Group_Message *group_message)
{
    assert(group_message != nullptr);
    return group_message->message_id;
}

non_null()
static bool tox_event_group_message_pack(
    const Tox_Event_Group_Message *event, Bin_Pack *bp)
{
    assert(event != nullptr);
    return bin_pack_array(bp, 2)
           && bin_pack_u32(bp, TOX_EVENT_GROUP_MESSAGE)
           && bin_pack_array(bp, 5)
           && bin_pack_u32(bp, event->group_number)
           && bin_pack_u32(bp, event->peer_id)
           && bin_pack_u32(bp, event->type)
           && bin_pack_bin(bp, event->message, event->message_length)
           && bin_pack_u32(bp, event->message_id);
}

non_null()
static bool tox_event_group_message_unpack(
    Tox_Event_Group_Message *event, Bin_Unpack *bu)
{
    assert(event != nullptr);
    if (!bin_unpack_array_fixed(bu, 5)) {
        return false;
    }

    return bin_unpack_u32(bu, &event->group_number)
           && bin_unpack_u32(bu, &event->peer_id)
           && tox_unpack_message_type(bu, &event->type)
           && bin_unpack_bin(bu, &event->message, &event->message_length)
           && bin_unpack_u32(bu, &event->message_id);
}


/*****************************************************
 *
 * :: add/clear/get
 *
 *****************************************************/


non_null()
static Tox_Event_Group_Message *tox_events_add_group_message(Tox_Events *events)
{
    if (events->group_message_size == UINT32_MAX) {
        return nullptr;
    }

    if (events->group_message_size == events->group_message_capacity) {
        const uint32_t new_group_message_capacity = events->group_message_capacity * 2 + 1;
        Tox_Event_Group_Message *new_group_message = (Tox_Event_Group_Message *)
                realloc(
                    events->group_message,
                    new_group_message_capacity * sizeof(Tox_Event_Group_Message));

        if (new_group_message == nullptr) {
            return nullptr;
        }

        events->group_message = new_group_message;
        events->group_message_capacity = new_group_message_capacity;
    }

    Tox_Event_Group_Message *const group_message =
        &events->group_message[events->group_message_size];
    tox_event_group_message_construct(group_message);
    ++events->group_message_size;
    return group_message;
}

void tox_events_clear_group_message(Tox_Events *events)
{
    if (events == nullptr) {
        return;
    }

    for (uint32_t i = 0; i < events->group_message_size; ++i) {
        tox_event_group_message_destruct(&events->group_message[i]);
    }

    free(events->group_message);
    events->group_message = nullptr;
    events->group_message_size = 0;
    events->group_message_capacity = 0;
}

uint32_t tox_events_get_group_message_size(const Tox_Events *events)
{
    if (events == nullptr) {
        return 0;
    }

    return events->group_message_size;
}

const Tox_Event_Group_Message *tox_events_get_group_message(const Tox_Events *events, uint32_t index)
{
    assert(index < events->group_message_size);
    assert(events->group_message != nullptr);
    return &events->group_message[index];
}

bool tox_events_pack_group_message(const Tox_Events *events, Bin_Pack *bp)
{
    const uint32_t size = tox_events_get_group_message_size(events);

    for (uint32_t i = 0; i < size; ++i) {
        if (!tox_event_group_message_pack(tox_events_get_group_message(events, i), bp)) {
            return false;
        }
    }
    return true;
}

bool tox_events_unpack_group_message(Tox_Events *events, Bin_Unpack *bu)
{
    Tox_Event_Group_Message *event = tox_events_add_group_message(events);

    if (event == nullptr) {
        return false;
    }

    return tox_event_group_message_unpack(event, bu);
}


/*****************************************************
 *
 * :: event handler
 *
 *****************************************************/


void tox_events_handle_group_message(Tox *tox, uint32_t group_number, uint32_t peer_id, Tox_Message_Type type, const uint8_t *message, size_t length, uint32_t message_id,
        void *user_data)
{
    Tox_Events_State *state = tox_events_alloc(user_data);
    assert(state != nullptr);

    if (state->events == nullptr) {
        return;
    }

    Tox_Event_Group_Message *group_message = tox_events_add_group_message(state->events);

    if (group_message == nullptr) {
        state->error = TOX_ERR_EVENTS_ITERATE_MALLOC;
        return;
    }

    tox_event_group_message_set_group_number(group_message, group_number);
    tox_event_group_message_set_peer_id(group_message, peer_id);
    tox_event_group_message_set_type(group_message, type);
    tox_event_group_message_set_message(group_message, message, length);
    tox_event_group_message_set_message_id(group_message, message_id);
}
