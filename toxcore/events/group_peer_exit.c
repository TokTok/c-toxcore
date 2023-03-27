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


struct Tox_Event_Group_Peer_Exit {
    uint32_t group_number;
    uint32_t peer_id;
    Tox_Group_Exit_Type exit_type;
    uint8_t *name;
    uint32_t name_length;
    uint8_t *part_message;
    uint32_t part_message_length;
};

non_null()
static void tox_event_group_peer_exit_construct(Tox_Event_Group_Peer_Exit *group_peer_exit)
{
    *group_peer_exit = (Tox_Event_Group_Peer_Exit) {
        0
    };
}
non_null()
static void tox_event_group_peer_exit_destruct(Tox_Event_Group_Peer_Exit *group_peer_exit)
{
    free(group_peer_exit->name);
    free(group_peer_exit->part_message);
}

non_null()
static void tox_event_group_peer_exit_set_group_number(Tox_Event_Group_Peer_Exit *group_peer_exit,
        uint32_t group_number)
{
    assert(group_peer_exit != nullptr);
    group_peer_exit->group_number = group_number;
}
uint32_t tox_event_group_peer_exit_get_group_number(const Tox_Event_Group_Peer_Exit *group_peer_exit)
{
    assert(group_peer_exit != nullptr);
    return group_peer_exit->group_number;
}

non_null()
static void tox_event_group_peer_exit_set_peer_id(Tox_Event_Group_Peer_Exit *group_peer_exit,
        uint32_t peer_id)
{
    assert(group_peer_exit != nullptr);
    group_peer_exit->peer_id = peer_id;
}
uint32_t tox_event_group_peer_exit_get_peer_id(const Tox_Event_Group_Peer_Exit *group_peer_exit)
{
    assert(group_peer_exit != nullptr);
    return group_peer_exit->peer_id;
}

non_null()
static void tox_event_group_peer_exit_set_exit_type(Tox_Event_Group_Peer_Exit *group_peer_exit,
        Tox_Group_Exit_Type exit_type)
{
    assert(group_peer_exit != nullptr);
    group_peer_exit->exit_type = exit_type;
}
Tox_Group_Exit_Type tox_event_group_peer_exit_get_exit_type(const Tox_Event_Group_Peer_Exit *group_peer_exit)
{
    assert(group_peer_exit != nullptr);
    return group_peer_exit->exit_type;
}

non_null()
static bool tox_event_group_peer_exit_set_name(Tox_Event_Group_Peer_Exit *group_peer_exit,
        const uint8_t *name, uint32_t name_length)
{
    assert(group_peer_exit != nullptr);

    if (group_peer_exit->name != nullptr) {
        free(group_peer_exit->name);
        group_peer_exit->name = nullptr;
        group_peer_exit->name_length = 0;
    }

    group_peer_exit->name = (uint8_t *)malloc(name_length);

    if (group_peer_exit->name == nullptr) {
        return false;
    }

    memcpy(group_peer_exit->name, name, name_length);
    group_peer_exit->name_length = name_length;
    return true;
}
size_t tox_event_group_peer_exit_get_name_length(const Tox_Event_Group_Peer_Exit *group_peer_exit)
{
    assert(group_peer_exit != nullptr);
    return group_peer_exit->name_length;
}
const uint8_t *tox_event_group_peer_exit_get_name(const Tox_Event_Group_Peer_Exit *group_peer_exit)
{
    assert(group_peer_exit != nullptr);
    return group_peer_exit->name;
}

non_null()
static bool tox_event_group_peer_exit_set_part_message(Tox_Event_Group_Peer_Exit *group_peer_exit,
        const uint8_t *part_message, uint32_t part_message_length)
{
    assert(group_peer_exit != nullptr);

    if (group_peer_exit->part_message != nullptr) {
        free(group_peer_exit->part_message);
        group_peer_exit->part_message = nullptr;
        group_peer_exit->part_message_length = 0;
    }

    group_peer_exit->part_message = (uint8_t *)malloc(part_message_length);

    if (group_peer_exit->part_message == nullptr) {
        return false;
    }

    memcpy(group_peer_exit->part_message, part_message, part_message_length);
    group_peer_exit->part_message_length = part_message_length;
    return true;
}
size_t tox_event_group_peer_exit_get_part_message_length(const Tox_Event_Group_Peer_Exit *group_peer_exit)
{
    assert(group_peer_exit != nullptr);
    return group_peer_exit->part_message_length;
}
const uint8_t *tox_event_group_peer_exit_get_part_message(const Tox_Event_Group_Peer_Exit *group_peer_exit)
{
    assert(group_peer_exit != nullptr);
    return group_peer_exit->part_message;
}

non_null()
static bool tox_event_group_peer_exit_pack(
    const Tox_Event_Group_Peer_Exit *event, Bin_Pack *bp)
{
    assert(event != nullptr);
    return bin_pack_array(bp, 2)
           && bin_pack_u32(bp, TOX_EVENT_GROUP_PEER_EXIT)
           && bin_pack_array(bp, 5)
           && bin_pack_u32(bp, event->group_number)
           && bin_pack_u32(bp, event->peer_id)
           && bin_pack_u32(bp, event->exit_type)
           && bin_pack_bin(bp, event->name, event->name_length)
           && bin_pack_bin(bp, event->part_message, event->part_message_length);
}

non_null()
static bool tox_event_group_peer_exit_unpack(
    Tox_Event_Group_Peer_Exit *event, Bin_Unpack *bu)
{
    assert(event != nullptr);
    if (!bin_unpack_array_fixed(bu, 5)) {
        return false;
    }

    return bin_unpack_u32(bu, &event->group_number)
           && bin_unpack_u32(bu, &event->peer_id)
           && tox_unpack_group_exit_type(bu, &event->exit_type)
           && bin_unpack_bin(bu, &event->name, &event->name_length)
           && bin_unpack_bin(bu, &event->part_message, &event->part_message_length);
}


/*****************************************************
 *
 * :: add/clear/get
 *
 *****************************************************/


non_null()
static Tox_Event_Group_Peer_Exit *tox_events_add_group_peer_exit(Tox_Events *events)
{
    if (events->group_peer_exit_size == UINT32_MAX) {
        return nullptr;
    }

    if (events->group_peer_exit_size == events->group_peer_exit_capacity) {
        const uint32_t new_group_peer_exit_capacity = events->group_peer_exit_capacity * 2 + 1;
        Tox_Event_Group_Peer_Exit *new_group_peer_exit = (Tox_Event_Group_Peer_Exit *)
                realloc(
                    events->group_peer_exit,
                    new_group_peer_exit_capacity * sizeof(Tox_Event_Group_Peer_Exit));

        if (new_group_peer_exit == nullptr) {
            return nullptr;
        }

        events->group_peer_exit = new_group_peer_exit;
        events->group_peer_exit_capacity = new_group_peer_exit_capacity;
    }

    Tox_Event_Group_Peer_Exit *const group_peer_exit =
        &events->group_peer_exit[events->group_peer_exit_size];
    tox_event_group_peer_exit_construct(group_peer_exit);
    ++events->group_peer_exit_size;
    return group_peer_exit;
}

void tox_events_clear_group_peer_exit(Tox_Events *events)
{
    if (events == nullptr) {
        return;
    }

    for (uint32_t i = 0; i < events->group_peer_exit_size; ++i) {
        tox_event_group_peer_exit_destruct(&events->group_peer_exit[i]);
    }

    free(events->group_peer_exit);
    events->group_peer_exit = nullptr;
    events->group_peer_exit_size = 0;
    events->group_peer_exit_capacity = 0;
}

uint32_t tox_events_get_group_peer_exit_size(const Tox_Events *events)
{
    if (events == nullptr) {
        return 0;
    }

    return events->group_peer_exit_size;
}

const Tox_Event_Group_Peer_Exit *tox_events_get_group_peer_exit(const Tox_Events *events, uint32_t index)
{
    assert(index < events->group_peer_exit_size);
    assert(events->group_peer_exit != nullptr);
    return &events->group_peer_exit[index];
}

bool tox_events_pack_group_peer_exit(const Tox_Events *events, Bin_Pack *bp)
{
    const uint32_t size = tox_events_get_group_peer_exit_size(events);

    for (uint32_t i = 0; i < size; ++i) {
        if (!tox_event_group_peer_exit_pack(tox_events_get_group_peer_exit(events, i), bp)) {
            return false;
        }
    }
    return true;
}

bool tox_events_unpack_group_peer_exit(Tox_Events *events, Bin_Unpack *bu)
{
    Tox_Event_Group_Peer_Exit *event = tox_events_add_group_peer_exit(events);

    if (event == nullptr) {
        return false;
    }

    return tox_event_group_peer_exit_unpack(event, bu);
}


/*****************************************************
 *
 * :: event handler
 *
 *****************************************************/


void tox_events_handle_group_peer_exit(Tox *tox, uint32_t group_number, uint32_t peer_id, Tox_Group_Exit_Type exit_type, const uint8_t *name, size_t name_length, const uint8_t *part_message, size_t part_message_length,
        void *user_data)
{
    Tox_Events_State *state = tox_events_alloc(user_data);
    assert(state != nullptr);

    if (state->events == nullptr) {
        return;
    }

    Tox_Event_Group_Peer_Exit *group_peer_exit = tox_events_add_group_peer_exit(state->events);

    if (group_peer_exit == nullptr) {
        state->error = TOX_ERR_EVENTS_ITERATE_MALLOC;
        return;
    }

    tox_event_group_peer_exit_set_group_number(group_peer_exit, group_number);
    tox_event_group_peer_exit_set_peer_id(group_peer_exit, peer_id);
    tox_event_group_peer_exit_set_exit_type(group_peer_exit, exit_type);
    tox_event_group_peer_exit_set_name(group_peer_exit, name, name_length);
    tox_event_group_peer_exit_set_part_message(group_peer_exit, part_message, part_message_length);
}
