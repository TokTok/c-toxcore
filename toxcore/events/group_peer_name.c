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


struct Tox_Event_Group_Peer_Name {
    uint32_t group_number;
    uint32_t peer_id;
    uint8_t *name;
    uint32_t name_length;
};

non_null()
static void tox_event_group_peer_name_construct(Tox_Event_Group_Peer_Name *group_peer_name)
{
    *group_peer_name = (Tox_Event_Group_Peer_Name) {
        0
    };
}
non_null()
static void tox_event_group_peer_name_destruct(Tox_Event_Group_Peer_Name *group_peer_name)
{
    free(group_peer_name->name);
}

non_null()
static void tox_event_group_peer_name_set_group_number(Tox_Event_Group_Peer_Name *group_peer_name,
        uint32_t group_number)
{
    assert(group_peer_name != nullptr);
    group_peer_name->group_number = group_number;
}
uint32_t tox_event_group_peer_name_get_group_number(const Tox_Event_Group_Peer_Name *group_peer_name)
{
    assert(group_peer_name != nullptr);
    return group_peer_name->group_number;
}

non_null()
static void tox_event_group_peer_name_set_peer_id(Tox_Event_Group_Peer_Name *group_peer_name,
        uint32_t peer_id)
{
    assert(group_peer_name != nullptr);
    group_peer_name->peer_id = peer_id;
}
uint32_t tox_event_group_peer_name_get_peer_id(const Tox_Event_Group_Peer_Name *group_peer_name)
{
    assert(group_peer_name != nullptr);
    return group_peer_name->peer_id;
}

non_null()
static bool tox_event_group_peer_name_set_name(Tox_Event_Group_Peer_Name *group_peer_name,
        const uint8_t *name, uint32_t name_length)
{
    assert(group_peer_name != nullptr);

    if (group_peer_name->name != nullptr) {
        free(group_peer_name->name);
        group_peer_name->name = nullptr;
        group_peer_name->name_length = 0;
    }

    group_peer_name->name = (uint8_t *)malloc(name_length);

    if (group_peer_name->name == nullptr) {
        return false;
    }

    memcpy(group_peer_name->name, name, name_length);
    group_peer_name->name_length = name_length;
    return true;
}
size_t tox_event_group_peer_name_get_name_length(const Tox_Event_Group_Peer_Name *group_peer_name)
{
    assert(group_peer_name != nullptr);
    return group_peer_name->name_length;
}
const uint8_t *tox_event_group_peer_name_get_name(const Tox_Event_Group_Peer_Name *group_peer_name)
{
    assert(group_peer_name != nullptr);
    return group_peer_name->name;
}

non_null()
static bool tox_event_group_peer_name_pack(
    const Tox_Event_Group_Peer_Name *event, Bin_Pack *bp)
{
    assert(event != nullptr);
    return bin_pack_array(bp, 2)
           && bin_pack_u32(bp, TOX_EVENT_GROUP_PEER_NAME)
           && bin_pack_array(bp, 3)
           && bin_pack_u32(bp, event->group_number)
           && bin_pack_u32(bp, event->peer_id)
           && bin_pack_bin(bp, event->name, event->name_length);
}

non_null()
static bool tox_event_group_peer_name_unpack(
    Tox_Event_Group_Peer_Name *event, Bin_Unpack *bu)
{
    assert(event != nullptr);
    if (!bin_unpack_array_fixed(bu, 3, nullptr)) {
        return false;
    }

    return bin_unpack_u32(bu, &event->group_number)
           && bin_unpack_u32(bu, &event->peer_id)
           && bin_unpack_bin(bu, &event->name, &event->name_length);
}


/*****************************************************
 *
 * :: add/clear/get
 *
 *****************************************************/


non_null()
static Tox_Event_Group_Peer_Name *tox_events_add_group_peer_name(Tox_Events *events)
{
    if (events->group_peer_name_size == UINT32_MAX) {
        return nullptr;
    }

    if (events->group_peer_name_size == events->group_peer_name_capacity) {
        const uint32_t new_group_peer_name_capacity = events->group_peer_name_capacity * 2 + 1;
        Tox_Event_Group_Peer_Name *new_group_peer_name = (Tox_Event_Group_Peer_Name *)
                realloc(
                    events->group_peer_name,
                    new_group_peer_name_capacity * sizeof(Tox_Event_Group_Peer_Name));

        if (new_group_peer_name == nullptr) {
            return nullptr;
        }

        events->group_peer_name = new_group_peer_name;
        events->group_peer_name_capacity = new_group_peer_name_capacity;
    }

    Tox_Event_Group_Peer_Name *const group_peer_name =
        &events->group_peer_name[events->group_peer_name_size];
    tox_event_group_peer_name_construct(group_peer_name);
    ++events->group_peer_name_size;
    return group_peer_name;
}

void tox_events_clear_group_peer_name(Tox_Events *events)
{
    if (events == nullptr) {
        return;
    }

    for (uint32_t i = 0; i < events->group_peer_name_size; ++i) {
        tox_event_group_peer_name_destruct(&events->group_peer_name[i]);
    }

    free(events->group_peer_name);
    events->group_peer_name = nullptr;
    events->group_peer_name_size = 0;
    events->group_peer_name_capacity = 0;
}

uint32_t tox_events_get_group_peer_name_size(const Tox_Events *events)
{
    if (events == nullptr) {
        return 0;
    }

    return events->group_peer_name_size;
}

const Tox_Event_Group_Peer_Name *tox_events_get_group_peer_name(const Tox_Events *events, uint32_t index)
{
    assert(index < events->group_peer_name_size);
    assert(events->group_peer_name != nullptr);
    return &events->group_peer_name[index];
}

bool tox_events_pack_group_peer_name(const Tox_Events *events, Bin_Pack *bp)
{
    const uint32_t size = tox_events_get_group_peer_name_size(events);

    for (uint32_t i = 0; i < size; ++i) {
        if (!tox_event_group_peer_name_pack(tox_events_get_group_peer_name(events, i), bp)) {
            return false;
        }
    }
    return true;
}

bool tox_events_unpack_group_peer_name(Tox_Events *events, Bin_Unpack *bu)
{
    Tox_Event_Group_Peer_Name *event = tox_events_add_group_peer_name(events);

    if (event == nullptr) {
        return false;
    }

    return tox_event_group_peer_name_unpack(event, bu);
}


/*****************************************************
 *
 * :: event handler
 *
 *****************************************************/


void tox_events_handle_group_peer_name(Tox *tox, uint32_t group_number, uint32_t peer_id, const uint8_t *name, size_t length,
        void *user_data)
{
    Tox_Events_State *state = tox_events_alloc(user_data);
    assert(state != nullptr);

    if (state->events == nullptr) {
        return;
    }

    Tox_Event_Group_Peer_Name *group_peer_name = tox_events_add_group_peer_name(state->events);

    if (group_peer_name == nullptr) {
        state->error = TOX_ERR_EVENTS_ITERATE_MALLOC;
        return;
    }

    tox_event_group_peer_name_set_group_number(group_peer_name, group_number);
    tox_event_group_peer_name_set_peer_id(group_peer_name, peer_id);
    tox_event_group_peer_name_set_name(group_peer_name, name, length);
}
