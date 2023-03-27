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


struct Tox_Event_Group_Peer_Status {
    uint32_t group_number;
    uint32_t peer_id;
    Tox_User_Status status;
};

non_null()
static void tox_event_group_peer_status_construct(Tox_Event_Group_Peer_Status *group_peer_status)
{
    *group_peer_status = (Tox_Event_Group_Peer_Status) {
        0
    };
}
non_null()
static void tox_event_group_peer_status_destruct(Tox_Event_Group_Peer_Status *group_peer_status)
{
    return;
}

non_null()
static void tox_event_group_peer_status_set_group_number(Tox_Event_Group_Peer_Status *group_peer_status,
        uint32_t group_number)
{
    assert(group_peer_status != nullptr);
    group_peer_status->group_number = group_number;
}
uint32_t tox_event_group_peer_status_get_group_number(const Tox_Event_Group_Peer_Status *group_peer_status)
{
    assert(group_peer_status != nullptr);
    return group_peer_status->group_number;
}

non_null()
static void tox_event_group_peer_status_set_peer_id(Tox_Event_Group_Peer_Status *group_peer_status,
        uint32_t peer_id)
{
    assert(group_peer_status != nullptr);
    group_peer_status->peer_id = peer_id;
}
uint32_t tox_event_group_peer_status_get_peer_id(const Tox_Event_Group_Peer_Status *group_peer_status)
{
    assert(group_peer_status != nullptr);
    return group_peer_status->peer_id;
}

non_null()
static void tox_event_group_peer_status_set_status(Tox_Event_Group_Peer_Status *group_peer_status,
        Tox_User_Status status)
{
    assert(group_peer_status != nullptr);
    group_peer_status->status = status;
}
Tox_User_Status tox_event_group_peer_status_get_status(const Tox_Event_Group_Peer_Status *group_peer_status)
{
    assert(group_peer_status != nullptr);
    return group_peer_status->status;
}

non_null()
static bool tox_event_group_peer_status_pack(
    const Tox_Event_Group_Peer_Status *event, Bin_Pack *bp)
{
    assert(event != nullptr);
    return bin_pack_array(bp, 2)
           && bin_pack_u32(bp, TOX_EVENT_GROUP_PEER_STATUS)
           && bin_pack_array(bp, 3)
           && bin_pack_u32(bp, event->group_number)
           && bin_pack_u32(bp, event->peer_id)
           && bin_pack_u32(bp, event->status);
}

non_null()
static bool tox_event_group_peer_status_unpack(
    Tox_Event_Group_Peer_Status *event, Bin_Unpack *bu)
{
    assert(event != nullptr);
    if (!bin_unpack_array_fixed(bu, 3, nullptr)) {
        return false;
    }

    return bin_unpack_u32(bu, &event->group_number)
           && bin_unpack_u32(bu, &event->peer_id)
           && tox_unpack_user_status(bu, &event->status);
}


/*****************************************************
 *
 * :: add/clear/get
 *
 *****************************************************/


non_null()
static Tox_Event_Group_Peer_Status *tox_events_add_group_peer_status(Tox_Events *events)
{
    if (events->group_peer_status_size == UINT32_MAX) {
        return nullptr;
    }

    if (events->group_peer_status_size == events->group_peer_status_capacity) {
        const uint32_t new_group_peer_status_capacity = events->group_peer_status_capacity * 2 + 1;
        Tox_Event_Group_Peer_Status *new_group_peer_status = (Tox_Event_Group_Peer_Status *)
                realloc(
                    events->group_peer_status,
                    new_group_peer_status_capacity * sizeof(Tox_Event_Group_Peer_Status));

        if (new_group_peer_status == nullptr) {
            return nullptr;
        }

        events->group_peer_status = new_group_peer_status;
        events->group_peer_status_capacity = new_group_peer_status_capacity;
    }

    Tox_Event_Group_Peer_Status *const group_peer_status =
        &events->group_peer_status[events->group_peer_status_size];
    tox_event_group_peer_status_construct(group_peer_status);
    ++events->group_peer_status_size;
    return group_peer_status;
}

void tox_events_clear_group_peer_status(Tox_Events *events)
{
    if (events == nullptr) {
        return;
    }

    for (uint32_t i = 0; i < events->group_peer_status_size; ++i) {
        tox_event_group_peer_status_destruct(&events->group_peer_status[i]);
    }

    free(events->group_peer_status);
    events->group_peer_status = nullptr;
    events->group_peer_status_size = 0;
    events->group_peer_status_capacity = 0;
}

uint32_t tox_events_get_group_peer_status_size(const Tox_Events *events)
{
    if (events == nullptr) {
        return 0;
    }

    return events->group_peer_status_size;
}

const Tox_Event_Group_Peer_Status *tox_events_get_group_peer_status(const Tox_Events *events, uint32_t index)
{
    assert(index < events->group_peer_status_size);
    assert(events->group_peer_status != nullptr);
    return &events->group_peer_status[index];
}

bool tox_events_pack_group_peer_status(const Tox_Events *events, Bin_Pack *bp)
{
    const uint32_t size = tox_events_get_group_peer_status_size(events);

    for (uint32_t i = 0; i < size; ++i) {
        if (!tox_event_group_peer_status_pack(tox_events_get_group_peer_status(events, i), bp)) {
            return false;
        }
    }
    return true;
}

bool tox_events_unpack_group_peer_status(Tox_Events *events, Bin_Unpack *bu)
{
    Tox_Event_Group_Peer_Status *event = tox_events_add_group_peer_status(events);

    if (event == nullptr) {
        return false;
    }

    return tox_event_group_peer_status_unpack(event, bu);
}


/*****************************************************
 *
 * :: event handler
 *
 *****************************************************/


void tox_events_handle_group_peer_status(Tox *tox, uint32_t group_number, uint32_t peer_id, Tox_User_Status status,
        void *user_data)
{
    Tox_Events_State *state = tox_events_alloc(user_data);
    assert(state != nullptr);

    if (state->events == nullptr) {
        return;
    }

    Tox_Event_Group_Peer_Status *group_peer_status = tox_events_add_group_peer_status(state->events);

    if (group_peer_status == nullptr) {
        state->error = TOX_ERR_EVENTS_ITERATE_MALLOC;
        return;
    }

    tox_event_group_peer_status_set_group_number(group_peer_status, group_number);
    tox_event_group_peer_status_set_peer_id(group_peer_status, peer_id);
    tox_event_group_peer_status_set_status(group_peer_status, status);
}
