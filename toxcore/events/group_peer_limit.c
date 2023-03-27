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


struct Tox_Event_Group_Peer_Limit {
    uint32_t group_number;
    uint32_t peer_limit;
};

non_null()
static void tox_event_group_peer_limit_construct(Tox_Event_Group_Peer_Limit *group_peer_limit)
{
    *group_peer_limit = (Tox_Event_Group_Peer_Limit) {
        0
    };
}
non_null()
static void tox_event_group_peer_limit_destruct(Tox_Event_Group_Peer_Limit *group_peer_limit)
{
    return;
}

non_null()
static void tox_event_group_peer_limit_set_group_number(Tox_Event_Group_Peer_Limit *group_peer_limit,
        uint32_t group_number)
{
    assert(group_peer_limit != nullptr);
    group_peer_limit->group_number = group_number;
}
uint32_t tox_event_group_peer_limit_get_group_number(const Tox_Event_Group_Peer_Limit *group_peer_limit)
{
    assert(group_peer_limit != nullptr);
    return group_peer_limit->group_number;
}

non_null()
static void tox_event_group_peer_limit_set_peer_limit(Tox_Event_Group_Peer_Limit *group_peer_limit,
        uint32_t peer_limit)
{
    assert(group_peer_limit != nullptr);
    group_peer_limit->peer_limit = peer_limit;
}
uint32_t tox_event_group_peer_limit_get_peer_limit(const Tox_Event_Group_Peer_Limit *group_peer_limit)
{
    assert(group_peer_limit != nullptr);
    return group_peer_limit->peer_limit;
}

non_null()
static bool tox_event_group_peer_limit_pack(
    const Tox_Event_Group_Peer_Limit *event, Bin_Pack *bp)
{
    assert(event != nullptr);
    return bin_pack_array(bp, 2)
           && bin_pack_u32(bp, TOX_EVENT_GROUP_PEER_LIMIT)
           && bin_pack_array(bp, 2)
           && bin_pack_u32(bp, event->group_number)
           && bin_pack_u32(bp, event->peer_limit);
}

non_null()
static bool tox_event_group_peer_limit_unpack(
    Tox_Event_Group_Peer_Limit *event, Bin_Unpack *bu)
{
    assert(event != nullptr);
    if (!bin_unpack_array_fixed(bu, 2)) {
        return false;
    }

    return bin_unpack_u32(bu, &event->group_number)
           && bin_unpack_u32(bu, &event->peer_limit);
}


/*****************************************************
 *
 * :: add/clear/get
 *
 *****************************************************/


non_null()
static Tox_Event_Group_Peer_Limit *tox_events_add_group_peer_limit(Tox_Events *events)
{
    if (events->group_peer_limit_size == UINT32_MAX) {
        return nullptr;
    }

    if (events->group_peer_limit_size == events->group_peer_limit_capacity) {
        const uint32_t new_group_peer_limit_capacity = events->group_peer_limit_capacity * 2 + 1;
        Tox_Event_Group_Peer_Limit *new_group_peer_limit = (Tox_Event_Group_Peer_Limit *)
                realloc(
                    events->group_peer_limit,
                    new_group_peer_limit_capacity * sizeof(Tox_Event_Group_Peer_Limit));

        if (new_group_peer_limit == nullptr) {
            return nullptr;
        }

        events->group_peer_limit = new_group_peer_limit;
        events->group_peer_limit_capacity = new_group_peer_limit_capacity;
    }

    Tox_Event_Group_Peer_Limit *const group_peer_limit =
        &events->group_peer_limit[events->group_peer_limit_size];
    tox_event_group_peer_limit_construct(group_peer_limit);
    ++events->group_peer_limit_size;
    return group_peer_limit;
}

void tox_events_clear_group_peer_limit(Tox_Events *events)
{
    if (events == nullptr) {
        return;
    }

    for (uint32_t i = 0; i < events->group_peer_limit_size; ++i) {
        tox_event_group_peer_limit_destruct(&events->group_peer_limit[i]);
    }

    free(events->group_peer_limit);
    events->group_peer_limit = nullptr;
    events->group_peer_limit_size = 0;
    events->group_peer_limit_capacity = 0;
}

uint32_t tox_events_get_group_peer_limit_size(const Tox_Events *events)
{
    if (events == nullptr) {
        return 0;
    }

    return events->group_peer_limit_size;
}

const Tox_Event_Group_Peer_Limit *tox_events_get_group_peer_limit(const Tox_Events *events, uint32_t index)
{
    assert(index < events->group_peer_limit_size);
    assert(events->group_peer_limit != nullptr);
    return &events->group_peer_limit[index];
}

bool tox_events_pack_group_peer_limit(const Tox_Events *events, Bin_Pack *bp)
{
    const uint32_t size = tox_events_get_group_peer_limit_size(events);

    for (uint32_t i = 0; i < size; ++i) {
        if (!tox_event_group_peer_limit_pack(tox_events_get_group_peer_limit(events, i), bp)) {
            return false;
        }
    }
    return true;
}

bool tox_events_unpack_group_peer_limit(Tox_Events *events, Bin_Unpack *bu)
{
    Tox_Event_Group_Peer_Limit *event = tox_events_add_group_peer_limit(events);

    if (event == nullptr) {
        return false;
    }

    return tox_event_group_peer_limit_unpack(event, bu);
}


/*****************************************************
 *
 * :: event handler
 *
 *****************************************************/


void tox_events_handle_group_peer_limit(Tox *tox, uint32_t group_number, uint32_t peer_limit,
        void *user_data)
{
    Tox_Events_State *state = tox_events_alloc(user_data);
    assert(state != nullptr);

    if (state->events == nullptr) {
        return;
    }

    Tox_Event_Group_Peer_Limit *group_peer_limit = tox_events_add_group_peer_limit(state->events);

    if (group_peer_limit == nullptr) {
        state->error = TOX_ERR_EVENTS_ITERATE_MALLOC;
        return;
    }

    tox_event_group_peer_limit_set_group_number(group_peer_limit, group_number);
    tox_event_group_peer_limit_set_peer_limit(group_peer_limit, peer_limit);
}
