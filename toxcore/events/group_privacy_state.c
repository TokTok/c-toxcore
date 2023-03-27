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


struct Tox_Event_Group_Privacy_State {
    uint32_t group_number;
    Tox_Group_Privacy_State privacy_state;
};

non_null()
static void tox_event_group_privacy_state_construct(Tox_Event_Group_Privacy_State *group_privacy_state)
{
    *group_privacy_state = (Tox_Event_Group_Privacy_State) {
        0
    };
}
non_null()
static void tox_event_group_privacy_state_destruct(Tox_Event_Group_Privacy_State *group_privacy_state)
{
    return;
}

non_null()
static void tox_event_group_privacy_state_set_group_number(Tox_Event_Group_Privacy_State *group_privacy_state,
        uint32_t group_number)
{
    assert(group_privacy_state != nullptr);
    group_privacy_state->group_number = group_number;
}
uint32_t tox_event_group_privacy_state_get_group_number(const Tox_Event_Group_Privacy_State *group_privacy_state)
{
    assert(group_privacy_state != nullptr);
    return group_privacy_state->group_number;
}

non_null()
static void tox_event_group_privacy_state_set_privacy_state(Tox_Event_Group_Privacy_State *group_privacy_state,
        Tox_Group_Privacy_State privacy_state)
{
    assert(group_privacy_state != nullptr);
    group_privacy_state->privacy_state = privacy_state;
}
Tox_Group_Privacy_State tox_event_group_privacy_state_get_privacy_state(const Tox_Event_Group_Privacy_State *group_privacy_state)
{
    assert(group_privacy_state != nullptr);
    return group_privacy_state->privacy_state;
}

non_null()
static bool tox_event_group_privacy_state_pack(
    const Tox_Event_Group_Privacy_State *event, Bin_Pack *bp)
{
    assert(event != nullptr);
    return bin_pack_array(bp, 2)
           && bin_pack_u32(bp, TOX_EVENT_GROUP_PRIVACY_STATE)
           && bin_pack_array(bp, 2)
           && bin_pack_u32(bp, event->group_number)
           && bin_pack_u32(bp, event->privacy_state);
}

non_null()
static bool tox_event_group_privacy_state_unpack(
    Tox_Event_Group_Privacy_State *event, Bin_Unpack *bu)
{
    assert(event != nullptr);
    if (!bin_unpack_array_fixed(bu, 2, nullptr)) {
        return false;
    }

    return bin_unpack_u32(bu, &event->group_number)
           && tox_unpack_group_privacy_state(bu, &event->privacy_state);
}


/*****************************************************
 *
 * :: add/clear/get
 *
 *****************************************************/


non_null()
static Tox_Event_Group_Privacy_State *tox_events_add_group_privacy_state(Tox_Events *events)
{
    if (events->group_privacy_state_size == UINT32_MAX) {
        return nullptr;
    }

    if (events->group_privacy_state_size == events->group_privacy_state_capacity) {
        const uint32_t new_group_privacy_state_capacity = events->group_privacy_state_capacity * 2 + 1;
        Tox_Event_Group_Privacy_State *new_group_privacy_state = (Tox_Event_Group_Privacy_State *)
                realloc(
                    events->group_privacy_state,
                    new_group_privacy_state_capacity * sizeof(Tox_Event_Group_Privacy_State));

        if (new_group_privacy_state == nullptr) {
            return nullptr;
        }

        events->group_privacy_state = new_group_privacy_state;
        events->group_privacy_state_capacity = new_group_privacy_state_capacity;
    }

    Tox_Event_Group_Privacy_State *const group_privacy_state =
        &events->group_privacy_state[events->group_privacy_state_size];
    tox_event_group_privacy_state_construct(group_privacy_state);
    ++events->group_privacy_state_size;
    return group_privacy_state;
}

void tox_events_clear_group_privacy_state(Tox_Events *events)
{
    if (events == nullptr) {
        return;
    }

    for (uint32_t i = 0; i < events->group_privacy_state_size; ++i) {
        tox_event_group_privacy_state_destruct(&events->group_privacy_state[i]);
    }

    free(events->group_privacy_state);
    events->group_privacy_state = nullptr;
    events->group_privacy_state_size = 0;
    events->group_privacy_state_capacity = 0;
}

uint32_t tox_events_get_group_privacy_state_size(const Tox_Events *events)
{
    if (events == nullptr) {
        return 0;
    }

    return events->group_privacy_state_size;
}

const Tox_Event_Group_Privacy_State *tox_events_get_group_privacy_state(const Tox_Events *events, uint32_t index)
{
    assert(index < events->group_privacy_state_size);
    assert(events->group_privacy_state != nullptr);
    return &events->group_privacy_state[index];
}

bool tox_events_pack_group_privacy_state(const Tox_Events *events, Bin_Pack *bp)
{
    const uint32_t size = tox_events_get_group_privacy_state_size(events);

    for (uint32_t i = 0; i < size; ++i) {
        if (!tox_event_group_privacy_state_pack(tox_events_get_group_privacy_state(events, i), bp)) {
            return false;
        }
    }
    return true;
}

bool tox_events_unpack_group_privacy_state(Tox_Events *events, Bin_Unpack *bu)
{
    Tox_Event_Group_Privacy_State *event = tox_events_add_group_privacy_state(events);

    if (event == nullptr) {
        return false;
    }

    return tox_event_group_privacy_state_unpack(event, bu);
}


/*****************************************************
 *
 * :: event handler
 *
 *****************************************************/


void tox_events_handle_group_privacy_state(Tox *tox, uint32_t group_number, Tox_Group_Privacy_State privacy_state,
        void *user_data)
{
    Tox_Events_State *state = tox_events_alloc(user_data);
    assert(state != nullptr);

    if (state->events == nullptr) {
        return;
    }

    Tox_Event_Group_Privacy_State *group_privacy_state = tox_events_add_group_privacy_state(state->events);

    if (group_privacy_state == nullptr) {
        state->error = TOX_ERR_EVENTS_ITERATE_MALLOC;
        return;
    }

    tox_event_group_privacy_state_set_group_number(group_privacy_state, group_number);
    tox_event_group_privacy_state_set_privacy_state(group_privacy_state, privacy_state);
}
