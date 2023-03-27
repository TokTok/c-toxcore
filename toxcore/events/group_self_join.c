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


struct Tox_Event_Group_Self_Join {
    uint32_t group_number;
};

non_null()
static void tox_event_group_self_join_construct(Tox_Event_Group_Self_Join *group_self_join)
{
    *group_self_join = (Tox_Event_Group_Self_Join) {
        0
    };
}
non_null()
static void tox_event_group_self_join_destruct(Tox_Event_Group_Self_Join *group_self_join)
{
    return;
}

non_null()
static void tox_event_group_self_join_set_group_number(Tox_Event_Group_Self_Join *group_self_join,
        uint32_t group_number)
{
    assert(group_self_join != nullptr);
    group_self_join->group_number = group_number;
}
uint32_t tox_event_group_self_join_get_group_number(const Tox_Event_Group_Self_Join *group_self_join)
{
    assert(group_self_join != nullptr);
    return group_self_join->group_number;
}

non_null()
static bool tox_event_group_self_join_pack(
    const Tox_Event_Group_Self_Join *event, Bin_Pack *bp)
{
    assert(event != nullptr);
    return bin_pack_array(bp, 2)
           && bin_pack_u32(bp, TOX_EVENT_GROUP_SELF_JOIN)

           && bin_pack_u32(bp, event->group_number);
}

non_null()
static bool tox_event_group_self_join_unpack(
    Tox_Event_Group_Self_Join *event, Bin_Unpack *bu)
{
    assert(event != nullptr);
    return bin_unpack_u32(bu, &event->group_number);
}


/*****************************************************
 *
 * :: add/clear/get
 *
 *****************************************************/


non_null()
static Tox_Event_Group_Self_Join *tox_events_add_group_self_join(Tox_Events *events)
{
    if (events->group_self_join_size == UINT32_MAX) {
        return nullptr;
    }

    if (events->group_self_join_size == events->group_self_join_capacity) {
        const uint32_t new_group_self_join_capacity = events->group_self_join_capacity * 2 + 1;
        Tox_Event_Group_Self_Join *new_group_self_join = (Tox_Event_Group_Self_Join *)
                realloc(
                    events->group_self_join,
                    new_group_self_join_capacity * sizeof(Tox_Event_Group_Self_Join));

        if (new_group_self_join == nullptr) {
            return nullptr;
        }

        events->group_self_join = new_group_self_join;
        events->group_self_join_capacity = new_group_self_join_capacity;
    }

    Tox_Event_Group_Self_Join *const group_self_join =
        &events->group_self_join[events->group_self_join_size];
    tox_event_group_self_join_construct(group_self_join);
    ++events->group_self_join_size;
    return group_self_join;
}

void tox_events_clear_group_self_join(Tox_Events *events)
{
    if (events == nullptr) {
        return;
    }

    for (uint32_t i = 0; i < events->group_self_join_size; ++i) {
        tox_event_group_self_join_destruct(&events->group_self_join[i]);
    }

    free(events->group_self_join);
    events->group_self_join = nullptr;
    events->group_self_join_size = 0;
    events->group_self_join_capacity = 0;
}

uint32_t tox_events_get_group_self_join_size(const Tox_Events *events)
{
    if (events == nullptr) {
        return 0;
    }

    return events->group_self_join_size;
}

const Tox_Event_Group_Self_Join *tox_events_get_group_self_join(const Tox_Events *events, uint32_t index)
{
    assert(index < events->group_self_join_size);
    assert(events->group_self_join != nullptr);
    return &events->group_self_join[index];
}

bool tox_events_pack_group_self_join(const Tox_Events *events, Bin_Pack *bp)
{
    const uint32_t size = tox_events_get_group_self_join_size(events);

    for (uint32_t i = 0; i < size; ++i) {
        if (!tox_event_group_self_join_pack(tox_events_get_group_self_join(events, i), bp)) {
            return false;
        }
    }
    return true;
}

bool tox_events_unpack_group_self_join(Tox_Events *events, Bin_Unpack *bu)
{
    Tox_Event_Group_Self_Join *event = tox_events_add_group_self_join(events);

    if (event == nullptr) {
        return false;
    }

    return tox_event_group_self_join_unpack(event, bu);
}


/*****************************************************
 *
 * :: event handler
 *
 *****************************************************/


void tox_events_handle_group_self_join(Tox *tox, uint32_t group_number,
        void *user_data)
{
    Tox_Events_State *state = tox_events_alloc(user_data);
    assert(state != nullptr);

    if (state->events == nullptr) {
        return;
    }

    Tox_Event_Group_Self_Join *group_self_join = tox_events_add_group_self_join(state->events);

    if (group_self_join == nullptr) {
        state->error = TOX_ERR_EVENTS_ITERATE_MALLOC;
        return;
    }

    tox_event_group_self_join_set_group_number(group_self_join, group_number);
}
