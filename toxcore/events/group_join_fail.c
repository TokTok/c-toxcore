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


struct Tox_Event_Group_Join_Fail {
    uint32_t group_number;
    Tox_Group_Join_Fail fail_type;
};

non_null()
static void tox_event_group_join_fail_construct(Tox_Event_Group_Join_Fail *group_join_fail)
{
    *group_join_fail = (Tox_Event_Group_Join_Fail) {
        0
    };
}
non_null()
static void tox_event_group_join_fail_destruct(Tox_Event_Group_Join_Fail *group_join_fail)
{
    return;
}

non_null()
static void tox_event_group_join_fail_set_group_number(Tox_Event_Group_Join_Fail *group_join_fail,
        uint32_t group_number)
{
    assert(group_join_fail != nullptr);
    group_join_fail->group_number = group_number;
}
uint32_t tox_event_group_join_fail_get_group_number(const Tox_Event_Group_Join_Fail *group_join_fail)
{
    assert(group_join_fail != nullptr);
    return group_join_fail->group_number;
}

non_null()
static void tox_event_group_join_fail_set_fail_type(Tox_Event_Group_Join_Fail *group_join_fail,
        Tox_Group_Join_Fail fail_type)
{
    assert(group_join_fail != nullptr);
    group_join_fail->fail_type = fail_type;
}
Tox_Group_Join_Fail tox_event_group_join_fail_get_fail_type(const Tox_Event_Group_Join_Fail *group_join_fail)
{
    assert(group_join_fail != nullptr);
    return group_join_fail->fail_type;
}

non_null()
static bool tox_event_group_join_fail_pack(
    const Tox_Event_Group_Join_Fail *event, Bin_Pack *bp)
{
    assert(event != nullptr);
    return bin_pack_array(bp, 2)
           && bin_pack_u32(bp, TOX_EVENT_GROUP_JOIN_FAIL)
           && bin_pack_array(bp, 2)
           && bin_pack_u32(bp, event->group_number)
           && bin_pack_u32(bp, event->fail_type);
}

non_null()
static bool tox_event_group_join_fail_unpack(
    Tox_Event_Group_Join_Fail *event, Bin_Unpack *bu)
{
    assert(event != nullptr);
    if (!bin_unpack_array_fixed(bu, 2)) {
        return false;
    }

    return bin_unpack_u32(bu, &event->group_number)
           && tox_unpack_group_join_fail(bu, &event->fail_type);
}


/*****************************************************
 *
 * :: add/clear/get
 *
 *****************************************************/


non_null()
static Tox_Event_Group_Join_Fail *tox_events_add_group_join_fail(Tox_Events *events)
{
    if (events->group_join_fail_size == UINT32_MAX) {
        return nullptr;
    }

    if (events->group_join_fail_size == events->group_join_fail_capacity) {
        const uint32_t new_group_join_fail_capacity = events->group_join_fail_capacity * 2 + 1;
        Tox_Event_Group_Join_Fail *new_group_join_fail = (Tox_Event_Group_Join_Fail *)
                realloc(
                    events->group_join_fail,
                    new_group_join_fail_capacity * sizeof(Tox_Event_Group_Join_Fail));

        if (new_group_join_fail == nullptr) {
            return nullptr;
        }

        events->group_join_fail = new_group_join_fail;
        events->group_join_fail_capacity = new_group_join_fail_capacity;
    }

    Tox_Event_Group_Join_Fail *const group_join_fail =
        &events->group_join_fail[events->group_join_fail_size];
    tox_event_group_join_fail_construct(group_join_fail);
    ++events->group_join_fail_size;
    return group_join_fail;
}

void tox_events_clear_group_join_fail(Tox_Events *events)
{
    if (events == nullptr) {
        return;
    }

    for (uint32_t i = 0; i < events->group_join_fail_size; ++i) {
        tox_event_group_join_fail_destruct(&events->group_join_fail[i]);
    }

    free(events->group_join_fail);
    events->group_join_fail = nullptr;
    events->group_join_fail_size = 0;
    events->group_join_fail_capacity = 0;
}

uint32_t tox_events_get_group_join_fail_size(const Tox_Events *events)
{
    if (events == nullptr) {
        return 0;
    }

    return events->group_join_fail_size;
}

const Tox_Event_Group_Join_Fail *tox_events_get_group_join_fail(const Tox_Events *events, uint32_t index)
{
    assert(index < events->group_join_fail_size);
    assert(events->group_join_fail != nullptr);
    return &events->group_join_fail[index];
}

bool tox_events_pack_group_join_fail(const Tox_Events *events, Bin_Pack *bp)
{
    const uint32_t size = tox_events_get_group_join_fail_size(events);

    for (uint32_t i = 0; i < size; ++i) {
        if (!tox_event_group_join_fail_pack(tox_events_get_group_join_fail(events, i), bp)) {
            return false;
        }
    }
    return true;
}

bool tox_events_unpack_group_join_fail(Tox_Events *events, Bin_Unpack *bu)
{
    Tox_Event_Group_Join_Fail *event = tox_events_add_group_join_fail(events);

    if (event == nullptr) {
        return false;
    }

    return tox_event_group_join_fail_unpack(event, bu);
}


/*****************************************************
 *
 * :: event handler
 *
 *****************************************************/


void tox_events_handle_group_join_fail(Tox *tox, uint32_t group_number, Tox_Group_Join_Fail fail_type,
        void *user_data)
{
    Tox_Events_State *state = tox_events_alloc(user_data);
    assert(state != nullptr);

    if (state->events == nullptr) {
        return;
    }

    Tox_Event_Group_Join_Fail *group_join_fail = tox_events_add_group_join_fail(state->events);

    if (group_join_fail == nullptr) {
        state->error = TOX_ERR_EVENTS_ITERATE_MALLOC;
        return;
    }

    tox_event_group_join_fail_set_group_number(group_join_fail, group_number);
    tox_event_group_join_fail_set_fail_type(group_join_fail, fail_type);
}
