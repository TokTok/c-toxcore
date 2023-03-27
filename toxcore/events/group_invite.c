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


struct Tox_Event_Group_Invite {
    uint32_t friend_number;
    uint8_t *invite_data;
    uint32_t invite_data_length;
    uint8_t *group_name;
    uint32_t group_name_length;
};

non_null()
static void tox_event_group_invite_construct(Tox_Event_Group_Invite *group_invite)
{
    *group_invite = (Tox_Event_Group_Invite) {
        0
    };
}
non_null()
static void tox_event_group_invite_destruct(Tox_Event_Group_Invite *group_invite)
{
    free(group_invite->invite_data);
    free(group_invite->group_name);
}

non_null()
static void tox_event_group_invite_set_friend_number(Tox_Event_Group_Invite *group_invite,
        uint32_t friend_number)
{
    assert(group_invite != nullptr);
    group_invite->friend_number = friend_number;
}
uint32_t tox_event_group_invite_get_friend_number(const Tox_Event_Group_Invite *group_invite)
{
    assert(group_invite != nullptr);
    return group_invite->friend_number;
}

non_null()
static bool tox_event_group_invite_set_invite_data(Tox_Event_Group_Invite *group_invite,
        const uint8_t *invite_data, uint32_t invite_data_length)
{
    assert(group_invite != nullptr);

    if (group_invite->invite_data != nullptr) {
        free(group_invite->invite_data);
        group_invite->invite_data = nullptr;
        group_invite->invite_data_length = 0;
    }

    group_invite->invite_data = (uint8_t *)malloc(invite_data_length);

    if (group_invite->invite_data == nullptr) {
        return false;
    }

    memcpy(group_invite->invite_data, invite_data, invite_data_length);
    group_invite->invite_data_length = invite_data_length;
    return true;
}
size_t tox_event_group_invite_get_invite_data_length(const Tox_Event_Group_Invite *group_invite)
{
    assert(group_invite != nullptr);
    return group_invite->invite_data_length;
}
const uint8_t *tox_event_group_invite_get_invite_data(const Tox_Event_Group_Invite *group_invite)
{
    assert(group_invite != nullptr);
    return group_invite->invite_data;
}

non_null()
static bool tox_event_group_invite_set_group_name(Tox_Event_Group_Invite *group_invite,
        const uint8_t *group_name, uint32_t group_name_length)
{
    assert(group_invite != nullptr);

    if (group_invite->group_name != nullptr) {
        free(group_invite->group_name);
        group_invite->group_name = nullptr;
        group_invite->group_name_length = 0;
    }

    group_invite->group_name = (uint8_t *)malloc(group_name_length);

    if (group_invite->group_name == nullptr) {
        return false;
    }

    memcpy(group_invite->group_name, group_name, group_name_length);
    group_invite->group_name_length = group_name_length;
    return true;
}
size_t tox_event_group_invite_get_group_name_length(const Tox_Event_Group_Invite *group_invite)
{
    assert(group_invite != nullptr);
    return group_invite->group_name_length;
}
const uint8_t *tox_event_group_invite_get_group_name(const Tox_Event_Group_Invite *group_invite)
{
    assert(group_invite != nullptr);
    return group_invite->group_name;
}

non_null()
static bool tox_event_group_invite_pack(
    const Tox_Event_Group_Invite *event, Bin_Pack *bp)
{
    assert(event != nullptr);
    return bin_pack_array(bp, 2)
           && bin_pack_u32(bp, TOX_EVENT_GROUP_INVITE)
           && bin_pack_array(bp, 3)
           && bin_pack_u32(bp, event->friend_number)
           && bin_pack_bin(bp, event->invite_data, event->invite_data_length)
           && bin_pack_bin(bp, event->group_name, event->group_name_length);
}

non_null()
static bool tox_event_group_invite_unpack(
    Tox_Event_Group_Invite *event, Bin_Unpack *bu)
{
    assert(event != nullptr);
    if (!bin_unpack_array_fixed(bu, 3)) {
        return false;
    }

    return bin_unpack_u32(bu, &event->friend_number)
           && bin_unpack_bin(bu, &event->invite_data, &event->invite_data_length)
           && bin_unpack_bin(bu, &event->group_name, &event->group_name_length);
}


/*****************************************************
 *
 * :: add/clear/get
 *
 *****************************************************/


non_null()
static Tox_Event_Group_Invite *tox_events_add_group_invite(Tox_Events *events)
{
    if (events->group_invite_size == UINT32_MAX) {
        return nullptr;
    }

    if (events->group_invite_size == events->group_invite_capacity) {
        const uint32_t new_group_invite_capacity = events->group_invite_capacity * 2 + 1;
        Tox_Event_Group_Invite *new_group_invite = (Tox_Event_Group_Invite *)
                realloc(
                    events->group_invite,
                    new_group_invite_capacity * sizeof(Tox_Event_Group_Invite));

        if (new_group_invite == nullptr) {
            return nullptr;
        }

        events->group_invite = new_group_invite;
        events->group_invite_capacity = new_group_invite_capacity;
    }

    Tox_Event_Group_Invite *const group_invite =
        &events->group_invite[events->group_invite_size];
    tox_event_group_invite_construct(group_invite);
    ++events->group_invite_size;
    return group_invite;
}

void tox_events_clear_group_invite(Tox_Events *events)
{
    if (events == nullptr) {
        return;
    }

    for (uint32_t i = 0; i < events->group_invite_size; ++i) {
        tox_event_group_invite_destruct(&events->group_invite[i]);
    }

    free(events->group_invite);
    events->group_invite = nullptr;
    events->group_invite_size = 0;
    events->group_invite_capacity = 0;
}

uint32_t tox_events_get_group_invite_size(const Tox_Events *events)
{
    if (events == nullptr) {
        return 0;
    }

    return events->group_invite_size;
}

const Tox_Event_Group_Invite *tox_events_get_group_invite(const Tox_Events *events, uint32_t index)
{
    assert(index < events->group_invite_size);
    assert(events->group_invite != nullptr);
    return &events->group_invite[index];
}

bool tox_events_pack_group_invite(const Tox_Events *events, Bin_Pack *bp)
{
    const uint32_t size = tox_events_get_group_invite_size(events);

    for (uint32_t i = 0; i < size; ++i) {
        if (!tox_event_group_invite_pack(tox_events_get_group_invite(events, i), bp)) {
            return false;
        }
    }
    return true;
}

bool tox_events_unpack_group_invite(Tox_Events *events, Bin_Unpack *bu)
{
    Tox_Event_Group_Invite *event = tox_events_add_group_invite(events);

    if (event == nullptr) {
        return false;
    }

    return tox_event_group_invite_unpack(event, bu);
}


/*****************************************************
 *
 * :: event handler
 *
 *****************************************************/


void tox_events_handle_group_invite(Tox *tox, uint32_t friend_number, const uint8_t *invite_data, size_t length, const uint8_t *group_name, size_t group_name_length,
        void *user_data)
{
    Tox_Events_State *state = tox_events_alloc(user_data);
    assert(state != nullptr);

    if (state->events == nullptr) {
        return;
    }

    Tox_Event_Group_Invite *group_invite = tox_events_add_group_invite(state->events);

    if (group_invite == nullptr) {
        state->error = TOX_ERR_EVENTS_ITERATE_MALLOC;
        return;
    }

    tox_event_group_invite_set_friend_number(group_invite, friend_number);
    tox_event_group_invite_set_invite_data(group_invite, invite_data, length);
    tox_event_group_invite_set_group_name(group_invite, group_name, group_name_length);
}
