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


struct Tox_Event_Group_Moderation {
    uint32_t group_number;
    uint32_t source_peer_id;
    uint32_t target_peer_id;
    Tox_Group_Mod_Event mod_type;
};

non_null()
static void tox_event_group_moderation_construct(Tox_Event_Group_Moderation *group_moderation)
{
    *group_moderation = (Tox_Event_Group_Moderation) {
        0
    };
}
non_null()
static void tox_event_group_moderation_destruct(Tox_Event_Group_Moderation *group_moderation)
{
    return;
}

non_null()
static void tox_event_group_moderation_set_group_number(Tox_Event_Group_Moderation *group_moderation,
        uint32_t group_number)
{
    assert(group_moderation != nullptr);
    group_moderation->group_number = group_number;
}
uint32_t tox_event_group_moderation_get_group_number(const Tox_Event_Group_Moderation *group_moderation)
{
    assert(group_moderation != nullptr);
    return group_moderation->group_number;
}

non_null()
static void tox_event_group_moderation_set_source_peer_id(Tox_Event_Group_Moderation *group_moderation,
        uint32_t source_peer_id)
{
    assert(group_moderation != nullptr);
    group_moderation->source_peer_id = source_peer_id;
}
uint32_t tox_event_group_moderation_get_source_peer_id(const Tox_Event_Group_Moderation *group_moderation)
{
    assert(group_moderation != nullptr);
    return group_moderation->source_peer_id;
}

non_null()
static void tox_event_group_moderation_set_target_peer_id(Tox_Event_Group_Moderation *group_moderation,
        uint32_t target_peer_id)
{
    assert(group_moderation != nullptr);
    group_moderation->target_peer_id = target_peer_id;
}
uint32_t tox_event_group_moderation_get_target_peer_id(const Tox_Event_Group_Moderation *group_moderation)
{
    assert(group_moderation != nullptr);
    return group_moderation->target_peer_id;
}

non_null()
static void tox_event_group_moderation_set_mod_type(Tox_Event_Group_Moderation *group_moderation,
        Tox_Group_Mod_Event mod_type)
{
    assert(group_moderation != nullptr);
    group_moderation->mod_type = mod_type;
}
Tox_Group_Mod_Event tox_event_group_moderation_get_mod_type(const Tox_Event_Group_Moderation *group_moderation)
{
    assert(group_moderation != nullptr);
    return group_moderation->mod_type;
}

non_null()
static bool tox_event_group_moderation_pack(
    const Tox_Event_Group_Moderation *event, Bin_Pack *bp)
{
    assert(event != nullptr);
    return bin_pack_array(bp, 2)
           && bin_pack_u32(bp, TOX_EVENT_GROUP_MODERATION)
           && bin_pack_array(bp, 4)
           && bin_pack_u32(bp, event->group_number)
           && bin_pack_u32(bp, event->source_peer_id)
           && bin_pack_u32(bp, event->target_peer_id)
           && bin_pack_u32(bp, event->mod_type);
}

non_null()
static bool tox_event_group_moderation_unpack(
    Tox_Event_Group_Moderation *event, Bin_Unpack *bu)
{
    assert(event != nullptr);
    if (!bin_unpack_array_fixed(bu, 4)) {
        return false;
    }

    return bin_unpack_u32(bu, &event->group_number)
           && bin_unpack_u32(bu, &event->source_peer_id)
           && bin_unpack_u32(bu, &event->target_peer_id)
           && tox_unpack_group_mod_event(bu, &event->mod_type);
}


/*****************************************************
 *
 * :: add/clear/get
 *
 *****************************************************/


non_null()
static Tox_Event_Group_Moderation *tox_events_add_group_moderation(Tox_Events *events)
{
    if (events->group_moderation_size == UINT32_MAX) {
        return nullptr;
    }

    if (events->group_moderation_size == events->group_moderation_capacity) {
        const uint32_t new_group_moderation_capacity = events->group_moderation_capacity * 2 + 1;
        Tox_Event_Group_Moderation *new_group_moderation = (Tox_Event_Group_Moderation *)
                realloc(
                    events->group_moderation,
                    new_group_moderation_capacity * sizeof(Tox_Event_Group_Moderation));

        if (new_group_moderation == nullptr) {
            return nullptr;
        }

        events->group_moderation = new_group_moderation;
        events->group_moderation_capacity = new_group_moderation_capacity;
    }

    Tox_Event_Group_Moderation *const group_moderation =
        &events->group_moderation[events->group_moderation_size];
    tox_event_group_moderation_construct(group_moderation);
    ++events->group_moderation_size;
    return group_moderation;
}

void tox_events_clear_group_moderation(Tox_Events *events)
{
    if (events == nullptr) {
        return;
    }

    for (uint32_t i = 0; i < events->group_moderation_size; ++i) {
        tox_event_group_moderation_destruct(&events->group_moderation[i]);
    }

    free(events->group_moderation);
    events->group_moderation = nullptr;
    events->group_moderation_size = 0;
    events->group_moderation_capacity = 0;
}

uint32_t tox_events_get_group_moderation_size(const Tox_Events *events)
{
    if (events == nullptr) {
        return 0;
    }

    return events->group_moderation_size;
}

const Tox_Event_Group_Moderation *tox_events_get_group_moderation(const Tox_Events *events, uint32_t index)
{
    assert(index < events->group_moderation_size);
    assert(events->group_moderation != nullptr);
    return &events->group_moderation[index];
}

bool tox_events_pack_group_moderation(const Tox_Events *events, Bin_Pack *bp)
{
    const uint32_t size = tox_events_get_group_moderation_size(events);

    for (uint32_t i = 0; i < size; ++i) {
        if (!tox_event_group_moderation_pack(tox_events_get_group_moderation(events, i), bp)) {
            return false;
        }
    }
    return true;
}

bool tox_events_unpack_group_moderation(Tox_Events *events, Bin_Unpack *bu)
{
    Tox_Event_Group_Moderation *event = tox_events_add_group_moderation(events);

    if (event == nullptr) {
        return false;
    }

    return tox_event_group_moderation_unpack(event, bu);
}


/*****************************************************
 *
 * :: event handler
 *
 *****************************************************/


void tox_events_handle_group_moderation(Tox *tox, uint32_t group_number, uint32_t source_peer_id, uint32_t target_peer_id, Tox_Group_Mod_Event mod_type,
        void *user_data)
{
    Tox_Events_State *state = tox_events_alloc(user_data);
    assert(state != nullptr);

    if (state->events == nullptr) {
        return;
    }

    Tox_Event_Group_Moderation *group_moderation = tox_events_add_group_moderation(state->events);

    if (group_moderation == nullptr) {
        state->error = TOX_ERR_EVENTS_ITERATE_MALLOC;
        return;
    }

    tox_event_group_moderation_set_group_number(group_moderation, group_number);
    tox_event_group_moderation_set_source_peer_id(group_moderation, source_peer_id);
    tox_event_group_moderation_set_target_peer_id(group_moderation, target_peer_id);
    tox_event_group_moderation_set_mod_type(group_moderation, mod_type);
}
