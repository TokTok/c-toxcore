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


struct Tox_Event_Group_Topic {
    uint32_t group_number;
    uint32_t peer_id;
    uint8_t *topic;
    uint32_t topic_length;
};

non_null()
static void tox_event_group_topic_construct(Tox_Event_Group_Topic *group_topic)
{
    *group_topic = (Tox_Event_Group_Topic) {
        0
    };
}
non_null()
static void tox_event_group_topic_destruct(Tox_Event_Group_Topic *group_topic)
{
    free(group_topic->topic);
}

non_null()
static void tox_event_group_topic_set_group_number(Tox_Event_Group_Topic *group_topic,
        uint32_t group_number)
{
    assert(group_topic != nullptr);
    group_topic->group_number = group_number;
}
uint32_t tox_event_group_topic_get_group_number(const Tox_Event_Group_Topic *group_topic)
{
    assert(group_topic != nullptr);
    return group_topic->group_number;
}

non_null()
static void tox_event_group_topic_set_peer_id(Tox_Event_Group_Topic *group_topic,
        uint32_t peer_id)
{
    assert(group_topic != nullptr);
    group_topic->peer_id = peer_id;
}
uint32_t tox_event_group_topic_get_peer_id(const Tox_Event_Group_Topic *group_topic)
{
    assert(group_topic != nullptr);
    return group_topic->peer_id;
}

non_null()
static bool tox_event_group_topic_set_topic(Tox_Event_Group_Topic *group_topic,
        const uint8_t *topic, uint32_t topic_length)
{
    assert(group_topic != nullptr);

    if (group_topic->topic != nullptr) {
        free(group_topic->topic);
        group_topic->topic = nullptr;
        group_topic->topic_length = 0;
    }

    group_topic->topic = (uint8_t *)malloc(topic_length);

    if (group_topic->topic == nullptr) {
        return false;
    }

    memcpy(group_topic->topic, topic, topic_length);
    group_topic->topic_length = topic_length;
    return true;
}
size_t tox_event_group_topic_get_topic_length(const Tox_Event_Group_Topic *group_topic)
{
    assert(group_topic != nullptr);
    return group_topic->topic_length;
}
const uint8_t *tox_event_group_topic_get_topic(const Tox_Event_Group_Topic *group_topic)
{
    assert(group_topic != nullptr);
    return group_topic->topic;
}

non_null()
static bool tox_event_group_topic_pack(
    const Tox_Event_Group_Topic *event, Bin_Pack *bp)
{
    assert(event != nullptr);
    return bin_pack_array(bp, 2)
           && bin_pack_u32(bp, TOX_EVENT_GROUP_TOPIC)
           && bin_pack_array(bp, 3)
           && bin_pack_u32(bp, event->group_number)
           && bin_pack_u32(bp, event->peer_id)
           && bin_pack_bin(bp, event->topic, event->topic_length);
}

non_null()
static bool tox_event_group_topic_unpack(
    Tox_Event_Group_Topic *event, Bin_Unpack *bu)
{
    assert(event != nullptr);
    if (!bin_unpack_array_fixed(bu, 3)) {
        return false;
    }

    return bin_unpack_u32(bu, &event->group_number)
           && bin_unpack_u32(bu, &event->peer_id)
           && bin_unpack_bin(bu, &event->topic, &event->topic_length);
}


/*****************************************************
 *
 * :: add/clear/get
 *
 *****************************************************/


non_null()
static Tox_Event_Group_Topic *tox_events_add_group_topic(Tox_Events *events)
{
    if (events->group_topic_size == UINT32_MAX) {
        return nullptr;
    }

    if (events->group_topic_size == events->group_topic_capacity) {
        const uint32_t new_group_topic_capacity = events->group_topic_capacity * 2 + 1;
        Tox_Event_Group_Topic *new_group_topic = (Tox_Event_Group_Topic *)
                realloc(
                    events->group_topic,
                    new_group_topic_capacity * sizeof(Tox_Event_Group_Topic));

        if (new_group_topic == nullptr) {
            return nullptr;
        }

        events->group_topic = new_group_topic;
        events->group_topic_capacity = new_group_topic_capacity;
    }

    Tox_Event_Group_Topic *const group_topic =
        &events->group_topic[events->group_topic_size];
    tox_event_group_topic_construct(group_topic);
    ++events->group_topic_size;
    return group_topic;
}

void tox_events_clear_group_topic(Tox_Events *events)
{
    if (events == nullptr) {
        return;
    }

    for (uint32_t i = 0; i < events->group_topic_size; ++i) {
        tox_event_group_topic_destruct(&events->group_topic[i]);
    }

    free(events->group_topic);
    events->group_topic = nullptr;
    events->group_topic_size = 0;
    events->group_topic_capacity = 0;
}

uint32_t tox_events_get_group_topic_size(const Tox_Events *events)
{
    if (events == nullptr) {
        return 0;
    }

    return events->group_topic_size;
}

const Tox_Event_Group_Topic *tox_events_get_group_topic(const Tox_Events *events, uint32_t index)
{
    assert(index < events->group_topic_size);
    assert(events->group_topic != nullptr);
    return &events->group_topic[index];
}

bool tox_events_pack_group_topic(const Tox_Events *events, Bin_Pack *bp)
{
    const uint32_t size = tox_events_get_group_topic_size(events);

    for (uint32_t i = 0; i < size; ++i) {
        if (!tox_event_group_topic_pack(tox_events_get_group_topic(events, i), bp)) {
            return false;
        }
    }
    return true;
}

bool tox_events_unpack_group_topic(Tox_Events *events, Bin_Unpack *bu)
{
    Tox_Event_Group_Topic *event = tox_events_add_group_topic(events);

    if (event == nullptr) {
        return false;
    }

    return tox_event_group_topic_unpack(event, bu);
}


/*****************************************************
 *
 * :: event handler
 *
 *****************************************************/


void tox_events_handle_group_topic(Tox *tox, uint32_t group_number, uint32_t peer_id, const uint8_t *topic, size_t length,
        void *user_data)
{
    Tox_Events_State *state = tox_events_alloc(user_data);
    assert(state != nullptr);

    if (state->events == nullptr) {
        return;
    }

    Tox_Event_Group_Topic *group_topic = tox_events_add_group_topic(state->events);

    if (group_topic == nullptr) {
        state->error = TOX_ERR_EVENTS_ITERATE_MALLOC;
        return;
    }

    tox_event_group_topic_set_group_number(group_topic, group_number);
    tox_event_group_topic_set_peer_id(group_topic, peer_id);
    tox_event_group_topic_set_topic(group_topic, topic, length);
}
