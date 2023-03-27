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


struct Tox_Event_Group_Custom_Packet {
    uint32_t group_number;
    uint32_t peer_id;
    uint8_t *data;
    uint32_t data_length;
};

non_null()
static void tox_event_group_custom_packet_construct(Tox_Event_Group_Custom_Packet *group_custom_packet)
{
    *group_custom_packet = (Tox_Event_Group_Custom_Packet) {
        0
    };
}
non_null()
static void tox_event_group_custom_packet_destruct(Tox_Event_Group_Custom_Packet *group_custom_packet)
{
    free(group_custom_packet->data);
}

non_null()
static void tox_event_group_custom_packet_set_group_number(Tox_Event_Group_Custom_Packet *group_custom_packet,
        uint32_t group_number)
{
    assert(group_custom_packet != nullptr);
    group_custom_packet->group_number = group_number;
}
uint32_t tox_event_group_custom_packet_get_group_number(const Tox_Event_Group_Custom_Packet *group_custom_packet)
{
    assert(group_custom_packet != nullptr);
    return group_custom_packet->group_number;
}

non_null()
static void tox_event_group_custom_packet_set_peer_id(Tox_Event_Group_Custom_Packet *group_custom_packet,
        uint32_t peer_id)
{
    assert(group_custom_packet != nullptr);
    group_custom_packet->peer_id = peer_id;
}
uint32_t tox_event_group_custom_packet_get_peer_id(const Tox_Event_Group_Custom_Packet *group_custom_packet)
{
    assert(group_custom_packet != nullptr);
    return group_custom_packet->peer_id;
}

non_null()
static bool tox_event_group_custom_packet_set_data(Tox_Event_Group_Custom_Packet *group_custom_packet,
        const uint8_t *data, uint32_t data_length)
{
    assert(group_custom_packet != nullptr);

    if (group_custom_packet->data != nullptr) {
        free(group_custom_packet->data);
        group_custom_packet->data = nullptr;
        group_custom_packet->data_length = 0;
    }

    group_custom_packet->data = (uint8_t *)malloc(data_length);

    if (group_custom_packet->data == nullptr) {
        return false;
    }

    memcpy(group_custom_packet->data, data, data_length);
    group_custom_packet->data_length = data_length;
    return true;
}
size_t tox_event_group_custom_packet_get_data_length(const Tox_Event_Group_Custom_Packet *group_custom_packet)
{
    assert(group_custom_packet != nullptr);
    return group_custom_packet->data_length;
}
const uint8_t *tox_event_group_custom_packet_get_data(const Tox_Event_Group_Custom_Packet *group_custom_packet)
{
    assert(group_custom_packet != nullptr);
    return group_custom_packet->data;
}

non_null()
static bool tox_event_group_custom_packet_pack(
    const Tox_Event_Group_Custom_Packet *event, Bin_Pack *bp)
{
    assert(event != nullptr);
    return bin_pack_array(bp, 2)
           && bin_pack_u32(bp, TOX_EVENT_GROUP_CUSTOM_PACKET)
           && bin_pack_array(bp, 3)
           && bin_pack_u32(bp, event->group_number)
           && bin_pack_u32(bp, event->peer_id)
           && bin_pack_bin(bp, event->data, event->data_length);
}

non_null()
static bool tox_event_group_custom_packet_unpack(
    Tox_Event_Group_Custom_Packet *event, Bin_Unpack *bu)
{
    assert(event != nullptr);
    if (!bin_unpack_array_fixed(bu, 3)) {
        return false;
    }

    return bin_unpack_u32(bu, &event->group_number)
           && bin_unpack_u32(bu, &event->peer_id)
           && bin_unpack_bin(bu, &event->data, &event->data_length);
}


/*****************************************************
 *
 * :: add/clear/get
 *
 *****************************************************/


non_null()
static Tox_Event_Group_Custom_Packet *tox_events_add_group_custom_packet(Tox_Events *events)
{
    if (events->group_custom_packet_size == UINT32_MAX) {
        return nullptr;
    }

    if (events->group_custom_packet_size == events->group_custom_packet_capacity) {
        const uint32_t new_group_custom_packet_capacity = events->group_custom_packet_capacity * 2 + 1;
        Tox_Event_Group_Custom_Packet *new_group_custom_packet = (Tox_Event_Group_Custom_Packet *)
                realloc(
                    events->group_custom_packet,
                    new_group_custom_packet_capacity * sizeof(Tox_Event_Group_Custom_Packet));

        if (new_group_custom_packet == nullptr) {
            return nullptr;
        }

        events->group_custom_packet = new_group_custom_packet;
        events->group_custom_packet_capacity = new_group_custom_packet_capacity;
    }

    Tox_Event_Group_Custom_Packet *const group_custom_packet =
        &events->group_custom_packet[events->group_custom_packet_size];
    tox_event_group_custom_packet_construct(group_custom_packet);
    ++events->group_custom_packet_size;
    return group_custom_packet;
}

void tox_events_clear_group_custom_packet(Tox_Events *events)
{
    if (events == nullptr) {
        return;
    }

    for (uint32_t i = 0; i < events->group_custom_packet_size; ++i) {
        tox_event_group_custom_packet_destruct(&events->group_custom_packet[i]);
    }

    free(events->group_custom_packet);
    events->group_custom_packet = nullptr;
    events->group_custom_packet_size = 0;
    events->group_custom_packet_capacity = 0;
}

uint32_t tox_events_get_group_custom_packet_size(const Tox_Events *events)
{
    if (events == nullptr) {
        return 0;
    }

    return events->group_custom_packet_size;
}

const Tox_Event_Group_Custom_Packet *tox_events_get_group_custom_packet(const Tox_Events *events, uint32_t index)
{
    assert(index < events->group_custom_packet_size);
    assert(events->group_custom_packet != nullptr);
    return &events->group_custom_packet[index];
}

bool tox_events_pack_group_custom_packet(const Tox_Events *events, Bin_Pack *bp)
{
    const uint32_t size = tox_events_get_group_custom_packet_size(events);

    for (uint32_t i = 0; i < size; ++i) {
        if (!tox_event_group_custom_packet_pack(tox_events_get_group_custom_packet(events, i), bp)) {
            return false;
        }
    }
    return true;
}

bool tox_events_unpack_group_custom_packet(Tox_Events *events, Bin_Unpack *bu)
{
    Tox_Event_Group_Custom_Packet *event = tox_events_add_group_custom_packet(events);

    if (event == nullptr) {
        return false;
    }

    return tox_event_group_custom_packet_unpack(event, bu);
}


/*****************************************************
 *
 * :: event handler
 *
 *****************************************************/


void tox_events_handle_group_custom_packet(Tox *tox, uint32_t group_number, uint32_t peer_id, const uint8_t *data, size_t length,
        void *user_data)
{
    Tox_Events_State *state = tox_events_alloc(user_data);
    assert(state != nullptr);

    if (state->events == nullptr) {
        return;
    }

    Tox_Event_Group_Custom_Packet *group_custom_packet = tox_events_add_group_custom_packet(state->events);

    if (group_custom_packet == nullptr) {
        state->error = TOX_ERR_EVENTS_ITERATE_MALLOC;
        return;
    }

    tox_event_group_custom_packet_set_group_number(group_custom_packet, group_number);
    tox_event_group_custom_packet_set_peer_id(group_custom_packet, peer_id);
    tox_event_group_custom_packet_set_data(group_custom_packet, data, length);
}
