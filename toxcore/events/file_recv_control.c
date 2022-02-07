/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2022 The TokTok team.
 */

#include "events_alloc.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "../ccompat.h"
#include "../tox.h"
#include "../tox_events.h"


/*****************************************************
 *
 * :: struct and accessors
 *
 *****************************************************/


struct Tox_Event_File_Recv_Control {
    uint32_t friend_number;
    uint32_t file_number;
    Tox_File_Control control;
};

static void tox_event_file_recv_control_pack(const Tox_Event_File_Recv_Control *event, msgpack_packer *mp)
{
    assert(event != nullptr);
    msgpack_pack_array(mp, 3);
    msgpack_pack_uint32(mp, event->friend_number);
    msgpack_pack_uint32(mp, event->file_number);
    msgpack_pack_uint32(mp, event->control);
}

static void tox_event_file_recv_control_construct(Tox_Event_File_Recv_Control *file_recv_control)
{
    *file_recv_control = (Tox_Event_File_Recv_Control) {
        0
    };
}
static void tox_event_file_recv_control_destruct(Tox_Event_File_Recv_Control *file_recv_control)
{
    return;
}

static void tox_event_file_recv_control_set_friend_number(Tox_Event_File_Recv_Control *file_recv_control,
        uint32_t friend_number)
{
    assert(file_recv_control != nullptr);
    file_recv_control->friend_number = friend_number;
}
uint32_t tox_event_file_recv_control_get_friend_number(const Tox_Event_File_Recv_Control *file_recv_control)
{
    assert(file_recv_control != nullptr);
    return file_recv_control->friend_number;
}

static void tox_event_file_recv_control_set_file_number(Tox_Event_File_Recv_Control *file_recv_control,
        uint32_t file_number)
{
    assert(file_recv_control != nullptr);
    file_recv_control->file_number = file_number;
}
uint32_t tox_event_file_recv_control_get_file_number(const Tox_Event_File_Recv_Control *file_recv_control)
{
    assert(file_recv_control != nullptr);
    return file_recv_control->file_number;
}

static void tox_event_file_recv_control_set_control(Tox_Event_File_Recv_Control *file_recv_control,
        Tox_File_Control control)
{
    assert(file_recv_control != nullptr);
    file_recv_control->control = control;
}
Tox_File_Control tox_event_file_recv_control_get_control(const Tox_Event_File_Recv_Control *file_recv_control)
{
    assert(file_recv_control != nullptr);
    return file_recv_control->control;
}


/*****************************************************
 *
 * :: add/clear/get
 *
 *****************************************************/


static Tox_Event_File_Recv_Control *tox_events_add_file_recv_control(Tox_Events *events)
{
    if (events->file_recv_control_size == UINT32_MAX) {
        return nullptr;
    }

    if (events->file_recv_control_size == events->file_recv_control_capacity) {
        const uint32_t new_file_recv_control_capacity = events->file_recv_control_capacity * 2 + 1;
        Tox_Event_File_Recv_Control *new_file_recv_control = (Tox_Event_File_Recv_Control *)realloc(
                    events->file_recv_control, new_file_recv_control_capacity * sizeof(Tox_Event_File_Recv_Control));

        if (new_file_recv_control == nullptr) {
            return nullptr;
        }

        events->file_recv_control = new_file_recv_control;
        events->file_recv_control_capacity = new_file_recv_control_capacity;
    }

    Tox_Event_File_Recv_Control *const file_recv_control = &events->file_recv_control[events->file_recv_control_size];
    tox_event_file_recv_control_construct(file_recv_control);
    ++events->file_recv_control_size;
    return file_recv_control;
}

void tox_events_clear_file_recv_control(Tox_Events *events)
{
    if (events == nullptr) {
        return;
    }

    for (uint32_t i = 0; i < events->file_recv_control_size; ++i) {
        tox_event_file_recv_control_destruct(&events->file_recv_control[i]);
    }

    free(events->file_recv_control);
    events->file_recv_control = nullptr;
    events->file_recv_control_size = 0;
    events->file_recv_control_capacity = 0;
}

uint32_t tox_events_get_file_recv_control_size(const Tox_Events *events)
{
    if (events == nullptr) {
        return 0;
    }

    return events->file_recv_control_size;
}

const Tox_Event_File_Recv_Control *tox_events_get_file_recv_control(const Tox_Events *events, uint32_t index)
{
    assert(index < events->file_recv_control_size);
    assert(events->file_recv_control != nullptr);
    return &events->file_recv_control[index];
}

void tox_events_pack_file_recv_control(const Tox_Events *events, msgpack_packer *mp)
{
    const uint32_t size = tox_events_get_file_recv_control_size(events);

    msgpack_pack_array(mp, size);

    for (uint32_t i = 0; i < size; ++i) {
        tox_event_file_recv_control_pack(tox_events_get_file_recv_control(events, i), mp);
    }
}


/*****************************************************
 *
 * :: event handler
 *
 *****************************************************/


void tox_events_handle_file_recv_control(Tox *tox, uint32_t friend_number, uint32_t file_number,
        Tox_File_Control control, void *user_data)
{
    Tox_Events_State *state = tox_events_alloc(user_data);
    assert(state != nullptr);

    Tox_Event_File_Recv_Control *file_recv_control = tox_events_add_file_recv_control(state->events);

    if (file_recv_control == nullptr) {
        state->error = TOX_ERR_EVENTS_ITERATE_MALLOC;
        return;
    }

    tox_event_file_recv_control_set_friend_number(file_recv_control, friend_number);
    tox_event_file_recv_control_set_file_number(file_recv_control, file_number);
    tox_event_file_recv_control_set_control(file_recv_control, control);
}
