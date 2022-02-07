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


struct Tox_Event_File_Chunk_Request {
    uint32_t friend_number;
    uint32_t file_number;
    uint64_t position;
    size_t length;
};

static void tox_event_file_chunk_request_construct(Tox_Event_File_Chunk_Request *file_chunk_request)
{
    *file_chunk_request = (Tox_Event_File_Chunk_Request) {
        0
    };
}
static void tox_event_file_chunk_request_destruct(Tox_Event_File_Chunk_Request *file_chunk_request)
{
    return;
}

static void tox_event_file_chunk_request_set_friend_number(Tox_Event_File_Chunk_Request *file_chunk_request,
        uint32_t friend_number)
{
    assert(file_chunk_request != nullptr);
    file_chunk_request->friend_number = friend_number;
}
uint32_t tox_event_file_chunk_request_get_friend_number(const Tox_Event_File_Chunk_Request *file_chunk_request)
{
    assert(file_chunk_request != nullptr);
    return file_chunk_request->friend_number;
}

static void tox_event_file_chunk_request_set_file_number(Tox_Event_File_Chunk_Request *file_chunk_request,
        uint32_t file_number)
{
    assert(file_chunk_request != nullptr);
    file_chunk_request->file_number = file_number;
}
uint32_t tox_event_file_chunk_request_get_file_number(const Tox_Event_File_Chunk_Request *file_chunk_request)
{
    assert(file_chunk_request != nullptr);
    return file_chunk_request->file_number;
}

static void tox_event_file_chunk_request_set_position(Tox_Event_File_Chunk_Request *file_chunk_request,
        uint64_t position)
{
    assert(file_chunk_request != nullptr);
    file_chunk_request->position = position;
}
uint64_t tox_event_file_chunk_request_get_position(const Tox_Event_File_Chunk_Request *file_chunk_request)
{
    assert(file_chunk_request != nullptr);
    return file_chunk_request->position;
}

static void tox_event_file_chunk_request_set_length(Tox_Event_File_Chunk_Request *file_chunk_request, size_t length)
{
    assert(file_chunk_request != nullptr);
    file_chunk_request->length = length;
}
size_t tox_event_file_chunk_request_get_length(const Tox_Event_File_Chunk_Request *file_chunk_request)
{
    assert(file_chunk_request != nullptr);
    return file_chunk_request->length;
}

static void tox_event_file_chunk_request_pack(const Tox_Event_File_Chunk_Request *event, msgpack_packer *mp)
{
    assert(event != nullptr);
    msgpack_pack_array(mp, 4);
    msgpack_pack_uint32(mp, event->friend_number);
    msgpack_pack_uint32(mp, event->file_number);
    msgpack_pack_uint64(mp, event->position);
    msgpack_pack_uint16(mp, event->length);
}


/*****************************************************
 *
 * :: add/clear/get
 *
 *****************************************************/


static Tox_Event_File_Chunk_Request *tox_events_add_file_chunk_request(Tox_Events *events)
{
    if (events->file_chunk_request_size == UINT32_MAX) {
        return nullptr;
    }

    if (events->file_chunk_request_size == events->file_chunk_request_capacity) {
        const uint32_t new_file_chunk_request_capacity = events->file_chunk_request_capacity * 2 + 1;
        Tox_Event_File_Chunk_Request *new_file_chunk_request = (Tox_Event_File_Chunk_Request *)realloc(
                    events->file_chunk_request, new_file_chunk_request_capacity * sizeof(Tox_Event_File_Chunk_Request));

        if (new_file_chunk_request == nullptr) {
            return nullptr;
        }

        events->file_chunk_request = new_file_chunk_request;
        events->file_chunk_request_capacity = new_file_chunk_request_capacity;
    }

    Tox_Event_File_Chunk_Request *const file_chunk_request = &events->file_chunk_request[events->file_chunk_request_size];
    tox_event_file_chunk_request_construct(file_chunk_request);
    ++events->file_chunk_request_size;
    return file_chunk_request;
}

void tox_events_clear_file_chunk_request(Tox_Events *events)
{
    if (events == nullptr) {
        return;
    }

    for (uint32_t i = 0; i < events->file_chunk_request_size; ++i) {
        tox_event_file_chunk_request_destruct(&events->file_chunk_request[i]);
    }

    free(events->file_chunk_request);
    events->file_chunk_request = nullptr;
    events->file_chunk_request_size = 0;
    events->file_chunk_request_capacity = 0;
}

uint32_t tox_events_get_file_chunk_request_size(const Tox_Events *events)
{
    if (events == nullptr) {
        return 0;
    }

    return events->file_chunk_request_size;
}

const Tox_Event_File_Chunk_Request *tox_events_get_file_chunk_request(const Tox_Events *events, uint32_t index)
{
    assert(index < events->file_chunk_request_size);
    assert(events->file_chunk_request != nullptr);
    return &events->file_chunk_request[index];
}

void tox_events_pack_file_chunk_request(const Tox_Events *events, msgpack_packer *mp)
{
    const uint32_t size = tox_events_get_file_chunk_request_size(events);

    msgpack_pack_array(mp, size);

    for (uint32_t i = 0; i < size; ++i) {
        tox_event_file_chunk_request_pack(tox_events_get_file_chunk_request(events, i), mp);
    }
}


/*****************************************************
 *
 * :: event handler
 *
 *****************************************************/


void tox_events_handle_file_chunk_request(Tox *tox, uint32_t friend_number, uint32_t file_number, uint64_t position,
        size_t length, void *user_data)
{
    Tox_Events_State *state = tox_events_alloc(user_data);
    assert(state != nullptr);

    Tox_Event_File_Chunk_Request *file_chunk_request = tox_events_add_file_chunk_request(state->events);

    if (file_chunk_request == nullptr) {
        state->error = TOX_ERR_EVENTS_ITERATE_MALLOC;
        return;
    }

    tox_event_file_chunk_request_set_friend_number(file_chunk_request, friend_number);
    tox_event_file_chunk_request_set_file_number(file_chunk_request, file_number);
    tox_event_file_chunk_request_set_position(file_chunk_request, position);
    tox_event_file_chunk_request_set_length(file_chunk_request, length);
}
