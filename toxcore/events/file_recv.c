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


struct Tox_Event_File_Recv {
    uint32_t friend_number;
    uint32_t file_number;
    uint32_t kind;
    uint64_t file_size;
    uint8_t *filename;
    size_t filename_length;
};

static void tox_event_file_recv_construct(Tox_Event_File_Recv *file_recv)
{
    *file_recv = (Tox_Event_File_Recv) {
        0
    };
}
static void tox_event_file_recv_destruct(Tox_Event_File_Recv *file_recv)
{
    free(file_recv->filename);
}

static void tox_event_file_recv_set_friend_number(Tox_Event_File_Recv *file_recv,
        uint32_t friend_number)
{
    assert(file_recv != nullptr);
    file_recv->friend_number = friend_number;
}
uint32_t tox_event_file_recv_get_friend_number(const Tox_Event_File_Recv *file_recv)
{
    assert(file_recv != nullptr);
    return file_recv->friend_number;
}

static void tox_event_file_recv_set_file_number(Tox_Event_File_Recv *file_recv,
        uint32_t file_number)
{
    assert(file_recv != nullptr);
    file_recv->file_number = file_number;
}
uint32_t tox_event_file_recv_get_file_number(const Tox_Event_File_Recv *file_recv)
{
    assert(file_recv != nullptr);
    return file_recv->file_number;
}

static void tox_event_file_recv_set_kind(Tox_Event_File_Recv *file_recv,
        uint32_t kind)
{
    assert(file_recv != nullptr);
    file_recv->kind = kind;
}
uint32_t tox_event_file_recv_get_kind(const Tox_Event_File_Recv *file_recv)
{
    assert(file_recv != nullptr);
    return file_recv->kind;
}

static void tox_event_file_recv_set_file_size(Tox_Event_File_Recv *file_recv,
        uint32_t file_size)
{
    assert(file_recv != nullptr);
    file_recv->file_size = file_size;
}
uint32_t tox_event_file_recv_get_file_size(const Tox_Event_File_Recv *file_recv)
{
    assert(file_recv != nullptr);
    return file_recv->file_size;
}

static bool tox_event_file_recv_set_filename(Tox_Event_File_Recv *file_recv, const uint8_t *filename,
        size_t filename_length)
{
    assert(file_recv != nullptr);

    if (file_recv->filename != nullptr) {
        free(file_recv->filename);
        file_recv->filename = nullptr;
        file_recv->filename_length = 0;
    }

    file_recv->filename = (uint8_t *)malloc(filename_length);

    if (file_recv->filename == nullptr) {
        return false;
    }

    memcpy(file_recv->filename, filename, filename_length);
    file_recv->filename_length = filename_length;
    return true;
}
size_t tox_event_file_recv_get_filename_length(const Tox_Event_File_Recv *file_recv)
{
    assert(file_recv != nullptr);
    return file_recv->filename_length;
}
const uint8_t *tox_event_file_recv_get_filename(const Tox_Event_File_Recv *file_recv)
{
    assert(file_recv != nullptr);
    return file_recv->filename;
}

static void tox_event_file_recv_pack(const Tox_Event_File_Recv *event, msgpack_packer *mp)
{
    assert(event != nullptr);
    msgpack_pack_array(mp, 5);
    msgpack_pack_uint32(mp, event->friend_number);
    msgpack_pack_uint32(mp, event->file_number);
    msgpack_pack_uint32(mp, event->kind);
    msgpack_pack_uint64(mp, event->file_size);
    msgpack_pack_bin(mp, event->filename_length);
    msgpack_pack_bin_body(mp, event->filename, event->filename_length);
}


/*****************************************************
 *
 * :: add/clear/get
 *
 *****************************************************/


static Tox_Event_File_Recv *tox_events_add_file_recv(Tox_Events *events)
{
    if (events->file_recv_size == UINT32_MAX) {
        return nullptr;
    }

    if (events->file_recv_size == events->file_recv_capacity) {
        const uint32_t new_file_recv_capacity = events->file_recv_capacity * 2 + 1;
        Tox_Event_File_Recv *new_file_recv = (Tox_Event_File_Recv *)realloc(
                events->file_recv, new_file_recv_capacity * sizeof(Tox_Event_File_Recv));

        if (new_file_recv == nullptr) {
            return nullptr;
        }

        events->file_recv = new_file_recv;
        events->file_recv_capacity = new_file_recv_capacity;
    }

    Tox_Event_File_Recv *const file_recv = &events->file_recv[events->file_recv_size];
    tox_event_file_recv_construct(file_recv);
    ++events->file_recv_size;
    return file_recv;
}

void tox_events_clear_file_recv(Tox_Events *events)
{
    if (events == nullptr) {
        return;
    }

    for (uint32_t i = 0; i < events->file_recv_size; ++i) {
        tox_event_file_recv_destruct(&events->file_recv[i]);
    }

    free(events->file_recv);
    events->file_recv = nullptr;
    events->file_recv_size = 0;
    events->file_recv_capacity = 0;
}

uint32_t tox_events_get_file_recv_size(const Tox_Events *events)
{
    if (events == nullptr) {
        return 0;
    }

    return events->file_recv_size;
}

const Tox_Event_File_Recv *tox_events_get_file_recv(const Tox_Events *events, uint32_t index)
{
    assert(index < events->file_recv_size);
    assert(events->file_recv != nullptr);
    return &events->file_recv[index];
}

void tox_events_pack_file_recv(const Tox_Events *events, msgpack_packer *mp)
{
    const uint32_t size = tox_events_get_file_recv_size(events);

    msgpack_pack_array(mp, size);

    for (uint32_t i = 0; i < size; ++i) {
        tox_event_file_recv_pack(tox_events_get_file_recv(events, i), mp);
    }
}


/*****************************************************
 *
 * :: event handler
 *
 *****************************************************/


void tox_events_handle_file_recv(Tox *tox, uint32_t friend_number, uint32_t file_number, uint32_t kind,
                                 uint64_t file_size, const uint8_t *filename, size_t filename_length, void *user_data)
{
    Tox_Events_State *state = tox_events_alloc(user_data);
    assert(state != nullptr);

    Tox_Event_File_Recv *file_recv = tox_events_add_file_recv(state->events);

    if (file_recv == nullptr) {
        state->error = TOX_ERR_EVENTS_ITERATE_MALLOC;
        return;
    }

    tox_event_file_recv_set_friend_number(file_recv, friend_number);
    tox_event_file_recv_set_file_number(file_recv, file_number);
    tox_event_file_recv_set_kind(file_recv, kind);
    tox_event_file_recv_set_file_size(file_recv, file_size);
    tox_event_file_recv_set_filename(file_recv, filename, filename_length);
}
