/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2022 The TokTok team.
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
#include "event_macros.h"


/*****************************************************
 *
 * :: struct and accessors
 *
 *****************************************************/


struct Tox_Event_File_Chunk_Request {
    uint32_t friend_number;
    uint32_t file_number;
    uint64_t position;
    uint16_t length;
};

EV_ACCESS_VALUE(File_Chunk_Request, file_chunk_request, uint32_t, friend_number)
EV_ACCESS_VALUE(File_Chunk_Request, file_chunk_request, uint32_t, file_number)
EV_ACCESS_VALUE(File_Chunk_Request, file_chunk_request, uint64_t, position)
EV_ACCESS_VALUE(File_Chunk_Request, file_chunk_request, uint16_t, length)

non_null()
static void tox_event_file_chunk_request_construct(Tox_Event_File_Chunk_Request *file_chunk_request)
{
    *file_chunk_request = (Tox_Event_File_Chunk_Request) {
        0
    };
}
non_null()
static void tox_event_file_chunk_request_destruct(Tox_Event_File_Chunk_Request *file_chunk_request, const Memory *mem)
{
    return;
}

bool tox_event_file_chunk_request_pack(
    const Tox_Event_File_Chunk_Request *event, Bin_Pack *bp)
{
    assert(event != nullptr);
    return bin_pack_array(bp, 2)
           && bin_pack_u32(bp, TOX_EVENT_FILE_CHUNK_REQUEST)
           && bin_pack_array(bp, 4)
           && bin_pack_u32(bp, event->friend_number)
           && bin_pack_u32(bp, event->file_number)
           && bin_pack_u64(bp, event->position)
           && bin_pack_u16(bp, event->length);
}

non_null()
static bool tox_event_file_chunk_request_unpack_into(
    Tox_Event_File_Chunk_Request *event, Bin_Unpack *bu)
{
    assert(event != nullptr);
    if (!bin_unpack_array_fixed(bu, 4)) {
        return false;
    }

    return bin_unpack_u32(bu, &event->friend_number)
           && bin_unpack_u32(bu, &event->file_number)
           && bin_unpack_u64(bu, &event->position)
           && bin_unpack_u16(bu, &event->length);
}

EV_FUNCS(File_Chunk_Request, file_chunk_request, FILE_CHUNK_REQUEST)


/*****************************************************
 *
 * :: event handler
 *
 *****************************************************/


void tox_events_handle_file_chunk_request(Tox *tox, uint32_t friend_number, uint32_t file_number, uint64_t position,
        size_t length, void *user_data)
{
    Tox_Event_File_Chunk_Request *file_chunk_request = tox_event_file_chunk_request_alloc(user_data);

    if (file_chunk_request == nullptr) {
        return;
    }

    tox_event_file_chunk_request_set_friend_number(file_chunk_request, friend_number);
    tox_event_file_chunk_request_set_file_number(file_chunk_request, file_number);
    tox_event_file_chunk_request_set_position(file_chunk_request, position);
    tox_event_file_chunk_request_set_length(file_chunk_request, length);
}
