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
#include "../tox_private.h"
#include "event_macros.h"


/*****************************************************
 *
 * :: struct and accessors
 *
 *****************************************************/


struct Tox_Event_File_Recv_Chunk {
    uint32_t friend_number;
    uint32_t file_number;
    uint64_t position;
    uint8_t *data;
    uint32_t data_length;
};

EV_ACCESS_VALUE(File_Recv_Chunk, file_recv_chunk, uint32_t, friend_number)
EV_ACCESS_VALUE(File_Recv_Chunk, file_recv_chunk, uint32_t, file_number)
EV_ACCESS_VALUE(File_Recv_Chunk, file_recv_chunk, uint64_t, position)
EV_ACCESS_ARRAY(File_Recv_Chunk, file_recv_chunk, uint8_t, data)

non_null()
static void tox_event_file_recv_chunk_construct(Tox_Event_File_Recv_Chunk *file_recv_chunk)
{
    *file_recv_chunk = (Tox_Event_File_Recv_Chunk) {
        0
    };
}
non_null()
static void tox_event_file_recv_chunk_destruct(Tox_Event_File_Recv_Chunk *file_recv_chunk, const Memory *mem)
{
    mem_delete(mem, file_recv_chunk->data);
}

bool tox_event_file_recv_chunk_pack(
    const Tox_Event_File_Recv_Chunk *event, Bin_Pack *bp)
{
    assert(event != nullptr);
    return bin_pack_array(bp, 2)
           && bin_pack_u32(bp, TOX_EVENT_FILE_RECV_CHUNK)
           && bin_pack_array(bp, 4)
           && bin_pack_u32(bp, event->friend_number)
           && bin_pack_u32(bp, event->file_number)
           && bin_pack_u64(bp, event->position)
           && bin_pack_bin(bp, event->data, event->data_length);
}

non_null()
static bool tox_event_file_recv_chunk_unpack_into(
    Tox_Event_File_Recv_Chunk *event, Bin_Unpack *bu)
{
    assert(event != nullptr);
    if (!bin_unpack_array_fixed(bu, 4)) {
        return false;
    }

    return bin_unpack_u32(bu, &event->friend_number)
           && bin_unpack_u32(bu, &event->file_number)
           && bin_unpack_u64(bu, &event->position)
           && bin_unpack_bin(bu, &event->data, &event->data_length);
}

EV_FUNCS(File_Recv_Chunk, file_recv_chunk, FILE_RECV_CHUNK)


/*****************************************************
 *
 * :: event handler
 *
 *****************************************************/


void tox_events_handle_file_recv_chunk(Tox *tox, uint32_t friend_number, uint32_t file_number, uint64_t position,
                                       const uint8_t *data, size_t length, void *user_data)
{
    Tox_Event_File_Recv_Chunk *file_recv_chunk = tox_event_file_recv_chunk_alloc(user_data);

    if (file_recv_chunk == nullptr) {
        return;
    }

    const Tox_System *sys = tox_get_system(tox);

    tox_event_file_recv_chunk_set_friend_number(file_recv_chunk, friend_number);
    tox_event_file_recv_chunk_set_file_number(file_recv_chunk, file_number);
    tox_event_file_recv_chunk_set_position(file_recv_chunk, position);
    tox_event_file_recv_chunk_set_data(file_recv_chunk, data, length, sys->mem);
}
