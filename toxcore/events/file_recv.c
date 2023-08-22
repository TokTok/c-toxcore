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


struct Tox_Event_File_Recv {
    uint32_t friend_number;
    uint32_t file_number;
    uint32_t kind;
    uint64_t file_size;
    uint8_t *filename;
    uint32_t filename_length;
};

EV_ACCESS_VALUE(File_Recv, file_recv, uint32_t, friend_number)
EV_ACCESS_VALUE(File_Recv, file_recv, uint32_t, file_number)
EV_ACCESS_VALUE(File_Recv, file_recv, uint32_t, kind)
EV_ACCESS_VALUE(File_Recv, file_recv, uint64_t, file_size)
EV_ACCESS_ARRAY(File_Recv, file_recv, uint8_t, filename)

non_null()
static void tox_event_file_recv_construct(Tox_Event_File_Recv *file_recv)
{
    *file_recv = (Tox_Event_File_Recv) {
        0
    };
}
non_null()
static void tox_event_file_recv_destruct(Tox_Event_File_Recv *file_recv, const Memory *mem)
{
    mem_delete(mem, file_recv->filename);
}

bool tox_event_file_recv_pack(
    const Tox_Event_File_Recv *event, Bin_Pack *bp)
{
    assert(event != nullptr);
    return bin_pack_array(bp, 2)
           && bin_pack_u32(bp, TOX_EVENT_FILE_RECV)
           && bin_pack_array(bp, 5)
           && bin_pack_u32(bp, event->friend_number)
           && bin_pack_u32(bp, event->file_number)
           && bin_pack_u32(bp, event->kind)
           && bin_pack_u64(bp, event->file_size)
           && bin_pack_bin(bp, event->filename, event->filename_length);
}

non_null()
static bool tox_event_file_recv_unpack_into(
    Tox_Event_File_Recv *event, Bin_Unpack *bu)
{
    assert(event != nullptr);
    if (!bin_unpack_array_fixed(bu, 5)) {
        return false;
    }

    return bin_unpack_u32(bu, &event->friend_number)
           && bin_unpack_u32(bu, &event->file_number)
           && bin_unpack_u32(bu, &event->kind)
           && bin_unpack_u64(bu, &event->file_size)
           && bin_unpack_bin(bu, &event->filename, &event->filename_length);
}

EV_FUNCS(File_Recv, file_recv, FILE_RECV)


/*****************************************************
 *
 * :: event handler
 *
 *****************************************************/


void tox_events_handle_file_recv(Tox *tox, uint32_t friend_number, uint32_t file_number, uint32_t kind,
                                 uint64_t file_size, const uint8_t *filename, size_t filename_length, void *user_data)
{
    Tox_Event_File_Recv *file_recv = tox_event_file_recv_alloc(user_data);

    if (file_recv == nullptr) {
        return;
    }

    const Tox_System *sys = tox_get_system(tox);

    tox_event_file_recv_set_friend_number(file_recv, friend_number);
    tox_event_file_recv_set_file_number(file_recv, file_number);
    tox_event_file_recv_set_kind(file_recv, kind);
    tox_event_file_recv_set_file_size(file_recv, file_size);
    tox_event_file_recv_set_filename(file_recv, filename, filename_length, sys->mem);
}
