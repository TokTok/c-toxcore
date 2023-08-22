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
#include "../tox_unpack.h"
#include "event_macros.h"


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

EV_ACCESS_VALUE(File_Recv_Control, file_recv_control, uint32_t, friend_number)
EV_ACCESS_VALUE(File_Recv_Control, file_recv_control, uint32_t, file_number)
EV_ACCESS_VALUE(File_Recv_Control, file_recv_control, Tox_File_Control, control)

non_null()
static void tox_event_file_recv_control_construct(Tox_Event_File_Recv_Control *file_recv_control)
{
    *file_recv_control = (Tox_Event_File_Recv_Control) {
        0
    };
}
non_null()
static void tox_event_file_recv_control_destruct(Tox_Event_File_Recv_Control *file_recv_control, const Memory *mem)
{
    return;
}

bool tox_event_file_recv_control_pack(
    const Tox_Event_File_Recv_Control *event, Bin_Pack *bp)
{
    assert(event != nullptr);
    return bin_pack_array(bp, 2)
           && bin_pack_u32(bp, TOX_EVENT_FILE_RECV_CONTROL)
           && bin_pack_array(bp, 3)
           && bin_pack_u32(bp, event->friend_number)
           && bin_pack_u32(bp, event->file_number)
           && bin_pack_u32(bp, event->control);
}

non_null()
static bool tox_event_file_recv_control_unpack_into(
    Tox_Event_File_Recv_Control *event, Bin_Unpack *bu)
{
    assert(event != nullptr);
    if (!bin_unpack_array_fixed(bu, 3)) {
        return false;
    }

    return bin_unpack_u32(bu, &event->friend_number)
           && bin_unpack_u32(bu, &event->file_number)
           && tox_unpack_file_control(bu, &event->control);
}

EV_FUNCS(File_Recv_Control, file_recv_control, FILE_RECV_CONTROL)


/*****************************************************
 *
 * :: event handler
 *
 *****************************************************/


void tox_events_handle_file_recv_control(Tox *tox, uint32_t friend_number, uint32_t file_number,
        Tox_File_Control control, void *user_data)
{
    Tox_Event_File_Recv_Control *file_recv_control = tox_event_file_recv_control_alloc(user_data);

    if (file_recv_control == nullptr) {
        return;
    }

    tox_event_file_recv_control_set_friend_number(file_recv_control, friend_number);
    tox_event_file_recv_control_set_file_number(file_recv_control, file_number);
    tox_event_file_recv_control_set_control(file_recv_control, control);
}
