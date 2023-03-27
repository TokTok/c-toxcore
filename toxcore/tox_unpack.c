/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2022 The TokTok team.
 */

#include "tox_unpack.h"

#include <stdint.h>

#include "bin_unpack.h"
#include "ccompat.h"

bool tox_unpack_conference_type(Bin_Unpack *bu, Tox_Conference_Type *val)
{
    uint32_t u32;

    if (!bin_unpack_u32(bu, &u32)) {
        return false;
    }

    *val = (Tox_Conference_Type)u32;
    return true;
}

bool tox_unpack_connection(Bin_Unpack *bu, Tox_Connection *val)
{
    uint32_t u32;

    if (!bin_unpack_u32(bu, &u32)) {
        return false;
    }

    *val = (Tox_Connection)u32;
    return true;
}

bool tox_unpack_file_control(Bin_Unpack *bu, Tox_File_Control *val)
{
    uint32_t u32;

    if (!bin_unpack_u32(bu, &u32)) {
        return false;
    }

    *val = (Tox_File_Control)u32;
    return true;
}

bool tox_unpack_message_type(Bin_Unpack *bu, Tox_Message_Type *val)
{
    uint32_t u32;

    if (!bin_unpack_u32(bu, &u32)) {
        return false;
    }

    *val = (Tox_Message_Type)u32;
    return true;
}

bool tox_unpack_user_status(Bin_Unpack *bu, Tox_User_Status *val)
{
    uint32_t u32;

    if (!bin_unpack_u32(bu, &u32)) {
        return false;
    }

    *val = (Tox_User_Status)u32;
    return true;
}

bool tox_unpack_group_privacy_state(Bin_Unpack *bu, Tox_Group_Privacy_State *val)
{
    uint32_t u32;

    if (!bin_unpack_u32(bu, &u32)) {
        return false;
    }

    *val = (Tox_Group_Privacy_State)u32;
    return true;
}

bool tox_unpack_group_voice_state(Bin_Unpack *bu, Tox_Group_Voice_State *val)
{
    uint32_t u32;

    if (!bin_unpack_u32(bu, &u32)) {
        return false;
    }

    *val = (Tox_Group_Voice_State)u32;
    return true;
}

bool tox_unpack_group_topic_lock(Bin_Unpack *bu, Tox_Group_Topic_Lock *val)
{
    uint32_t u32;

    if (!bin_unpack_u32(bu, &u32)) {
        return false;
    }

    *val = (Tox_Group_Topic_Lock)u32;
    return true;
}

bool tox_unpack_group_join_fail(Bin_Unpack *bu, Tox_Group_Join_Fail *val)
{
    uint32_t u32;

    if (!bin_unpack_u32(bu, &u32)) {
        return false;
    }

    *val = (Tox_Group_Join_Fail)u32;
    return true;
}

bool tox_unpack_group_mod_event(Bin_Unpack *bu, Tox_Group_Mod_Event *val)
{
    uint32_t u32;

    if (!bin_unpack_u32(bu, &u32)) {
        return false;
    }

    *val = (Tox_Group_Mod_Event)u32;
    return true;
}

bool tox_unpack_group_exit_type(Bin_Unpack *bu, Tox_Group_Exit_Type *val)
{
    uint32_t u32;

    if (!bin_unpack_u32(bu, &u32)) {
        return false;
    }

    *val = (Tox_Group_Exit_Type)u32;
    return true;
}
