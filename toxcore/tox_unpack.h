/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2022-2025 The TokTok team.
 */

#ifndef C_TOXCORE_TOXCORE_TOX_UNPACK_H
#define C_TOXCORE_TOXCORE_TOX_UNPACK_H

#include "attributes.h"
#include "bin_unpack.h"
#include "tox.h"

bool tox_conference_type_unpack(non_null() Tox_Conference_Type *val, non_null() Bin_Unpack *bu);
bool tox_connection_unpack(non_null() Tox_Connection *val, non_null() Bin_Unpack *bu);
bool tox_file_control_unpack(non_null() Tox_File_Control *val, non_null() Bin_Unpack *bu);
bool tox_message_type_unpack(non_null() Tox_Message_Type *val, non_null() Bin_Unpack *bu);
bool tox_user_status_unpack(non_null() Tox_User_Status *val, non_null() Bin_Unpack *bu);
bool tox_group_privacy_state_unpack(non_null() Tox_Group_Privacy_State *val, non_null() Bin_Unpack *bu);
bool tox_group_voice_state_unpack(non_null() Tox_Group_Voice_State *val, non_null() Bin_Unpack *bu);
bool tox_group_topic_lock_unpack(non_null() Tox_Group_Topic_Lock *val, non_null() Bin_Unpack *bu);
bool tox_group_join_fail_unpack(non_null() Tox_Group_Join_Fail *val, non_null() Bin_Unpack *bu);
bool tox_group_mod_event_unpack(non_null() Tox_Group_Mod_Event *val, non_null() Bin_Unpack *bu);
bool tox_group_exit_type_unpack(non_null() Tox_Group_Exit_Type *val, non_null() Bin_Unpack *bu);

#endif /* C_TOXCORE_TOXCORE_TOX_UNPACK_H */
