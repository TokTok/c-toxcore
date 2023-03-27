/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2022 The TokTok team.
 */

#ifndef C_TOXCORE_TOXCORE_TOX_EVENTS_INTERNAL_H
#define C_TOXCORE_TOXCORE_TOX_EVENTS_INTERNAL_H

#include "../attributes.h"
#include "../bin_pack.h"
#include "../bin_unpack.h"
#include "../tox_events.h"

#ifdef __cplusplus
extern "C" {
#endif

struct Tox_Events {
    Tox_Event_Conference_Connected *conference_connected;
    uint32_t conference_connected_size;
    uint32_t conference_connected_capacity;

    Tox_Event_Conference_Invite *conference_invite;
    uint32_t conference_invite_size;
    uint32_t conference_invite_capacity;

    Tox_Event_Conference_Message *conference_message;
    uint32_t conference_message_size;
    uint32_t conference_message_capacity;

    Tox_Event_Conference_Peer_List_Changed *conference_peer_list_changed;
    uint32_t conference_peer_list_changed_size;
    uint32_t conference_peer_list_changed_capacity;

    Tox_Event_Conference_Peer_Name *conference_peer_name;
    uint32_t conference_peer_name_size;
    uint32_t conference_peer_name_capacity;

    Tox_Event_Conference_Title *conference_title;
    uint32_t conference_title_size;
    uint32_t conference_title_capacity;

    Tox_Event_File_Chunk_Request *file_chunk_request;
    uint32_t file_chunk_request_size;
    uint32_t file_chunk_request_capacity;

    Tox_Event_File_Recv *file_recv;
    uint32_t file_recv_size;
    uint32_t file_recv_capacity;

    Tox_Event_File_Recv_Chunk *file_recv_chunk;
    uint32_t file_recv_chunk_size;
    uint32_t file_recv_chunk_capacity;

    Tox_Event_File_Recv_Control *file_recv_control;
    uint32_t file_recv_control_size;
    uint32_t file_recv_control_capacity;

    Tox_Event_Friend_Connection_Status *friend_connection_status;
    uint32_t friend_connection_status_size;
    uint32_t friend_connection_status_capacity;

    Tox_Event_Friend_Lossless_Packet *friend_lossless_packet;
    uint32_t friend_lossless_packet_size;
    uint32_t friend_lossless_packet_capacity;

    Tox_Event_Friend_Lossy_Packet *friend_lossy_packet;
    uint32_t friend_lossy_packet_size;
    uint32_t friend_lossy_packet_capacity;

    Tox_Event_Friend_Message *friend_message;
    uint32_t friend_message_size;
    uint32_t friend_message_capacity;

    Tox_Event_Friend_Name *friend_name;
    uint32_t friend_name_size;
    uint32_t friend_name_capacity;

    Tox_Event_Friend_Read_Receipt *friend_read_receipt;
    uint32_t friend_read_receipt_size;
    uint32_t friend_read_receipt_capacity;

    Tox_Event_Friend_Request *friend_request;
    uint32_t friend_request_size;
    uint32_t friend_request_capacity;

    Tox_Event_Friend_Status *friend_status;
    uint32_t friend_status_size;
    uint32_t friend_status_capacity;

    Tox_Event_Friend_Status_Message *friend_status_message;
    uint32_t friend_status_message_size;
    uint32_t friend_status_message_capacity;

    Tox_Event_Friend_Typing *friend_typing;
    uint32_t friend_typing_size;
    uint32_t friend_typing_capacity;

    Tox_Event_Self_Connection_Status *self_connection_status;
    uint32_t self_connection_status_size;
    uint32_t self_connection_status_capacity;

    Tox_Event_Group_Peer_Name *group_peer_name;
    uint32_t group_peer_name_size;
    uint32_t group_peer_name_capacity;

    Tox_Event_Group_Peer_Status *group_peer_status;
    uint32_t group_peer_status_size;
    uint32_t group_peer_status_capacity;

    Tox_Event_Group_Topic *group_topic;
    uint32_t group_topic_size;
    uint32_t group_topic_capacity;

    Tox_Event_Group_Privacy_State *group_privacy_state;
    uint32_t group_privacy_state_size;
    uint32_t group_privacy_state_capacity;

    Tox_Event_Group_Voice_State *group_voice_state;
    uint32_t group_voice_state_size;
    uint32_t group_voice_state_capacity;

    Tox_Event_Group_Topic_Lock *group_topic_lock;
    uint32_t group_topic_lock_size;
    uint32_t group_topic_lock_capacity;

    Tox_Event_Group_Peer_Limit *group_peer_limit;
    uint32_t group_peer_limit_size;
    uint32_t group_peer_limit_capacity;

    Tox_Event_Group_Password *group_password;
    uint32_t group_password_size;
    uint32_t group_password_capacity;

    Tox_Event_Group_Message *group_message;
    uint32_t group_message_size;
    uint32_t group_message_capacity;

    Tox_Event_Group_Private_Message *group_private_message;
    uint32_t group_private_message_size;
    uint32_t group_private_message_capacity;

    Tox_Event_Group_Custom_Packet *group_custom_packet;
    uint32_t group_custom_packet_size;
    uint32_t group_custom_packet_capacity;

    Tox_Event_Group_Custom_Private_Packet *group_custom_private_packet;
    uint32_t group_custom_private_packet_size;
    uint32_t group_custom_private_packet_capacity;

    Tox_Event_Group_Invite *group_invite;
    uint32_t group_invite_size;
    uint32_t group_invite_capacity;

    Tox_Event_Group_Peer_Join *group_peer_join;
    uint32_t group_peer_join_size;
    uint32_t group_peer_join_capacity;

    Tox_Event_Group_Peer_Exit *group_peer_exit;
    uint32_t group_peer_exit_size;
    uint32_t group_peer_exit_capacity;

    Tox_Event_Group_Self_Join *group_self_join;
    uint32_t group_self_join_size;
    uint32_t group_self_join_capacity;

    Tox_Event_Group_Join_Fail *group_join_fail;
    uint32_t group_join_fail_size;
    uint32_t group_join_fail_capacity;

    Tox_Event_Group_Moderation *group_moderation;
    uint32_t group_moderation_size;
    uint32_t group_moderation_capacity;
};

typedef struct Tox_Events_State {
    Tox_Err_Events_Iterate error;
    Tox_Events *events;
} Tox_Events_State;

tox_conference_connected_cb tox_events_handle_conference_connected;
tox_conference_invite_cb tox_events_handle_conference_invite;
tox_conference_message_cb tox_events_handle_conference_message;
tox_conference_peer_list_changed_cb tox_events_handle_conference_peer_list_changed;
tox_conference_peer_name_cb tox_events_handle_conference_peer_name;
tox_conference_title_cb tox_events_handle_conference_title;
tox_file_chunk_request_cb tox_events_handle_file_chunk_request;
tox_file_recv_cb tox_events_handle_file_recv;
tox_file_recv_chunk_cb tox_events_handle_file_recv_chunk;
tox_file_recv_control_cb tox_events_handle_file_recv_control;
tox_friend_connection_status_cb tox_events_handle_friend_connection_status;
tox_friend_lossless_packet_cb tox_events_handle_friend_lossless_packet;
tox_friend_lossy_packet_cb tox_events_handle_friend_lossy_packet;
tox_friend_message_cb tox_events_handle_friend_message;
tox_friend_name_cb tox_events_handle_friend_name;
tox_friend_read_receipt_cb tox_events_handle_friend_read_receipt;
tox_friend_request_cb tox_events_handle_friend_request;
tox_friend_status_cb tox_events_handle_friend_status;
tox_friend_status_message_cb tox_events_handle_friend_status_message;
tox_friend_typing_cb tox_events_handle_friend_typing;
tox_self_connection_status_cb tox_events_handle_self_connection_status;
tox_group_peer_name_cb tox_events_handle_group_peer_name;
tox_group_peer_status_cb tox_events_handle_group_peer_status;
tox_group_topic_cb tox_events_handle_group_topic;
tox_group_privacy_state_cb tox_events_handle_group_privacy_state;
tox_group_voice_state_cb tox_events_handle_group_voice_state;
tox_group_topic_lock_cb tox_events_handle_group_topic_lock;
tox_group_peer_limit_cb tox_events_handle_group_peer_limit;
tox_group_password_cb tox_events_handle_group_password;
tox_group_message_cb tox_events_handle_group_message;
tox_group_private_message_cb tox_events_handle_group_private_message;
tox_group_custom_packet_cb tox_events_handle_group_custom_packet;
tox_group_custom_private_packet_cb tox_events_handle_group_custom_private_packet;
tox_group_invite_cb tox_events_handle_group_invite;
tox_group_peer_join_cb tox_events_handle_group_peer_join;
tox_group_peer_exit_cb tox_events_handle_group_peer_exit;
tox_group_self_join_cb tox_events_handle_group_self_join;
tox_group_join_fail_cb tox_events_handle_group_join_fail;
tox_group_moderation_cb tox_events_handle_group_moderation;

// non_null()
typedef void tox_events_clear_cb(Tox_Events *events);

tox_events_clear_cb tox_events_clear_conference_connected;
tox_events_clear_cb tox_events_clear_conference_invite;
tox_events_clear_cb tox_events_clear_conference_message;
tox_events_clear_cb tox_events_clear_conference_peer_list_changed;
tox_events_clear_cb tox_events_clear_conference_peer_name;
tox_events_clear_cb tox_events_clear_conference_title;
tox_events_clear_cb tox_events_clear_file_chunk_request;
tox_events_clear_cb tox_events_clear_file_recv_chunk;
tox_events_clear_cb tox_events_clear_file_recv_control;
tox_events_clear_cb tox_events_clear_file_recv;
tox_events_clear_cb tox_events_clear_friend_connection_status;
tox_events_clear_cb tox_events_clear_friend_lossless_packet;
tox_events_clear_cb tox_events_clear_friend_lossy_packet;
tox_events_clear_cb tox_events_clear_friend_message;
tox_events_clear_cb tox_events_clear_friend_name;
tox_events_clear_cb tox_events_clear_friend_read_receipt;
tox_events_clear_cb tox_events_clear_friend_request;
tox_events_clear_cb tox_events_clear_friend_status_message;
tox_events_clear_cb tox_events_clear_friend_status;
tox_events_clear_cb tox_events_clear_friend_typing;
tox_events_clear_cb tox_events_clear_self_connection_status;
tox_events_clear_cb tox_events_clear_group_peer_name;
tox_events_clear_cb tox_events_clear_group_peer_status;
tox_events_clear_cb tox_events_clear_group_topic;
tox_events_clear_cb tox_events_clear_group_privacy_state;
tox_events_clear_cb tox_events_clear_group_voice_state;
tox_events_clear_cb tox_events_clear_group_topic_lock;
tox_events_clear_cb tox_events_clear_group_peer_limit;
tox_events_clear_cb tox_events_clear_group_password;
tox_events_clear_cb tox_events_clear_group_message;
tox_events_clear_cb tox_events_clear_group_private_message;
tox_events_clear_cb tox_events_clear_group_custom_packet;
tox_events_clear_cb tox_events_clear_group_custom_private_packet;
tox_events_clear_cb tox_events_clear_group_invite;
tox_events_clear_cb tox_events_clear_group_peer_join;
tox_events_clear_cb tox_events_clear_group_peer_exit;
tox_events_clear_cb tox_events_clear_group_self_join;
tox_events_clear_cb tox_events_clear_group_join_fail;
tox_events_clear_cb tox_events_clear_group_moderation;

// non_null()
typedef bool tox_events_pack_cb(const Tox_Events *events, Bin_Pack *bp);

tox_events_pack_cb tox_events_pack_conference_connected;
tox_events_pack_cb tox_events_pack_conference_invite;
tox_events_pack_cb tox_events_pack_conference_message;
tox_events_pack_cb tox_events_pack_conference_peer_list_changed;
tox_events_pack_cb tox_events_pack_conference_peer_name;
tox_events_pack_cb tox_events_pack_conference_title;
tox_events_pack_cb tox_events_pack_file_chunk_request;
tox_events_pack_cb tox_events_pack_file_recv_chunk;
tox_events_pack_cb tox_events_pack_file_recv_control;
tox_events_pack_cb tox_events_pack_file_recv;
tox_events_pack_cb tox_events_pack_friend_connection_status;
tox_events_pack_cb tox_events_pack_friend_lossless_packet;
tox_events_pack_cb tox_events_pack_friend_lossy_packet;
tox_events_pack_cb tox_events_pack_friend_message;
tox_events_pack_cb tox_events_pack_friend_name;
tox_events_pack_cb tox_events_pack_friend_read_receipt;
tox_events_pack_cb tox_events_pack_friend_request;
tox_events_pack_cb tox_events_pack_friend_status_message;
tox_events_pack_cb tox_events_pack_friend_status;
tox_events_pack_cb tox_events_pack_friend_typing;
tox_events_pack_cb tox_events_pack_self_connection_status;
tox_events_pack_cb tox_events_pack_group_peer_name;
tox_events_pack_cb tox_events_pack_group_peer_status;
tox_events_pack_cb tox_events_pack_group_topic;
tox_events_pack_cb tox_events_pack_group_privacy_state;
tox_events_pack_cb tox_events_pack_group_voice_state;
tox_events_pack_cb tox_events_pack_group_topic_lock;
tox_events_pack_cb tox_events_pack_group_peer_limit;
tox_events_pack_cb tox_events_pack_group_password;
tox_events_pack_cb tox_events_pack_group_message;
tox_events_pack_cb tox_events_pack_group_private_message;
tox_events_pack_cb tox_events_pack_group_custom_packet;
tox_events_pack_cb tox_events_pack_group_custom_private_packet;
tox_events_pack_cb tox_events_pack_group_invite;
tox_events_pack_cb tox_events_pack_group_peer_join;
tox_events_pack_cb tox_events_pack_group_peer_exit;
tox_events_pack_cb tox_events_pack_group_self_join;
tox_events_pack_cb tox_events_pack_group_join_fail;
tox_events_pack_cb tox_events_pack_group_moderation;

tox_events_pack_cb tox_events_pack;

// non_null()
typedef bool tox_events_unpack_cb(Tox_Events *events, Bin_Unpack *bu);

tox_events_unpack_cb tox_events_unpack_conference_connected;
tox_events_unpack_cb tox_events_unpack_conference_invite;
tox_events_unpack_cb tox_events_unpack_conference_message;
tox_events_unpack_cb tox_events_unpack_conference_peer_list_changed;
tox_events_unpack_cb tox_events_unpack_conference_peer_name;
tox_events_unpack_cb tox_events_unpack_conference_title;
tox_events_unpack_cb tox_events_unpack_file_chunk_request;
tox_events_unpack_cb tox_events_unpack_file_recv_chunk;
tox_events_unpack_cb tox_events_unpack_file_recv_control;
tox_events_unpack_cb tox_events_unpack_file_recv;
tox_events_unpack_cb tox_events_unpack_friend_connection_status;
tox_events_unpack_cb tox_events_unpack_friend_lossless_packet;
tox_events_unpack_cb tox_events_unpack_friend_lossy_packet;
tox_events_unpack_cb tox_events_unpack_friend_message;
tox_events_unpack_cb tox_events_unpack_friend_name;
tox_events_unpack_cb tox_events_unpack_friend_read_receipt;
tox_events_unpack_cb tox_events_unpack_friend_request;
tox_events_unpack_cb tox_events_unpack_friend_status_message;
tox_events_unpack_cb tox_events_unpack_friend_status;
tox_events_unpack_cb tox_events_unpack_friend_typing;
tox_events_unpack_cb tox_events_unpack_self_connection_status;
tox_events_unpack_cb tox_events_unpack_group_peer_name;
tox_events_unpack_cb tox_events_unpack_group_peer_status;
tox_events_unpack_cb tox_events_unpack_group_topic;
tox_events_unpack_cb tox_events_unpack_group_privacy_state;
tox_events_unpack_cb tox_events_unpack_group_voice_state;
tox_events_unpack_cb tox_events_unpack_group_topic_lock;
tox_events_unpack_cb tox_events_unpack_group_peer_limit;
tox_events_unpack_cb tox_events_unpack_group_password;
tox_events_unpack_cb tox_events_unpack_group_message;
tox_events_unpack_cb tox_events_unpack_group_private_message;
tox_events_unpack_cb tox_events_unpack_group_custom_packet;
tox_events_unpack_cb tox_events_unpack_group_custom_private_packet;
tox_events_unpack_cb tox_events_unpack_group_invite;
tox_events_unpack_cb tox_events_unpack_group_peer_join;
tox_events_unpack_cb tox_events_unpack_group_peer_exit;
tox_events_unpack_cb tox_events_unpack_group_self_join;
tox_events_unpack_cb tox_events_unpack_group_join_fail;
tox_events_unpack_cb tox_events_unpack_group_moderation;

tox_events_unpack_cb tox_events_unpack;

non_null()
Tox_Events_State *tox_events_alloc(void *user_data);

#ifdef __cplusplus
}
#endif

#endif // C_TOXCORE_TOXCORE_TOX_EVENTS_INTERNAL_H
