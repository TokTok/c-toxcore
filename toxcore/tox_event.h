/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2022-2025 The TokTok team.
 */

#ifndef C_TOXCORE_TOXCORE_TOX_EVENT_H
#define C_TOXCORE_TOXCORE_TOX_EVENT_H

#include "bin_pack.h"
#include "bin_unpack.h"
#include "mem.h"
#include "tox_attributes.h"
#include "tox_events.h"
#include "tox_private.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef union Tox_Event_Data {
    /**
     * Opaque pointer just to check whether any value is set.
     */
    void *value;

    Tox_Event_Conference_Connected *conference_connected;
    Tox_Event_Conference_Invite *conference_invite;
    Tox_Event_Conference_Message *conference_message;
    Tox_Event_Conference_Peer_List_Changed *conference_peer_list_changed;
    Tox_Event_Conference_Peer_Name *conference_peer_name;
    Tox_Event_Conference_Title *conference_title;
    Tox_Event_File_Chunk_Request *file_chunk_request;
    Tox_Event_File_Recv *file_recv;
    Tox_Event_File_Recv_Chunk *file_recv_chunk;
    Tox_Event_File_Recv_Control *file_recv_control;
    Tox_Event_Friend_Connection_Status *friend_connection_status;
    Tox_Event_Friend_Lossless_Packet *friend_lossless_packet;
    Tox_Event_Friend_Lossy_Packet *friend_lossy_packet;
    Tox_Event_Friend_Message *friend_message;
    Tox_Event_Friend_Name *friend_name;
    Tox_Event_Friend_Read_Receipt *friend_read_receipt;
    Tox_Event_Friend_Request *friend_request;
    Tox_Event_Friend_Status *friend_status;
    Tox_Event_Friend_Status_Message *friend_status_message;
    Tox_Event_Friend_Typing *friend_typing;
    Tox_Event_Self_Connection_Status *self_connection_status;
    Tox_Event_Group_Peer_Name *group_peer_name;
    Tox_Event_Group_Peer_Status *group_peer_status;
    Tox_Event_Group_Topic *group_topic;
    Tox_Event_Group_Privacy_State *group_privacy_state;
    Tox_Event_Group_Voice_State *group_voice_state;
    Tox_Event_Group_Topic_Lock *group_topic_lock;
    Tox_Event_Group_Peer_Limit *group_peer_limit;
    Tox_Event_Group_Password *group_password;
    Tox_Event_Group_Message *group_message;
    Tox_Event_Group_Private_Message *group_private_message;
    Tox_Event_Group_Custom_Packet *group_custom_packet;
    Tox_Event_Group_Custom_Private_Packet *group_custom_private_packet;
    Tox_Event_Group_Invite *group_invite;
    Tox_Event_Group_Peer_Join *group_peer_join;
    Tox_Event_Group_Peer_Exit *group_peer_exit;
    Tox_Event_Group_Self_Join *group_self_join;
    Tox_Event_Group_Join_Fail *group_join_fail;
    Tox_Event_Group_Moderation *group_moderation;
    Tox_Event_Dht_Nodes_Response *dht_nodes_response;
} Tox_Event_Data;

struct Tox_Event {
    Tox_Event_Type type;
    Tox_Event_Data data;
};

/**
 * Constructor.
 */
bool tox_event_construct(tox_non_null() Tox_Event *event, Tox_Event_Type type, tox_non_null() const Memory *mem);

Tox_Event_Conference_Connected *tox_event_conference_connected_new(tox_non_null() const Memory *mem);
Tox_Event_Conference_Invite *tox_event_conference_invite_new(tox_non_null() const Memory *mem);
Tox_Event_Conference_Message *tox_event_conference_message_new(tox_non_null() const Memory *mem);
Tox_Event_Conference_Peer_List_Changed *tox_event_conference_peer_list_changed_new(tox_non_null() const Memory *mem);
Tox_Event_Conference_Peer_Name *tox_event_conference_peer_name_new(tox_non_null() const Memory *mem);
Tox_Event_Conference_Title *tox_event_conference_title_new(tox_non_null() const Memory *mem);
Tox_Event_File_Chunk_Request *tox_event_file_chunk_request_new(tox_non_null() const Memory *mem);
Tox_Event_File_Recv_Chunk *tox_event_file_recv_chunk_new(tox_non_null() const Memory *mem);
Tox_Event_File_Recv_Control *tox_event_file_recv_control_new(tox_non_null() const Memory *mem);
Tox_Event_File_Recv *tox_event_file_recv_new(tox_non_null() const Memory *mem);
Tox_Event_Friend_Connection_Status *tox_event_friend_connection_status_new(tox_non_null() const Memory *mem);
Tox_Event_Friend_Lossless_Packet *tox_event_friend_lossless_packet_new(tox_non_null() const Memory *mem);
Tox_Event_Friend_Lossy_Packet *tox_event_friend_lossy_packet_new(tox_non_null() const Memory *mem);
Tox_Event_Friend_Message *tox_event_friend_message_new(tox_non_null() const Memory *mem);
Tox_Event_Friend_Name *tox_event_friend_name_new(tox_non_null() const Memory *mem);
Tox_Event_Friend_Read_Receipt *tox_event_friend_read_receipt_new(tox_non_null() const Memory *mem);
Tox_Event_Friend_Request *tox_event_friend_request_new(tox_non_null() const Memory *mem);
Tox_Event_Friend_Status_Message *tox_event_friend_status_message_new(tox_non_null() const Memory *mem);
Tox_Event_Friend_Status *tox_event_friend_status_new(tox_non_null() const Memory *mem);
Tox_Event_Friend_Typing *tox_event_friend_typing_new(tox_non_null() const Memory *mem);
Tox_Event_Self_Connection_Status *tox_event_self_connection_status_new(tox_non_null() const Memory *mem);
Tox_Event_Group_Peer_Name *tox_event_group_peer_name_new(tox_non_null() const Memory *mem);
Tox_Event_Group_Peer_Status *tox_event_group_peer_status_new(tox_non_null() const Memory *mem);
Tox_Event_Group_Topic *tox_event_group_topic_new(tox_non_null() const Memory *mem);
Tox_Event_Group_Privacy_State *tox_event_group_privacy_state_new(tox_non_null() const Memory *mem);
Tox_Event_Group_Voice_State *tox_event_group_voice_state_new(tox_non_null() const Memory *mem);
Tox_Event_Group_Topic_Lock *tox_event_group_topic_lock_new(tox_non_null() const Memory *mem);
Tox_Event_Group_Peer_Limit *tox_event_group_peer_limit_new(tox_non_null() const Memory *mem);
Tox_Event_Group_Password *tox_event_group_password_new(tox_non_null() const Memory *mem);
Tox_Event_Group_Message *tox_event_group_message_new(tox_non_null() const Memory *mem);
Tox_Event_Group_Private_Message *tox_event_group_private_message_new(tox_non_null() const Memory *mem);
Tox_Event_Group_Custom_Packet *tox_event_group_custom_packet_new(tox_non_null() const Memory *mem);
Tox_Event_Group_Custom_Private_Packet *tox_event_group_custom_private_packet_new(tox_non_null() const Memory *mem);
Tox_Event_Group_Invite *tox_event_group_invite_new(tox_non_null() const Memory *mem);
Tox_Event_Group_Peer_Join *tox_event_group_peer_join_new(tox_non_null() const Memory *mem);
Tox_Event_Group_Peer_Exit *tox_event_group_peer_exit_new(tox_non_null() const Memory *mem);
Tox_Event_Group_Self_Join *tox_event_group_self_join_new(tox_non_null() const Memory *mem);
Tox_Event_Group_Join_Fail *tox_event_group_join_fail_new(tox_non_null() const Memory *mem);
Tox_Event_Group_Moderation *tox_event_group_moderation_new(tox_non_null() const Memory *mem);
Tox_Event_Dht_Nodes_Response *tox_event_dht_nodes_response_new(tox_non_null() const Memory *mem);

/**
 * Destructor.
 */
void tox_event_destruct(tox_nullable() Tox_Event *event, tox_non_null() const Memory *mem);

void tox_event_conference_connected_free(tox_nullable() Tox_Event_Conference_Connected *conference_connected, tox_non_null() const Memory *mem);
void tox_event_conference_invite_free(tox_nullable() Tox_Event_Conference_Invite *conference_invite, tox_non_null() const Memory *mem);
void tox_event_conference_message_free(tox_nullable() Tox_Event_Conference_Message *conference_message, tox_non_null() const Memory *mem);
void tox_event_conference_peer_list_changed_free(tox_nullable() Tox_Event_Conference_Peer_List_Changed *conference_peer_list_changed, tox_non_null() const Memory *mem);
void tox_event_conference_peer_name_free(tox_nullable() Tox_Event_Conference_Peer_Name *conference_peer_name, tox_non_null() const Memory *mem);
void tox_event_conference_title_free(tox_nullable() Tox_Event_Conference_Title *conference_title, tox_non_null() const Memory *mem);
void tox_event_file_chunk_request_free(tox_nullable() Tox_Event_File_Chunk_Request *file_chunk_request, tox_non_null() const Memory *mem);
void tox_event_file_recv_chunk_free(tox_nullable() Tox_Event_File_Recv_Chunk *file_recv_chunk, tox_non_null() const Memory *mem);
void tox_event_file_recv_control_free(tox_nullable() Tox_Event_File_Recv_Control *file_recv_control, tox_non_null() const Memory *mem);
void tox_event_file_recv_free(tox_nullable() Tox_Event_File_Recv *file_recv, tox_non_null() const Memory *mem);
void tox_event_friend_connection_status_free(tox_nullable() Tox_Event_Friend_Connection_Status *friend_connection_status, tox_non_null() const Memory *mem);
void tox_event_friend_lossless_packet_free(tox_nullable() Tox_Event_Friend_Lossless_Packet *friend_lossless_packet, tox_non_null() const Memory *mem);
void tox_event_friend_lossy_packet_free(tox_nullable() Tox_Event_Friend_Lossy_Packet *friend_lossy_packet, tox_non_null() const Memory *mem);
void tox_event_friend_message_free(tox_nullable() Tox_Event_Friend_Message *friend_message, tox_non_null() const Memory *mem);
void tox_event_friend_name_free(tox_nullable() Tox_Event_Friend_Name *friend_name, tox_non_null() const Memory *mem);
void tox_event_friend_read_receipt_free(tox_nullable() Tox_Event_Friend_Read_Receipt *friend_read_receipt, tox_non_null() const Memory *mem);
void tox_event_friend_request_free(tox_nullable() Tox_Event_Friend_Request *friend_request, tox_non_null() const Memory *mem);
void tox_event_friend_status_message_free(tox_nullable() Tox_Event_Friend_Status_Message *friend_status_message, tox_non_null() const Memory *mem);
void tox_event_friend_status_free(tox_nullable() Tox_Event_Friend_Status *friend_status, tox_non_null() const Memory *mem);
void tox_event_friend_typing_free(tox_nullable() Tox_Event_Friend_Typing *friend_typing, tox_non_null() const Memory *mem);
void tox_event_self_connection_status_free(tox_nullable() Tox_Event_Self_Connection_Status *self_connection_status, tox_non_null() const Memory *mem);
void tox_event_group_peer_name_free(tox_nullable() Tox_Event_Group_Peer_Name *group_peer_name, tox_non_null() const Memory *mem);
void tox_event_group_peer_status_free(tox_nullable() Tox_Event_Group_Peer_Status *group_peer_status, tox_non_null() const Memory *mem);
void tox_event_group_topic_free(tox_nullable() Tox_Event_Group_Topic *group_topic, tox_non_null() const Memory *mem);
void tox_event_group_privacy_state_free(tox_nullable() Tox_Event_Group_Privacy_State *group_privacy_state, tox_non_null() const Memory *mem);
void tox_event_group_voice_state_free(tox_nullable() Tox_Event_Group_Voice_State *group_voice_state, tox_non_null() const Memory *mem);
void tox_event_group_topic_lock_free(tox_nullable() Tox_Event_Group_Topic_Lock *group_topic_lock, tox_non_null() const Memory *mem);
void tox_event_group_peer_limit_free(tox_nullable() Tox_Event_Group_Peer_Limit *group_peer_limit, tox_non_null() const Memory *mem);
void tox_event_group_password_free(tox_nullable() Tox_Event_Group_Password *group_password, tox_non_null() const Memory *mem);
void tox_event_group_message_free(tox_nullable() Tox_Event_Group_Message *group_message, tox_non_null() const Memory *mem);
void tox_event_group_private_message_free(tox_nullable() Tox_Event_Group_Private_Message *group_private_message, tox_non_null() const Memory *mem);
void tox_event_group_custom_packet_free(tox_nullable() Tox_Event_Group_Custom_Packet *group_custom_packet, tox_non_null() const Memory *mem);
void tox_event_group_custom_private_packet_free(tox_nullable() Tox_Event_Group_Custom_Private_Packet *group_custom_private_packet, tox_non_null() const Memory *mem);
void tox_event_group_invite_free(tox_nullable() Tox_Event_Group_Invite *group_invite, tox_non_null() const Memory *mem);
void tox_event_group_peer_join_free(tox_nullable() Tox_Event_Group_Peer_Join *group_peer_join, tox_non_null() const Memory *mem);
void tox_event_group_peer_exit_free(tox_nullable() Tox_Event_Group_Peer_Exit *group_peer_exit, tox_non_null() const Memory *mem);
void tox_event_group_self_join_free(tox_nullable() Tox_Event_Group_Self_Join *group_self_join, tox_non_null() const Memory *mem);
void tox_event_group_join_fail_free(tox_nullable() Tox_Event_Group_Join_Fail *group_join_fail, tox_non_null() const Memory *mem);
void tox_event_group_moderation_free(tox_nullable() Tox_Event_Group_Moderation *group_moderation, tox_non_null() const Memory *mem);
void tox_event_dht_nodes_response_free(tox_nullable() Tox_Event_Dht_Nodes_Response *dht_nodes_response, tox_non_null() const Memory *mem);

/**
 * Pack into msgpack.
 */
bool tox_event_pack(tox_non_null() const Tox_Event *event, tox_non_null() Bin_Pack *bp);

bool tox_event_conference_connected_pack(tox_non_null() const Tox_Event_Conference_Connected *event, tox_non_null() Bin_Pack *bp);
bool tox_event_conference_invite_pack(tox_non_null() const Tox_Event_Conference_Invite *event, tox_non_null() Bin_Pack *bp);
bool tox_event_conference_message_pack(tox_non_null() const Tox_Event_Conference_Message *event, tox_non_null() Bin_Pack *bp);
bool tox_event_conference_peer_list_changed_pack(tox_non_null() const Tox_Event_Conference_Peer_List_Changed *event, tox_non_null() Bin_Pack *bp);
bool tox_event_conference_peer_name_pack(tox_non_null() const Tox_Event_Conference_Peer_Name *event, tox_non_null() Bin_Pack *bp);
bool tox_event_conference_title_pack(tox_non_null() const Tox_Event_Conference_Title *event, tox_non_null() Bin_Pack *bp);
bool tox_event_file_chunk_request_pack(tox_non_null() const Tox_Event_File_Chunk_Request *event, tox_non_null() Bin_Pack *bp);
bool tox_event_file_recv_chunk_pack(tox_non_null() const Tox_Event_File_Recv_Chunk *event, tox_non_null() Bin_Pack *bp);
bool tox_event_file_recv_control_pack(tox_non_null() const Tox_Event_File_Recv_Control *event, tox_non_null() Bin_Pack *bp);
bool tox_event_file_recv_pack(tox_non_null() const Tox_Event_File_Recv *event, tox_non_null() Bin_Pack *bp);
bool tox_event_friend_connection_status_pack(tox_non_null() const Tox_Event_Friend_Connection_Status *event, tox_non_null() Bin_Pack *bp);
bool tox_event_friend_lossless_packet_pack(tox_non_null() const Tox_Event_Friend_Lossless_Packet *event, tox_non_null() Bin_Pack *bp);
bool tox_event_friend_lossy_packet_pack(tox_non_null() const Tox_Event_Friend_Lossy_Packet *event, tox_non_null() Bin_Pack *bp);
bool tox_event_friend_message_pack(tox_non_null() const Tox_Event_Friend_Message *event, tox_non_null() Bin_Pack *bp);
bool tox_event_friend_name_pack(tox_non_null() const Tox_Event_Friend_Name *event, tox_non_null() Bin_Pack *bp);
bool tox_event_friend_read_receipt_pack(tox_non_null() const Tox_Event_Friend_Read_Receipt *event, tox_non_null() Bin_Pack *bp);
bool tox_event_friend_request_pack(tox_non_null() const Tox_Event_Friend_Request *event, tox_non_null() Bin_Pack *bp);
bool tox_event_friend_status_message_pack(tox_non_null() const Tox_Event_Friend_Status_Message *event, tox_non_null() Bin_Pack *bp);
bool tox_event_friend_status_pack(tox_non_null() const Tox_Event_Friend_Status *event, tox_non_null() Bin_Pack *bp);
bool tox_event_friend_typing_pack(tox_non_null() const Tox_Event_Friend_Typing *event, tox_non_null() Bin_Pack *bp);
bool tox_event_self_connection_status_pack(tox_non_null() const Tox_Event_Self_Connection_Status *event, tox_non_null() Bin_Pack *bp);
bool tox_event_group_peer_name_pack(tox_non_null() const Tox_Event_Group_Peer_Name *event, tox_non_null() Bin_Pack *bp);
bool tox_event_group_peer_status_pack(tox_non_null() const Tox_Event_Group_Peer_Status *event, tox_non_null() Bin_Pack *bp);
bool tox_event_group_topic_pack(tox_non_null() const Tox_Event_Group_Topic *event, tox_non_null() Bin_Pack *bp);
bool tox_event_group_privacy_state_pack(tox_non_null() const Tox_Event_Group_Privacy_State *event, tox_non_null() Bin_Pack *bp);
bool tox_event_group_voice_state_pack(tox_non_null() const Tox_Event_Group_Voice_State *event, tox_non_null() Bin_Pack *bp);
bool tox_event_group_topic_lock_pack(tox_non_null() const Tox_Event_Group_Topic_Lock *event, tox_non_null() Bin_Pack *bp);
bool tox_event_group_peer_limit_pack(tox_non_null() const Tox_Event_Group_Peer_Limit *event, tox_non_null() Bin_Pack *bp);
bool tox_event_group_password_pack(tox_non_null() const Tox_Event_Group_Password *event, tox_non_null() Bin_Pack *bp);
bool tox_event_group_message_pack(tox_non_null() const Tox_Event_Group_Message *event, tox_non_null() Bin_Pack *bp);
bool tox_event_group_private_message_pack(tox_non_null() const Tox_Event_Group_Private_Message *event, tox_non_null() Bin_Pack *bp);
bool tox_event_group_custom_packet_pack(tox_non_null() const Tox_Event_Group_Custom_Packet *event, tox_non_null() Bin_Pack *bp);
bool tox_event_group_custom_private_packet_pack(tox_non_null() const Tox_Event_Group_Custom_Private_Packet *event, tox_non_null() Bin_Pack *bp);
bool tox_event_group_invite_pack(tox_non_null() const Tox_Event_Group_Invite *event, tox_non_null() Bin_Pack *bp);
bool tox_event_group_peer_join_pack(tox_non_null() const Tox_Event_Group_Peer_Join *event, tox_non_null() Bin_Pack *bp);
bool tox_event_group_peer_exit_pack(tox_non_null() const Tox_Event_Group_Peer_Exit *event, tox_non_null() Bin_Pack *bp);
bool tox_event_group_self_join_pack(tox_non_null() const Tox_Event_Group_Self_Join *event, tox_non_null() Bin_Pack *bp);
bool tox_event_group_join_fail_pack(tox_non_null() const Tox_Event_Group_Join_Fail *event, tox_non_null() Bin_Pack *bp);
bool tox_event_group_moderation_pack(tox_non_null() const Tox_Event_Group_Moderation *event, tox_non_null() Bin_Pack *bp);
bool tox_event_dht_nodes_response_pack(tox_non_null() const Tox_Event_Dht_Nodes_Response *event, tox_non_null() Bin_Pack *bp);

/**
 * Unpack from msgpack.
 */
bool tox_event_unpack_into(tox_non_null() Tox_Event *event, tox_non_null() Bin_Unpack *bu, tox_non_null() const Memory *mem);

bool tox_event_conference_connected_unpack(tox_non_null() Tox_Event_Conference_Connected **event, tox_non_null() Bin_Unpack *bu, tox_non_null() const Memory *mem);
bool tox_event_conference_invite_unpack(tox_non_null() Tox_Event_Conference_Invite **event, tox_non_null() Bin_Unpack *bu, tox_non_null() const Memory *mem);
bool tox_event_conference_message_unpack(tox_non_null() Tox_Event_Conference_Message **event, tox_non_null() Bin_Unpack *bu, tox_non_null() const Memory *mem);
bool tox_event_conference_peer_list_changed_unpack(tox_non_null() Tox_Event_Conference_Peer_List_Changed **event, tox_non_null() Bin_Unpack *bu, tox_non_null() const Memory *mem);
bool tox_event_conference_peer_name_unpack(tox_non_null() Tox_Event_Conference_Peer_Name **event, tox_non_null() Bin_Unpack *bu, tox_non_null() const Memory *mem);
bool tox_event_conference_title_unpack(tox_non_null() Tox_Event_Conference_Title **event, tox_non_null() Bin_Unpack *bu, tox_non_null() const Memory *mem);
bool tox_event_file_chunk_request_unpack(tox_non_null() Tox_Event_File_Chunk_Request **event, tox_non_null() Bin_Unpack *bu, tox_non_null() const Memory *mem);
bool tox_event_file_recv_chunk_unpack(tox_non_null() Tox_Event_File_Recv_Chunk **event, tox_non_null() Bin_Unpack *bu, tox_non_null() const Memory *mem);
bool tox_event_file_recv_control_unpack(tox_non_null() Tox_Event_File_Recv_Control **event, tox_non_null() Bin_Unpack *bu, tox_non_null() const Memory *mem);
bool tox_event_file_recv_unpack(tox_non_null() Tox_Event_File_Recv **event, tox_non_null() Bin_Unpack *bu, tox_non_null() const Memory *mem);
bool tox_event_friend_connection_status_unpack(tox_non_null() Tox_Event_Friend_Connection_Status **event, tox_non_null() Bin_Unpack *bu, tox_non_null() const Memory *mem);
bool tox_event_friend_lossless_packet_unpack(tox_non_null() Tox_Event_Friend_Lossless_Packet **event, tox_non_null() Bin_Unpack *bu, tox_non_null() const Memory *mem);
bool tox_event_friend_lossy_packet_unpack(tox_non_null() Tox_Event_Friend_Lossy_Packet **event, tox_non_null() Bin_Unpack *bu, tox_non_null() const Memory *mem);
bool tox_event_friend_message_unpack(tox_non_null() Tox_Event_Friend_Message **event, tox_non_null() Bin_Unpack *bu, tox_non_null() const Memory *mem);
bool tox_event_friend_name_unpack(tox_non_null() Tox_Event_Friend_Name **event, tox_non_null() Bin_Unpack *bu, tox_non_null() const Memory *mem);
bool tox_event_friend_read_receipt_unpack(tox_non_null() Tox_Event_Friend_Read_Receipt **event, tox_non_null() Bin_Unpack *bu, tox_non_null() const Memory *mem);
bool tox_event_friend_request_unpack(tox_non_null() Tox_Event_Friend_Request **event, tox_non_null() Bin_Unpack *bu, tox_non_null() const Memory *mem);
bool tox_event_friend_status_message_unpack(tox_non_null() Tox_Event_Friend_Status_Message **event, tox_non_null() Bin_Unpack *bu, tox_non_null() const Memory *mem);
bool tox_event_friend_status_unpack(tox_non_null() Tox_Event_Friend_Status **event, tox_non_null() Bin_Unpack *bu, tox_non_null() const Memory *mem);
bool tox_event_friend_typing_unpack(tox_non_null() Tox_Event_Friend_Typing **event, tox_non_null() Bin_Unpack *bu, tox_non_null() const Memory *mem);
bool tox_event_self_connection_status_unpack(tox_non_null() Tox_Event_Self_Connection_Status **event, tox_non_null() Bin_Unpack *bu, tox_non_null() const Memory *mem);
bool tox_event_group_peer_name_unpack(tox_non_null() Tox_Event_Group_Peer_Name **event, tox_non_null() Bin_Unpack *bu, tox_non_null() const Memory *mem);
bool tox_event_group_peer_status_unpack(tox_non_null() Tox_Event_Group_Peer_Status **event, tox_non_null() Bin_Unpack *bu, tox_non_null() const Memory *mem);
bool tox_event_group_topic_unpack(tox_non_null() Tox_Event_Group_Topic **event, tox_non_null() Bin_Unpack *bu, tox_non_null() const Memory *mem);
bool tox_event_group_privacy_state_unpack(tox_non_null() Tox_Event_Group_Privacy_State **event, tox_non_null() Bin_Unpack *bu, tox_non_null() const Memory *mem);
bool tox_event_group_voice_state_unpack(tox_non_null() Tox_Event_Group_Voice_State **event, tox_non_null() Bin_Unpack *bu, tox_non_null() const Memory *mem);
bool tox_event_group_topic_lock_unpack(tox_non_null() Tox_Event_Group_Topic_Lock **event, tox_non_null() Bin_Unpack *bu, tox_non_null() const Memory *mem);
bool tox_event_group_peer_limit_unpack(tox_non_null() Tox_Event_Group_Peer_Limit **event, tox_non_null() Bin_Unpack *bu, tox_non_null() const Memory *mem);
bool tox_event_group_password_unpack(tox_non_null() Tox_Event_Group_Password **event, tox_non_null() Bin_Unpack *bu, tox_non_null() const Memory *mem);
bool tox_event_group_message_unpack(tox_non_null() Tox_Event_Group_Message **event, tox_non_null() Bin_Unpack *bu, tox_non_null() const Memory *mem);
bool tox_event_group_private_message_unpack(tox_non_null() Tox_Event_Group_Private_Message **event, tox_non_null() Bin_Unpack *bu, tox_non_null() const Memory *mem);
bool tox_event_group_custom_packet_unpack(tox_non_null() Tox_Event_Group_Custom_Packet **event, tox_non_null() Bin_Unpack *bu, tox_non_null() const Memory *mem);
bool tox_event_group_custom_private_packet_unpack(tox_non_null() Tox_Event_Group_Custom_Private_Packet **event, tox_non_null() Bin_Unpack *bu, tox_non_null() const Memory *mem);
bool tox_event_group_invite_unpack(tox_non_null() Tox_Event_Group_Invite **event, tox_non_null() Bin_Unpack *bu, tox_non_null() const Memory *mem);
bool tox_event_group_peer_join_unpack(tox_non_null() Tox_Event_Group_Peer_Join **event, tox_non_null() Bin_Unpack *bu, tox_non_null() const Memory *mem);
bool tox_event_group_peer_exit_unpack(tox_non_null() Tox_Event_Group_Peer_Exit **event, tox_non_null() Bin_Unpack *bu, tox_non_null() const Memory *mem);
bool tox_event_group_self_join_unpack(tox_non_null() Tox_Event_Group_Self_Join **event, tox_non_null() Bin_Unpack *bu, tox_non_null() const Memory *mem);
bool tox_event_group_join_fail_unpack(tox_non_null() Tox_Event_Group_Join_Fail **event, tox_non_null() Bin_Unpack *bu, tox_non_null() const Memory *mem);
bool tox_event_group_moderation_unpack(tox_non_null() Tox_Event_Group_Moderation **event, tox_non_null() Bin_Unpack *bu, tox_non_null() const Memory *mem);
bool tox_event_dht_nodes_response_unpack(tox_non_null() Tox_Event_Dht_Nodes_Response **event, tox_non_null() Bin_Unpack *bu, tox_non_null() const Memory *mem);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* C_TOXCORE_TOXCORE_TOX_EVENT_H */
