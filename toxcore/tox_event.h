/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2022-2025 The TokTok team.
 */

#ifndef C_TOXCORE_TOXCORE_TOX_EVENT_H
#define C_TOXCORE_TOXCORE_TOX_EVENT_H

#include "attributes.h"
#include "bin_pack.h"
#include "bin_unpack.h"
#include "mem.h"
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
bool tox_event_construct(non_null() Tox_Event *event, Tox_Event_Type type, non_null() const Memory *mem);

Tox_Event_Conference_Connected *tox_event_conference_connected_new(non_null() const Memory *mem);
Tox_Event_Conference_Invite *tox_event_conference_invite_new(non_null() const Memory *mem);
Tox_Event_Conference_Message *tox_event_conference_message_new(non_null() const Memory *mem);
Tox_Event_Conference_Peer_List_Changed *tox_event_conference_peer_list_changed_new(non_null() const Memory *mem);
Tox_Event_Conference_Peer_Name *tox_event_conference_peer_name_new(non_null() const Memory *mem);
Tox_Event_Conference_Title *tox_event_conference_title_new(non_null() const Memory *mem);
Tox_Event_File_Chunk_Request *tox_event_file_chunk_request_new(non_null() const Memory *mem);
Tox_Event_File_Recv_Chunk *tox_event_file_recv_chunk_new(non_null() const Memory *mem);
Tox_Event_File_Recv_Control *tox_event_file_recv_control_new(non_null() const Memory *mem);
Tox_Event_File_Recv *tox_event_file_recv_new(non_null() const Memory *mem);
Tox_Event_Friend_Connection_Status *tox_event_friend_connection_status_new(non_null() const Memory *mem);
Tox_Event_Friend_Lossless_Packet *tox_event_friend_lossless_packet_new(non_null() const Memory *mem);
Tox_Event_Friend_Lossy_Packet *tox_event_friend_lossy_packet_new(non_null() const Memory *mem);
Tox_Event_Friend_Message *tox_event_friend_message_new(non_null() const Memory *mem);
Tox_Event_Friend_Name *tox_event_friend_name_new(non_null() const Memory *mem);
Tox_Event_Friend_Read_Receipt *tox_event_friend_read_receipt_new(non_null() const Memory *mem);
Tox_Event_Friend_Request *tox_event_friend_request_new(non_null() const Memory *mem);
Tox_Event_Friend_Status_Message *tox_event_friend_status_message_new(non_null() const Memory *mem);
Tox_Event_Friend_Status *tox_event_friend_status_new(non_null() const Memory *mem);
Tox_Event_Friend_Typing *tox_event_friend_typing_new(non_null() const Memory *mem);
Tox_Event_Self_Connection_Status *tox_event_self_connection_status_new(non_null() const Memory *mem);
Tox_Event_Group_Peer_Name *tox_event_group_peer_name_new(non_null() const Memory *mem);
Tox_Event_Group_Peer_Status *tox_event_group_peer_status_new(non_null() const Memory *mem);
Tox_Event_Group_Topic *tox_event_group_topic_new(non_null() const Memory *mem);
Tox_Event_Group_Privacy_State *tox_event_group_privacy_state_new(non_null() const Memory *mem);
Tox_Event_Group_Voice_State *tox_event_group_voice_state_new(non_null() const Memory *mem);
Tox_Event_Group_Topic_Lock *tox_event_group_topic_lock_new(non_null() const Memory *mem);
Tox_Event_Group_Peer_Limit *tox_event_group_peer_limit_new(non_null() const Memory *mem);
Tox_Event_Group_Password *tox_event_group_password_new(non_null() const Memory *mem);
Tox_Event_Group_Message *tox_event_group_message_new(non_null() const Memory *mem);
Tox_Event_Group_Private_Message *tox_event_group_private_message_new(non_null() const Memory *mem);
Tox_Event_Group_Custom_Packet *tox_event_group_custom_packet_new(non_null() const Memory *mem);
Tox_Event_Group_Custom_Private_Packet *tox_event_group_custom_private_packet_new(non_null() const Memory *mem);
Tox_Event_Group_Invite *tox_event_group_invite_new(non_null() const Memory *mem);
Tox_Event_Group_Peer_Join *tox_event_group_peer_join_new(non_null() const Memory *mem);
Tox_Event_Group_Peer_Exit *tox_event_group_peer_exit_new(non_null() const Memory *mem);
Tox_Event_Group_Self_Join *tox_event_group_self_join_new(non_null() const Memory *mem);
Tox_Event_Group_Join_Fail *tox_event_group_join_fail_new(non_null() const Memory *mem);
Tox_Event_Group_Moderation *tox_event_group_moderation_new(non_null() const Memory *mem);
Tox_Event_Dht_Nodes_Response *tox_event_dht_nodes_response_new(non_null() const Memory *mem);

/**
 * Destructor.
 */
void tox_event_destruct(nullable() Tox_Event *event, non_null() const Memory *mem);

void tox_event_conference_connected_free(nullable() Tox_Event_Conference_Connected *conference_connected, non_null() const Memory *mem);
void tox_event_conference_invite_free(nullable() Tox_Event_Conference_Invite *conference_invite, non_null() const Memory *mem);
void tox_event_conference_message_free(nullable() Tox_Event_Conference_Message *conference_message, non_null() const Memory *mem);
void tox_event_conference_peer_list_changed_free(nullable() Tox_Event_Conference_Peer_List_Changed *conference_peer_list_changed, non_null() const Memory *mem);
void tox_event_conference_peer_name_free(nullable() Tox_Event_Conference_Peer_Name *conference_peer_name, non_null() const Memory *mem);
void tox_event_conference_title_free(nullable() Tox_Event_Conference_Title *conference_title, non_null() const Memory *mem);
void tox_event_file_chunk_request_free(nullable() Tox_Event_File_Chunk_Request *file_chunk_request, non_null() const Memory *mem);
void tox_event_file_recv_chunk_free(nullable() Tox_Event_File_Recv_Chunk *file_recv_chunk, non_null() const Memory *mem);
void tox_event_file_recv_control_free(nullable() Tox_Event_File_Recv_Control *file_recv_control, non_null() const Memory *mem);
void tox_event_file_recv_free(nullable() Tox_Event_File_Recv *file_recv, non_null() const Memory *mem);
void tox_event_friend_connection_status_free(nullable() Tox_Event_Friend_Connection_Status *friend_connection_status, non_null() const Memory *mem);
void tox_event_friend_lossless_packet_free(nullable() Tox_Event_Friend_Lossless_Packet *friend_lossless_packet, non_null() const Memory *mem);
void tox_event_friend_lossy_packet_free(nullable() Tox_Event_Friend_Lossy_Packet *friend_lossy_packet, non_null() const Memory *mem);
void tox_event_friend_message_free(nullable() Tox_Event_Friend_Message *friend_message, non_null() const Memory *mem);
void tox_event_friend_name_free(nullable() Tox_Event_Friend_Name *friend_name, non_null() const Memory *mem);
void tox_event_friend_read_receipt_free(nullable() Tox_Event_Friend_Read_Receipt *friend_read_receipt, non_null() const Memory *mem);
void tox_event_friend_request_free(nullable() Tox_Event_Friend_Request *friend_request, non_null() const Memory *mem);
void tox_event_friend_status_message_free(nullable() Tox_Event_Friend_Status_Message *friend_status_message, non_null() const Memory *mem);
void tox_event_friend_status_free(nullable() Tox_Event_Friend_Status *friend_status, non_null() const Memory *mem);
void tox_event_friend_typing_free(nullable() Tox_Event_Friend_Typing *friend_typing, non_null() const Memory *mem);
void tox_event_self_connection_status_free(nullable() Tox_Event_Self_Connection_Status *self_connection_status, non_null() const Memory *mem);
void tox_event_group_peer_name_free(nullable() Tox_Event_Group_Peer_Name *group_peer_name, non_null() const Memory *mem);
void tox_event_group_peer_status_free(nullable() Tox_Event_Group_Peer_Status *group_peer_status, non_null() const Memory *mem);
void tox_event_group_topic_free(nullable() Tox_Event_Group_Topic *group_topic, non_null() const Memory *mem);
void tox_event_group_privacy_state_free(nullable() Tox_Event_Group_Privacy_State *group_privacy_state, non_null() const Memory *mem);
void tox_event_group_voice_state_free(nullable() Tox_Event_Group_Voice_State *group_voice_state, non_null() const Memory *mem);
void tox_event_group_topic_lock_free(nullable() Tox_Event_Group_Topic_Lock *group_topic_lock, non_null() const Memory *mem);
void tox_event_group_peer_limit_free(nullable() Tox_Event_Group_Peer_Limit *group_peer_limit, non_null() const Memory *mem);
void tox_event_group_password_free(nullable() Tox_Event_Group_Password *group_password, non_null() const Memory *mem);
void tox_event_group_message_free(nullable() Tox_Event_Group_Message *group_message, non_null() const Memory *mem);
void tox_event_group_private_message_free(nullable() Tox_Event_Group_Private_Message *group_private_message, non_null() const Memory *mem);
void tox_event_group_custom_packet_free(nullable() Tox_Event_Group_Custom_Packet *group_custom_packet, non_null() const Memory *mem);
void tox_event_group_custom_private_packet_free(nullable() Tox_Event_Group_Custom_Private_Packet *group_custom_private_packet, non_null() const Memory *mem);
void tox_event_group_invite_free(nullable() Tox_Event_Group_Invite *group_invite, non_null() const Memory *mem);
void tox_event_group_peer_join_free(nullable() Tox_Event_Group_Peer_Join *group_peer_join, non_null() const Memory *mem);
void tox_event_group_peer_exit_free(nullable() Tox_Event_Group_Peer_Exit *group_peer_exit, non_null() const Memory *mem);
void tox_event_group_self_join_free(nullable() Tox_Event_Group_Self_Join *group_self_join, non_null() const Memory *mem);
void tox_event_group_join_fail_free(nullable() Tox_Event_Group_Join_Fail *group_join_fail, non_null() const Memory *mem);
void tox_event_group_moderation_free(nullable() Tox_Event_Group_Moderation *group_moderation, non_null() const Memory *mem);
void tox_event_dht_nodes_response_free(nullable() Tox_Event_Dht_Nodes_Response *dht_nodes_response, non_null() const Memory *mem);

/**
 * Pack into msgpack.
 */
bool tox_event_pack(non_null() const Tox_Event *event, non_null() Bin_Pack *bp);

bool tox_event_conference_connected_pack(non_null() const Tox_Event_Conference_Connected *event, non_null() Bin_Pack *bp);
bool tox_event_conference_invite_pack(non_null() const Tox_Event_Conference_Invite *event, non_null() Bin_Pack *bp);
bool tox_event_conference_message_pack(non_null() const Tox_Event_Conference_Message *event, non_null() Bin_Pack *bp);
bool tox_event_conference_peer_list_changed_pack(non_null() const Tox_Event_Conference_Peer_List_Changed *event, non_null() Bin_Pack *bp);
bool tox_event_conference_peer_name_pack(non_null() const Tox_Event_Conference_Peer_Name *event, non_null() Bin_Pack *bp);
bool tox_event_conference_title_pack(non_null() const Tox_Event_Conference_Title *event, non_null() Bin_Pack *bp);
bool tox_event_file_chunk_request_pack(non_null() const Tox_Event_File_Chunk_Request *event, non_null() Bin_Pack *bp);
bool tox_event_file_recv_chunk_pack(non_null() const Tox_Event_File_Recv_Chunk *event, non_null() Bin_Pack *bp);
bool tox_event_file_recv_control_pack(non_null() const Tox_Event_File_Recv_Control *event, non_null() Bin_Pack *bp);
bool tox_event_file_recv_pack(non_null() const Tox_Event_File_Recv *event, non_null() Bin_Pack *bp);
bool tox_event_friend_connection_status_pack(non_null() const Tox_Event_Friend_Connection_Status *event, non_null() Bin_Pack *bp);
bool tox_event_friend_lossless_packet_pack(non_null() const Tox_Event_Friend_Lossless_Packet *event, non_null() Bin_Pack *bp);
bool tox_event_friend_lossy_packet_pack(non_null() const Tox_Event_Friend_Lossy_Packet *event, non_null() Bin_Pack *bp);
bool tox_event_friend_message_pack(non_null() const Tox_Event_Friend_Message *event, non_null() Bin_Pack *bp);
bool tox_event_friend_name_pack(non_null() const Tox_Event_Friend_Name *event, non_null() Bin_Pack *bp);
bool tox_event_friend_read_receipt_pack(non_null() const Tox_Event_Friend_Read_Receipt *event, non_null() Bin_Pack *bp);
bool tox_event_friend_request_pack(non_null() const Tox_Event_Friend_Request *event, non_null() Bin_Pack *bp);
bool tox_event_friend_status_message_pack(non_null() const Tox_Event_Friend_Status_Message *event, non_null() Bin_Pack *bp);
bool tox_event_friend_status_pack(non_null() const Tox_Event_Friend_Status *event, non_null() Bin_Pack *bp);
bool tox_event_friend_typing_pack(non_null() const Tox_Event_Friend_Typing *event, non_null() Bin_Pack *bp);
bool tox_event_self_connection_status_pack(non_null() const Tox_Event_Self_Connection_Status *event, non_null() Bin_Pack *bp);
bool tox_event_group_peer_name_pack(non_null() const Tox_Event_Group_Peer_Name *event, non_null() Bin_Pack *bp);
bool tox_event_group_peer_status_pack(non_null() const Tox_Event_Group_Peer_Status *event, non_null() Bin_Pack *bp);
bool tox_event_group_topic_pack(non_null() const Tox_Event_Group_Topic *event, non_null() Bin_Pack *bp);
bool tox_event_group_privacy_state_pack(non_null() const Tox_Event_Group_Privacy_State *event, non_null() Bin_Pack *bp);
bool tox_event_group_voice_state_pack(non_null() const Tox_Event_Group_Voice_State *event, non_null() Bin_Pack *bp);
bool tox_event_group_topic_lock_pack(non_null() const Tox_Event_Group_Topic_Lock *event, non_null() Bin_Pack *bp);
bool tox_event_group_peer_limit_pack(non_null() const Tox_Event_Group_Peer_Limit *event, non_null() Bin_Pack *bp);
bool tox_event_group_password_pack(non_null() const Tox_Event_Group_Password *event, non_null() Bin_Pack *bp);
bool tox_event_group_message_pack(non_null() const Tox_Event_Group_Message *event, non_null() Bin_Pack *bp);
bool tox_event_group_private_message_pack(non_null() const Tox_Event_Group_Private_Message *event, non_null() Bin_Pack *bp);
bool tox_event_group_custom_packet_pack(non_null() const Tox_Event_Group_Custom_Packet *event, non_null() Bin_Pack *bp);
bool tox_event_group_custom_private_packet_pack(non_null() const Tox_Event_Group_Custom_Private_Packet *event, non_null() Bin_Pack *bp);
bool tox_event_group_invite_pack(non_null() const Tox_Event_Group_Invite *event, non_null() Bin_Pack *bp);
bool tox_event_group_peer_join_pack(non_null() const Tox_Event_Group_Peer_Join *event, non_null() Bin_Pack *bp);
bool tox_event_group_peer_exit_pack(non_null() const Tox_Event_Group_Peer_Exit *event, non_null() Bin_Pack *bp);
bool tox_event_group_self_join_pack(non_null() const Tox_Event_Group_Self_Join *event, non_null() Bin_Pack *bp);
bool tox_event_group_join_fail_pack(non_null() const Tox_Event_Group_Join_Fail *event, non_null() Bin_Pack *bp);
bool tox_event_group_moderation_pack(non_null() const Tox_Event_Group_Moderation *event, non_null() Bin_Pack *bp);
bool tox_event_dht_nodes_response_pack(non_null() const Tox_Event_Dht_Nodes_Response *event, non_null() Bin_Pack *bp);

/**
 * Unpack from msgpack.
 */
bool tox_event_unpack_into(non_null() Tox_Event *event, non_null() Bin_Unpack *bu, non_null() const Memory *mem);

bool tox_event_conference_connected_unpack(non_null() Tox_Event_Conference_Connected **event, non_null() Bin_Unpack *bu, non_null() const Memory *mem);
bool tox_event_conference_invite_unpack(non_null() Tox_Event_Conference_Invite **event, non_null() Bin_Unpack *bu, non_null() const Memory *mem);
bool tox_event_conference_message_unpack(non_null() Tox_Event_Conference_Message **event, non_null() Bin_Unpack *bu, non_null() const Memory *mem);
bool tox_event_conference_peer_list_changed_unpack(non_null() Tox_Event_Conference_Peer_List_Changed **event, non_null() Bin_Unpack *bu, non_null() const Memory *mem);
bool tox_event_conference_peer_name_unpack(non_null() Tox_Event_Conference_Peer_Name **event, non_null() Bin_Unpack *bu, non_null() const Memory *mem);
bool tox_event_conference_title_unpack(non_null() Tox_Event_Conference_Title **event, non_null() Bin_Unpack *bu, non_null() const Memory *mem);
bool tox_event_file_chunk_request_unpack(non_null() Tox_Event_File_Chunk_Request **event, non_null() Bin_Unpack *bu, non_null() const Memory *mem);
bool tox_event_file_recv_chunk_unpack(non_null() Tox_Event_File_Recv_Chunk **event, non_null() Bin_Unpack *bu, non_null() const Memory *mem);
bool tox_event_file_recv_control_unpack(non_null() Tox_Event_File_Recv_Control **event, non_null() Bin_Unpack *bu, non_null() const Memory *mem);
bool tox_event_file_recv_unpack(non_null() Tox_Event_File_Recv **event, non_null() Bin_Unpack *bu, non_null() const Memory *mem);
bool tox_event_friend_connection_status_unpack(non_null() Tox_Event_Friend_Connection_Status **event, non_null() Bin_Unpack *bu, non_null() const Memory *mem);
bool tox_event_friend_lossless_packet_unpack(non_null() Tox_Event_Friend_Lossless_Packet **event, non_null() Bin_Unpack *bu, non_null() const Memory *mem);
bool tox_event_friend_lossy_packet_unpack(non_null() Tox_Event_Friend_Lossy_Packet **event, non_null() Bin_Unpack *bu, non_null() const Memory *mem);
bool tox_event_friend_message_unpack(non_null() Tox_Event_Friend_Message **event, non_null() Bin_Unpack *bu, non_null() const Memory *mem);
bool tox_event_friend_name_unpack(non_null() Tox_Event_Friend_Name **event, non_null() Bin_Unpack *bu, non_null() const Memory *mem);
bool tox_event_friend_read_receipt_unpack(non_null() Tox_Event_Friend_Read_Receipt **event, non_null() Bin_Unpack *bu, non_null() const Memory *mem);
bool tox_event_friend_request_unpack(non_null() Tox_Event_Friend_Request **event, non_null() Bin_Unpack *bu, non_null() const Memory *mem);
bool tox_event_friend_status_message_unpack(non_null() Tox_Event_Friend_Status_Message **event, non_null() Bin_Unpack *bu, non_null() const Memory *mem);
bool tox_event_friend_status_unpack(non_null() Tox_Event_Friend_Status **event, non_null() Bin_Unpack *bu, non_null() const Memory *mem);
bool tox_event_friend_typing_unpack(non_null() Tox_Event_Friend_Typing **event, non_null() Bin_Unpack *bu, non_null() const Memory *mem);
bool tox_event_self_connection_status_unpack(non_null() Tox_Event_Self_Connection_Status **event, non_null() Bin_Unpack *bu, non_null() const Memory *mem);
bool tox_event_group_peer_name_unpack(non_null() Tox_Event_Group_Peer_Name **event, non_null() Bin_Unpack *bu, non_null() const Memory *mem);
bool tox_event_group_peer_status_unpack(non_null() Tox_Event_Group_Peer_Status **event, non_null() Bin_Unpack *bu, non_null() const Memory *mem);
bool tox_event_group_topic_unpack(non_null() Tox_Event_Group_Topic **event, non_null() Bin_Unpack *bu, non_null() const Memory *mem);
bool tox_event_group_privacy_state_unpack(non_null() Tox_Event_Group_Privacy_State **event, non_null() Bin_Unpack *bu, non_null() const Memory *mem);
bool tox_event_group_voice_state_unpack(non_null() Tox_Event_Group_Voice_State **event, non_null() Bin_Unpack *bu, non_null() const Memory *mem);
bool tox_event_group_topic_lock_unpack(non_null() Tox_Event_Group_Topic_Lock **event, non_null() Bin_Unpack *bu, non_null() const Memory *mem);
bool tox_event_group_peer_limit_unpack(non_null() Tox_Event_Group_Peer_Limit **event, non_null() Bin_Unpack *bu, non_null() const Memory *mem);
bool tox_event_group_password_unpack(non_null() Tox_Event_Group_Password **event, non_null() Bin_Unpack *bu, non_null() const Memory *mem);
bool tox_event_group_message_unpack(non_null() Tox_Event_Group_Message **event, non_null() Bin_Unpack *bu, non_null() const Memory *mem);
bool tox_event_group_private_message_unpack(non_null() Tox_Event_Group_Private_Message **event, non_null() Bin_Unpack *bu, non_null() const Memory *mem);
bool tox_event_group_custom_packet_unpack(non_null() Tox_Event_Group_Custom_Packet **event, non_null() Bin_Unpack *bu, non_null() const Memory *mem);
bool tox_event_group_custom_private_packet_unpack(non_null() Tox_Event_Group_Custom_Private_Packet **event, non_null() Bin_Unpack *bu, non_null() const Memory *mem);
bool tox_event_group_invite_unpack(non_null() Tox_Event_Group_Invite **event, non_null() Bin_Unpack *bu, non_null() const Memory *mem);
bool tox_event_group_peer_join_unpack(non_null() Tox_Event_Group_Peer_Join **event, non_null() Bin_Unpack *bu, non_null() const Memory *mem);
bool tox_event_group_peer_exit_unpack(non_null() Tox_Event_Group_Peer_Exit **event, non_null() Bin_Unpack *bu, non_null() const Memory *mem);
bool tox_event_group_self_join_unpack(non_null() Tox_Event_Group_Self_Join **event, non_null() Bin_Unpack *bu, non_null() const Memory *mem);
bool tox_event_group_join_fail_unpack(non_null() Tox_Event_Group_Join_Fail **event, non_null() Bin_Unpack *bu, non_null() const Memory *mem);
bool tox_event_group_moderation_unpack(non_null() Tox_Event_Group_Moderation **event, non_null() Bin_Unpack *bu, non_null() const Memory *mem);
bool tox_event_dht_nodes_response_unpack(non_null() Tox_Event_Dht_Nodes_Response **event, non_null() Bin_Unpack *bu, non_null() const Memory *mem);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* C_TOXCORE_TOXCORE_TOX_EVENT_H */
