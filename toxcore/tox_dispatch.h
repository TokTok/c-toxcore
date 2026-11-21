/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2022-2026 The TokTok team.
 */

/**
 * WARNING: This is an experimental API and is subject to change.
 *
 * At this point, it probably won't change very much anymore, but we may have
 * small breaking changes before a stable release.
 */

#ifndef C_TOXCORE_TOXCORE_TOX_DISPATCH_H
#define C_TOXCORE_TOXCORE_TOX_DISPATCH_H

#include "tox.h"
#include "tox_attributes.h"
#include "tox_events.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief The events dispatch table.
 *
 * This holds all the callbacks registered with `tox_events_callback_*`
 * functions below.
 */
typedef struct Tox_Dispatch Tox_Dispatch;

typedef enum Tox_Err_Dispatch_New {
    /**
     * The function returned successfully.
     */
    TOX_ERR_DISPATCH_NEW_OK,

    /**
     * The function failed to allocate memory for the dispatch table.
     */
    TOX_ERR_DISPATCH_NEW_MALLOC,
} Tox_Err_Dispatch_New;

/**
 * @brief Creates a new empty event dispatch table.
 */
Tox_Dispatch *_Nullable tox_dispatch_new(Tox_Err_Dispatch_New *_Nullable error);

/**
 * @brief Deallocate an event dispatch table.
 */
void tox_dispatch_free(Tox_Dispatch *_Nullable dispatch);

/**
 * @brief Invoke registered callbacks for each of the events.
 *
 * @param dispatch The events dispatch table.
 * @param events The events object received from @ref tox_events_iterate.
 * @param user_data User data pointer to pass down to the callbacks.
 */
void tox_dispatch_invoke(const Tox_Dispatch *_Nonnull dispatch, const Tox_Events *_Nonnull events, void *_Nullable user_data);

typedef void tox_events_conference_connected_cb(
    const Tox_Event_Conference_Connected *_Nonnull event, void *_Nullable user_data);
typedef void tox_events_conference_invite_cb(
    const Tox_Event_Conference_Invite *_Nonnull event, void *_Nullable user_data);
typedef void tox_events_conference_message_cb(
    const Tox_Event_Conference_Message *_Nonnull event, void *_Nullable user_data);
typedef void tox_events_conference_peer_list_changed_cb(
    const Tox_Event_Conference_Peer_List_Changed *_Nonnull event, void *_Nullable user_data);
typedef void tox_events_conference_peer_name_cb(
    const Tox_Event_Conference_Peer_Name *_Nonnull event, void *_Nullable user_data);
typedef void tox_events_conference_title_cb(
    const Tox_Event_Conference_Title *_Nonnull event, void *_Nullable user_data);
typedef void tox_events_file_chunk_request_cb(
    const Tox_Event_File_Chunk_Request *_Nonnull event, void *_Nullable user_data);
typedef void tox_events_file_recv_cb(
    const Tox_Event_File_Recv *_Nonnull event, void *_Nullable user_data);
typedef void tox_events_file_recv_chunk_cb(
    const Tox_Event_File_Recv_Chunk *_Nonnull event, void *_Nullable user_data);
typedef void tox_events_file_recv_control_cb(
    const Tox_Event_File_Recv_Control *_Nonnull event, void *_Nullable user_data);
typedef void tox_events_friend_connection_status_cb(
    const Tox_Event_Friend_Connection_Status *_Nonnull event, void *_Nullable user_data);
typedef void tox_events_friend_lossless_packet_cb(
    const Tox_Event_Friend_Lossless_Packet *_Nonnull event, void *_Nullable user_data);
typedef void tox_events_friend_lossy_packet_cb(
    const Tox_Event_Friend_Lossy_Packet *_Nonnull event, void *_Nullable user_data);
typedef void tox_events_friend_message_cb(
    const Tox_Event_Friend_Message *_Nonnull event, void *_Nullable user_data);
typedef void tox_events_friend_name_cb(
    const Tox_Event_Friend_Name *_Nonnull event, void *_Nullable user_data);
typedef void tox_events_friend_read_receipt_cb(
    const Tox_Event_Friend_Read_Receipt *_Nonnull event, void *_Nullable user_data);
typedef void tox_events_friend_request_cb(
    const Tox_Event_Friend_Request *_Nonnull event, void *_Nullable user_data);
typedef void tox_events_friend_status_cb(
    const Tox_Event_Friend_Status *_Nonnull event, void *_Nullable user_data);
typedef void tox_events_friend_status_message_cb(
    const Tox_Event_Friend_Status_Message *_Nonnull event, void *_Nullable user_data);
typedef void tox_events_friend_typing_cb(
    const Tox_Event_Friend_Typing *_Nonnull event, void *_Nullable user_data);
typedef void tox_events_self_connection_status_cb(
    const Tox_Event_Self_Connection_Status *_Nonnull event, void *_Nullable user_data);
typedef void tox_events_group_peer_name_cb(
    const Tox_Event_Group_Peer_Name *_Nonnull event, void *_Nullable user_data);
typedef void tox_events_group_peer_status_cb(
    const Tox_Event_Group_Peer_Status *_Nonnull event, void *_Nullable user_data);
typedef void tox_events_group_topic_cb(
    const Tox_Event_Group_Topic *_Nonnull event, void *_Nullable user_data);
typedef void tox_events_group_privacy_state_cb(
    const Tox_Event_Group_Privacy_State *_Nonnull event, void *_Nullable user_data);
typedef void tox_events_group_voice_state_cb(
    const Tox_Event_Group_Voice_State *_Nonnull event, void *_Nullable user_data);
typedef void tox_events_group_topic_lock_cb(
    const Tox_Event_Group_Topic_Lock *_Nonnull event, void *_Nullable user_data);
typedef void tox_events_group_peer_limit_cb(
    const Tox_Event_Group_Peer_Limit *_Nonnull event, void *_Nullable user_data);
typedef void tox_events_group_password_cb(
    const Tox_Event_Group_Password *_Nonnull event, void *_Nullable user_data);
typedef void tox_events_group_message_cb(
    const Tox_Event_Group_Message *_Nonnull event, void *_Nullable user_data);
typedef void tox_events_group_private_message_cb(
    const Tox_Event_Group_Private_Message *_Nonnull event, void *_Nullable user_data);
typedef void tox_events_group_custom_packet_cb(
    const Tox_Event_Group_Custom_Packet *_Nonnull event, void *_Nullable user_data);
typedef void tox_events_group_custom_private_packet_cb(
    const Tox_Event_Group_Custom_Private_Packet *_Nonnull event, void *_Nullable user_data);
typedef void tox_events_group_invite_cb(
    const Tox_Event_Group_Invite *_Nonnull event, void *_Nullable user_data);
typedef void tox_events_group_peer_join_cb(
    const Tox_Event_Group_Peer_Join *_Nonnull event, void *_Nullable user_data);
typedef void tox_events_group_peer_exit_cb(
    const Tox_Event_Group_Peer_Exit *_Nonnull event, void *_Nullable user_data);
typedef void tox_events_group_self_join_cb(
    const Tox_Event_Group_Self_Join *_Nonnull event, void *_Nullable user_data);
typedef void tox_events_group_join_fail_cb(
    const Tox_Event_Group_Join_Fail *_Nonnull event, void *_Nullable user_data);
typedef void tox_events_group_moderation_cb(
    const Tox_Event_Group_Moderation *_Nonnull event, void *_Nullable user_data);
typedef void tox_events_dht_nodes_response_cb(
    const Tox_Event_Dht_Nodes_Response *_Nonnull event, void *_Nullable user_data);

void tox_events_callback_conference_connected(
    Tox_Dispatch *_Nonnull dispatch, tox_events_conference_connected_cb *_Nullable callback);
void tox_events_callback_conference_invite(
    Tox_Dispatch *_Nonnull dispatch, tox_events_conference_invite_cb *_Nullable callback);
void tox_events_callback_conference_message(
    Tox_Dispatch *_Nonnull dispatch, tox_events_conference_message_cb *_Nullable callback);
void tox_events_callback_conference_peer_list_changed(
    Tox_Dispatch *_Nonnull dispatch, tox_events_conference_peer_list_changed_cb *_Nullable callback);
void tox_events_callback_conference_peer_name(
    Tox_Dispatch *_Nonnull dispatch, tox_events_conference_peer_name_cb *_Nullable callback);
void tox_events_callback_conference_title(
    Tox_Dispatch *_Nonnull dispatch, tox_events_conference_title_cb *_Nullable callback);
void tox_events_callback_file_chunk_request(
    Tox_Dispatch *_Nonnull dispatch, tox_events_file_chunk_request_cb *_Nullable callback);
void tox_events_callback_file_recv(
    Tox_Dispatch *_Nonnull dispatch, tox_events_file_recv_cb *_Nullable callback);
void tox_events_callback_file_recv_chunk(
    Tox_Dispatch *_Nonnull dispatch, tox_events_file_recv_chunk_cb *_Nullable callback);
void tox_events_callback_file_recv_control(
    Tox_Dispatch *_Nonnull dispatch, tox_events_file_recv_control_cb *_Nullable callback);
void tox_events_callback_friend_connection_status(
    Tox_Dispatch *_Nonnull dispatch, tox_events_friend_connection_status_cb *_Nullable callback);
void tox_events_callback_friend_lossless_packet(
    Tox_Dispatch *_Nonnull dispatch, tox_events_friend_lossless_packet_cb *_Nullable callback);
void tox_events_callback_friend_lossy_packet(
    Tox_Dispatch *_Nonnull dispatch, tox_events_friend_lossy_packet_cb *_Nullable callback);
void tox_events_callback_friend_message(
    Tox_Dispatch *_Nonnull dispatch, tox_events_friend_message_cb *_Nullable callback);
void tox_events_callback_friend_name(
    Tox_Dispatch *_Nonnull dispatch, tox_events_friend_name_cb *_Nullable callback);
void tox_events_callback_friend_read_receipt(
    Tox_Dispatch *_Nonnull dispatch, tox_events_friend_read_receipt_cb *_Nullable callback);
void tox_events_callback_friend_request(
    Tox_Dispatch *_Nonnull dispatch, tox_events_friend_request_cb *_Nullable callback);
void tox_events_callback_friend_status(
    Tox_Dispatch *_Nonnull dispatch, tox_events_friend_status_cb *_Nullable callback);
void tox_events_callback_friend_status_message(
    Tox_Dispatch *_Nonnull dispatch, tox_events_friend_status_message_cb *_Nullable callback);
void tox_events_callback_friend_typing(
    Tox_Dispatch *_Nonnull dispatch, tox_events_friend_typing_cb *_Nullable callback);
void tox_events_callback_self_connection_status(
    Tox_Dispatch *_Nonnull dispatch, tox_events_self_connection_status_cb *_Nullable callback);
void tox_events_callback_group_peer_name(
    Tox_Dispatch *_Nonnull dispatch, tox_events_group_peer_name_cb *_Nullable callback);
void tox_events_callback_group_peer_status(
    Tox_Dispatch *_Nonnull dispatch, tox_events_group_peer_status_cb *_Nullable callback);
void tox_events_callback_group_topic(
    Tox_Dispatch *_Nonnull dispatch, tox_events_group_topic_cb *_Nullable callback);
void tox_events_callback_group_privacy_state(
    Tox_Dispatch *_Nonnull dispatch, tox_events_group_privacy_state_cb *_Nullable callback);
void tox_events_callback_group_voice_state(
    Tox_Dispatch *_Nonnull dispatch, tox_events_group_voice_state_cb *_Nullable callback);
void tox_events_callback_group_topic_lock(
    Tox_Dispatch *_Nonnull dispatch, tox_events_group_topic_lock_cb *_Nullable callback);
void tox_events_callback_group_peer_limit(
    Tox_Dispatch *_Nonnull dispatch, tox_events_group_peer_limit_cb *_Nullable callback);
void tox_events_callback_group_password(
    Tox_Dispatch *_Nonnull dispatch, tox_events_group_password_cb *_Nullable callback);
void tox_events_callback_group_message(
    Tox_Dispatch *_Nonnull dispatch, tox_events_group_message_cb *_Nullable callback);
void tox_events_callback_group_private_message(
    Tox_Dispatch *_Nonnull dispatch, tox_events_group_private_message_cb *_Nullable callback);
void tox_events_callback_group_custom_packet(
    Tox_Dispatch *_Nonnull dispatch, tox_events_group_custom_packet_cb *_Nullable callback);
void tox_events_callback_group_custom_private_packet(
    Tox_Dispatch *_Nonnull dispatch, tox_events_group_custom_private_packet_cb *_Nullable callback);
void tox_events_callback_group_invite(
    Tox_Dispatch *_Nonnull dispatch, tox_events_group_invite_cb *_Nullable callback);
void tox_events_callback_group_peer_join(
    Tox_Dispatch *_Nonnull dispatch, tox_events_group_peer_join_cb *_Nullable callback);
void tox_events_callback_group_peer_exit(
    Tox_Dispatch *_Nonnull dispatch, tox_events_group_peer_exit_cb *_Nullable callback);
void tox_events_callback_group_self_join(
    Tox_Dispatch *_Nonnull dispatch, tox_events_group_self_join_cb *_Nullable callback);
void tox_events_callback_group_join_fail(
    Tox_Dispatch *_Nonnull dispatch, tox_events_group_join_fail_cb *_Nullable callback);
void tox_events_callback_group_moderation(
    Tox_Dispatch *_Nonnull dispatch, tox_events_group_moderation_cb *_Nullable callback);
void tox_events_callback_dht_nodes_response(
    Tox_Dispatch *_Nonnull dispatch, tox_events_dht_nodes_response_cb *_Nullable callback);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* C_TOXCORE_TOXCORE_TOX_DISPATCH_H */
