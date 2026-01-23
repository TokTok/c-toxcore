/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2022-2025 The TokTok team.
 */

#ifndef C_TOXCORE_TOXCORE_EVENTS_EVENTS_ALLOC_H
#define C_TOXCORE_TOXCORE_EVENTS_EVENTS_ALLOC_H

#include <stdbool.h>
#include <stdint.h>

#include "../attributes.h"
#include "../tox.h"
#include "../tox_events.h"
#include "../tox_private.h"

#ifdef __cplusplus
extern "C" {
#endif

struct Memory;

struct Tox_Events {
    Tox_Event *_Nullable events;
    uint32_t events_size;
    uint32_t events_capacity;

    const struct Memory *_Nonnull mem;
};

typedef struct Tox_Events_State {
    Tox_Err_Events_Iterate error;
    const struct Memory *_Nonnull mem;
    Tox_Events *_Nullable events;
} Tox_Events_State;

void tox_events_handle_conference_connected(Tox_Conference_Number conference_number, Tox_Events_State *_Nonnull state);
void tox_events_handle_conference_invite(uint32_t friend_number, Tox_Conference_Type type, const uint8_t *_Nonnull cookie, size_t length, Tox_Events_State *_Nonnull state);
void tox_events_handle_conference_message(uint32_t conference_number, uint32_t peer_number, Tox_Message_Type type, const uint8_t *_Nonnull message, size_t length, Tox_Events_State *_Nonnull state);
void tox_events_handle_conference_peer_list_changed(uint32_t conference_number, Tox_Events_State *_Nonnull state);
void tox_events_handle_conference_peer_name(uint32_t conference_number, uint32_t peer_number, const uint8_t *_Nonnull name, size_t length, Tox_Events_State *_Nonnull state);
void tox_events_handle_conference_title(uint32_t conference_number, uint32_t peer_number, const uint8_t *_Nonnull title, size_t length, Tox_Events_State *_Nonnull state);
void tox_events_handle_dht_nodes_response(const uint8_t *_Nonnull public_key, const char *_Nonnull ip, uint32_t ip_length, uint16_t port, Tox_Events_State *_Nonnull state);
void tox_events_handle_file_chunk_request(uint32_t friend_number, uint32_t file_number, uint64_t position, size_t length, Tox_Events_State *_Nonnull state);
void tox_events_handle_file_recv(uint32_t friend_number, uint32_t file_number, uint32_t kind, uint64_t file_size, const uint8_t *_Nonnull filename, size_t filename_length,
                                 Tox_Events_State *_Nonnull state);
void tox_events_handle_file_recv_chunk(uint32_t friend_number, uint32_t file_number, uint64_t position, const uint8_t *_Nullable data, size_t length, Tox_Events_State *_Nonnull state);
void tox_events_handle_file_recv_control(uint32_t friend_number, uint32_t file_number, Tox_File_Control control, Tox_Events_State *_Nonnull state);
void tox_events_handle_friend_connection_status(uint32_t friend_number, Tox_Connection connection_status, Tox_Events_State *_Nonnull state);
void tox_events_handle_friend_lossless_packet(uint32_t friend_number, const uint8_t *_Nonnull data, size_t length, Tox_Events_State *_Nonnull state);
void tox_events_handle_friend_lossy_packet(uint32_t friend_number, const uint8_t *_Nonnull data, size_t length, Tox_Events_State *_Nonnull state);
void tox_events_handle_friend_message(uint32_t friend_number, Tox_Message_Type type, const uint8_t *_Nonnull message, size_t length, Tox_Events_State *_Nonnull state);
void tox_events_handle_friend_name(uint32_t friend_number, const uint8_t *_Nonnull name, size_t length, Tox_Events_State *_Nonnull state);
void tox_events_handle_friend_read_receipt(uint32_t friend_number, uint32_t message_id, Tox_Events_State *_Nonnull state);
void tox_events_handle_friend_request(const uint8_t *_Nonnull public_key, const uint8_t *_Nonnull message, size_t length, Tox_Events_State *_Nonnull state);
void tox_events_handle_friend_status(uint32_t friend_number, Tox_User_Status status, Tox_Events_State *_Nonnull state);
void tox_events_handle_friend_status_message(uint32_t friend_number, const uint8_t *_Nonnull message, size_t length, Tox_Events_State *_Nonnull state);
void tox_events_handle_friend_typing(uint32_t friend_number, bool typing, Tox_Events_State *_Nonnull state);
void tox_events_handle_self_connection_status(Tox_Connection connection_status, Tox_Events_State *_Nonnull state);
void tox_events_handle_group_peer_name(uint32_t group_number, uint32_t peer_id, const uint8_t *_Nonnull name, size_t name_length, Tox_Events_State *_Nonnull state);
void tox_events_handle_group_peer_status(uint32_t group_number, uint32_t peer_id, Tox_User_Status status, Tox_Events_State *_Nonnull state);
void tox_events_handle_group_topic(uint32_t group_number, uint32_t peer_id, const uint8_t *_Nonnull topic, size_t topic_length, Tox_Events_State *_Nonnull state);
void tox_events_handle_group_privacy_state(uint32_t group_number, Tox_Group_Privacy_State privacy_state, Tox_Events_State *_Nonnull state);
void tox_events_handle_group_voice_state(uint32_t group_number, Tox_Group_Voice_State voice_state, Tox_Events_State *_Nonnull state);
void tox_events_handle_group_topic_lock(uint32_t group_number, Tox_Group_Topic_Lock topic_lock, Tox_Events_State *_Nonnull state);
void tox_events_handle_group_peer_limit(uint32_t group_number, uint32_t peer_limit, Tox_Events_State *_Nonnull state);
void tox_events_handle_group_password(uint32_t group_number, const uint8_t *_Nullable password, size_t password_length, Tox_Events_State *_Nonnull state);
void tox_events_handle_group_message(uint32_t group_number, uint32_t peer_id, Tox_Message_Type message_type, const uint8_t *_Nonnull message, size_t message_length, uint32_t message_id,
                                     Tox_Events_State *_Nonnull state);
void tox_events_handle_group_private_message(uint32_t group_number, uint32_t peer_id, Tox_Message_Type message_type, const uint8_t *_Nonnull message, size_t message_length, uint32_t message_id,
        Tox_Events_State *_Nonnull state);
void tox_events_handle_group_custom_packet(uint32_t group_number, uint32_t peer_id, const uint8_t *_Nonnull data, size_t data_length, Tox_Events_State *_Nonnull state);
void tox_events_handle_group_custom_private_packet(uint32_t group_number, uint32_t peer_id, const uint8_t *_Nonnull data, size_t data_length, Tox_Events_State *_Nonnull state);
void tox_events_handle_group_invite(uint32_t friend_number, const uint8_t *_Nonnull invite_data, size_t invite_data_length, const uint8_t *_Nonnull group_name, size_t group_name_length,
                                    Tox_Events_State *_Nonnull state);
void tox_events_handle_group_peer_join(uint32_t group_number, uint32_t peer_id, Tox_Events_State *_Nonnull state);
void tox_events_handle_group_peer_exit(uint32_t group_number, uint32_t peer_id, Tox_Group_Exit_Type exit_type, const uint8_t *_Nonnull name, size_t name_length, const uint8_t *_Nullable part_message,
                                       size_t part_message_length, Tox_Events_State *_Nonnull state);
void tox_events_handle_group_self_join(uint32_t group_number, Tox_Events_State *_Nonnull state);
void tox_events_handle_group_join_fail(uint32_t group_number, Tox_Group_Join_Fail fail_type, Tox_Events_State *_Nonnull state);
void tox_events_handle_group_moderation(uint32_t group_number, uint32_t source_peer_id, uint32_t target_peer_id, Tox_Group_Mod_Event mod_type, Tox_Events_State *_Nonnull state);

void tox_events_handle_conference_connected_dispatch(Tox *_Nonnull tox, void *_Nullable user_data, const Tox_Event *_Nonnull event);
void tox_events_handle_conference_invite_dispatch(Tox *_Nonnull tox, void *_Nullable user_data, const Tox_Event *_Nonnull event);
void tox_events_handle_conference_message_dispatch(Tox *_Nonnull tox, void *_Nullable user_data, const Tox_Event *_Nonnull event);
void tox_events_handle_conference_peer_list_changed_dispatch(Tox *_Nonnull tox, void *_Nullable user_data, const Tox_Event *_Nonnull event);
void tox_events_handle_conference_peer_name_dispatch(Tox *_Nonnull tox, void *_Nullable user_data, const Tox_Event *_Nonnull event);
void tox_events_handle_conference_title_dispatch(Tox *_Nonnull tox, void *_Nullable user_data, const Tox_Event *_Nonnull event);
void tox_events_handle_dht_nodes_response_dispatch(Tox *_Nonnull tox, void *_Nullable user_data, const Tox_Event *_Nonnull event);
void tox_events_handle_file_chunk_request_dispatch(Tox *_Nonnull tox, void *_Nullable user_data, const Tox_Event *_Nonnull event);
void tox_events_handle_file_recv_chunk_dispatch(Tox *_Nonnull tox, void *_Nullable user_data, const Tox_Event *_Nonnull event);
void tox_events_handle_file_recv_control_dispatch(Tox *_Nonnull tox, void *_Nullable user_data, const Tox_Event *_Nonnull event);
void tox_events_handle_file_recv_dispatch(Tox *_Nonnull tox, void *_Nullable user_data, const Tox_Event *_Nonnull event);
void tox_events_handle_friend_connection_status_dispatch(Tox *_Nonnull tox, void *_Nullable user_data, const Tox_Event *_Nonnull event);
void tox_events_handle_friend_lossless_packet_dispatch(Tox *_Nonnull tox, void *_Nullable user_data, const Tox_Event *_Nonnull event);
void tox_events_handle_friend_lossy_packet_dispatch(Tox *_Nonnull tox, void *_Nullable user_data, const Tox_Event *_Nonnull event);
void tox_events_handle_friend_message_dispatch(Tox *_Nonnull tox, void *_Nullable user_data, const Tox_Event *_Nonnull event);
void tox_events_handle_friend_name_dispatch(Tox *_Nonnull tox, void *_Nullable user_data, const Tox_Event *_Nonnull event);
void tox_events_handle_friend_read_receipt_dispatch(Tox *_Nonnull tox, void *_Nullable user_data, const Tox_Event *_Nonnull event);
void tox_events_handle_friend_request_dispatch(Tox *_Nonnull tox, void *_Nullable user_data, const Tox_Event *_Nonnull event);
void tox_events_handle_friend_status_dispatch(Tox *_Nonnull tox, void *_Nullable user_data, const Tox_Event *_Nonnull event);
void tox_events_handle_friend_status_message_dispatch(Tox *_Nonnull tox, void *_Nullable user_data, const Tox_Event *_Nonnull event);
void tox_events_handle_friend_typing_dispatch(Tox *_Nonnull tox, void *_Nullable user_data, const Tox_Event *_Nonnull event);
void tox_events_handle_self_connection_status_dispatch(Tox *_Nonnull tox, void *_Nullable user_data, const Tox_Event *_Nonnull event);
void tox_events_handle_group_peer_name_dispatch(Tox *_Nonnull tox, void *_Nullable user_data, const Tox_Event *_Nonnull event);
void tox_events_handle_group_peer_status_dispatch(Tox *_Nonnull tox, void *_Nullable user_data, const Tox_Event *_Nonnull event);
void tox_events_handle_group_topic_dispatch(Tox *_Nonnull tox, void *_Nullable user_data, const Tox_Event *_Nonnull event);
void tox_events_handle_group_privacy_state_dispatch(Tox *_Nonnull tox, void *_Nullable user_data, const Tox_Event *_Nonnull event);
void tox_events_handle_group_voice_state_dispatch(Tox *_Nonnull tox, void *_Nullable user_data, const Tox_Event *_Nonnull event);
void tox_events_handle_group_topic_lock_dispatch(Tox *_Nonnull tox, void *_Nullable user_data, const Tox_Event *_Nonnull event);
void tox_events_handle_group_peer_limit_dispatch(Tox *_Nonnull tox, void *_Nullable user_data, const Tox_Event *_Nonnull event);
void tox_events_handle_group_password_dispatch(Tox *_Nonnull tox, void *_Nullable user_data, const Tox_Event *_Nonnull event);
void tox_events_handle_group_message_dispatch(Tox *_Nonnull tox, void *_Nullable user_data, const Tox_Event *_Nonnull event);
void tox_events_handle_group_private_message_dispatch(Tox *_Nonnull tox, void *_Nullable user_data, const Tox_Event *_Nonnull event);
void tox_events_handle_group_custom_packet_dispatch(Tox *_Nonnull tox, void *_Nullable user_data, const Tox_Event *_Nonnull event);
void tox_events_handle_group_custom_private_packet_dispatch(Tox *_Nonnull tox, void *_Nullable user_data, const Tox_Event *_Nonnull event);
void tox_events_handle_group_invite_dispatch(Tox *_Nonnull tox, void *_Nullable user_data, const Tox_Event *_Nonnull event);
void tox_events_handle_group_peer_join_dispatch(Tox *_Nonnull tox, void *_Nullable user_data, const Tox_Event *_Nonnull event);
void tox_events_handle_group_peer_exit_dispatch(Tox *_Nonnull tox, void *_Nullable user_data, const Tox_Event *_Nonnull event);
void tox_events_handle_group_self_join_dispatch(Tox *_Nonnull tox, void *_Nullable user_data, const Tox_Event *_Nonnull event);
void tox_events_handle_group_join_fail_dispatch(Tox *_Nonnull tox, void *_Nullable user_data, const Tox_Event *_Nonnull event);
void tox_events_handle_group_moderation_dispatch(Tox *_Nonnull tox, void *_Nullable user_data, const Tox_Event *_Nonnull event);

Tox_Events_State *_Nonnull tox_events_alloc(Tox_Events_State *_Nonnull state);

bool tox_events_add(Tox_Events *_Nonnull events, const Tox_Event *_Nonnull event);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* C_TOXCORE_TOXCORE_EVENTS_EVENTS_ALLOC_H */
