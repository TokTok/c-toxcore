/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2022-2025 The TokTok team.
 */

#include "tox_event.h"

#include <assert.h>

#include "attributes.h"
#include "bin_pack.h"
#include "bin_unpack.h"
#include "ccompat.h"
#include "mem.h"
#include "tox_events.h"

const char *tox_event_type_to_string(Tox_Event_Type type)
{
    switch (type) {
        case TOX_EVENT_SELF_CONNECTION_STATUS:
            return "TOX_EVENT_SELF_CONNECTION_STATUS";

        case TOX_EVENT_FRIEND_REQUEST:
            return "TOX_EVENT_FRIEND_REQUEST";

        case TOX_EVENT_FRIEND_CONNECTION_STATUS:
            return "TOX_EVENT_FRIEND_CONNECTION_STATUS";

        case TOX_EVENT_FRIEND_LOSSY_PACKET:
            return "TOX_EVENT_FRIEND_LOSSY_PACKET";

        case TOX_EVENT_FRIEND_LOSSLESS_PACKET:
            return "TOX_EVENT_FRIEND_LOSSLESS_PACKET";

        case TOX_EVENT_FRIEND_NAME:
            return "TOX_EVENT_FRIEND_NAME";

        case TOX_EVENT_FRIEND_STATUS:
            return "TOX_EVENT_FRIEND_STATUS";

        case TOX_EVENT_FRIEND_STATUS_MESSAGE:
            return "TOX_EVENT_FRIEND_STATUS_MESSAGE";

        case TOX_EVENT_FRIEND_MESSAGE:
            return "TOX_EVENT_FRIEND_MESSAGE";

        case TOX_EVENT_FRIEND_READ_RECEIPT:
            return "TOX_EVENT_FRIEND_READ_RECEIPT";

        case TOX_EVENT_FRIEND_TYPING:
            return "TOX_EVENT_FRIEND_TYPING";

        case TOX_EVENT_FILE_CHUNK_REQUEST:
            return "TOX_EVENT_FILE_CHUNK_REQUEST";

        case TOX_EVENT_FILE_RECV:
            return "TOX_EVENT_FILE_RECV";

        case TOX_EVENT_FILE_RECV_CHUNK:
            return "TOX_EVENT_FILE_RECV_CHUNK";

        case TOX_EVENT_FILE_RECV_CONTROL:
            return "TOX_EVENT_FILE_RECV_CONTROL";

        case TOX_EVENT_CONFERENCE_INVITE:
            return "TOX_EVENT_CONFERENCE_INVITE";

        case TOX_EVENT_CONFERENCE_CONNECTED:
            return "TOX_EVENT_CONFERENCE_CONNECTED";

        case TOX_EVENT_CONFERENCE_PEER_LIST_CHANGED:
            return "TOX_EVENT_CONFERENCE_PEER_LIST_CHANGED";

        case TOX_EVENT_CONFERENCE_PEER_NAME:
            return "TOX_EVENT_CONFERENCE_PEER_NAME";

        case TOX_EVENT_CONFERENCE_TITLE:
            return "TOX_EVENT_CONFERENCE_TITLE";

        case TOX_EVENT_CONFERENCE_MESSAGE:
            return "TOX_EVENT_CONFERENCE_MESSAGE";

        case TOX_EVENT_GROUP_PEER_NAME:
            return "TOX_EVENT_GROUP_PEER_NAME";

        case TOX_EVENT_GROUP_PEER_STATUS:
            return "TOX_EVENT_GROUP_PEER_STATUS";

        case TOX_EVENT_GROUP_TOPIC:
            return "TOX_EVENT_GROUP_TOPIC";

        case TOX_EVENT_GROUP_PRIVACY_STATE:
            return "TOX_EVENT_GROUP_PRIVACY_STATE";

        case TOX_EVENT_GROUP_VOICE_STATE:
            return "TOX_EVENT_GROUP_VOICE_STATE";

        case TOX_EVENT_GROUP_TOPIC_LOCK:
            return "TOX_EVENT_GROUP_TOPIC_LOCK";

        case TOX_EVENT_GROUP_PEER_LIMIT:
            return "TOX_EVENT_GROUP_PEER_LIMIT";

        case TOX_EVENT_GROUP_PASSWORD:
            return "TOX_EVENT_GROUP_PASSWORD";

        case TOX_EVENT_GROUP_MESSAGE:
            return "TOX_EVENT_GROUP_MESSAGE";

        case TOX_EVENT_GROUP_PRIVATE_MESSAGE:
            return "TOX_EVENT_GROUP_PRIVATE_MESSAGE";

        case TOX_EVENT_GROUP_CUSTOM_PACKET:
            return "TOX_EVENT_GROUP_CUSTOM_PACKET";

        case TOX_EVENT_GROUP_CUSTOM_PRIVATE_PACKET:
            return "TOX_EVENT_GROUP_CUSTOM_PRIVATE_PACKET";

        case TOX_EVENT_GROUP_INVITE:
            return "TOX_EVENT_GROUP_INVITE";

        case TOX_EVENT_GROUP_PEER_JOIN:
            return "TOX_EVENT_GROUP_PEER_JOIN";

        case TOX_EVENT_GROUP_PEER_EXIT:
            return "TOX_EVENT_GROUP_PEER_EXIT";

        case TOX_EVENT_GROUP_SELF_JOIN:
            return "TOX_EVENT_GROUP_SELF_JOIN";

        case TOX_EVENT_GROUP_JOIN_FAIL:
            return "TOX_EVENT_GROUP_JOIN_FAIL";

        case TOX_EVENT_GROUP_MODERATION:
            return "TOX_EVENT_GROUP_MODERATION";

        case TOX_EVENT_DHT_NODES_RESPONSE:
            return "TOX_EVENT_DHT_NODES_RESPONSE";

        case TOX_EVENT_INVALID:
            return "TOX_EVENT_INVALID";
    }

    return "<invalid Tox_Event_Type>";
}

Tox_Event_Type tox_event_get_type(const Tox_Event *event)
{
    return event->type;
}

void tox_event_destruct(Tox_Event *event, const Memory *mem)
{
    if (event == nullptr) {
        return;
    }

    switch (event->type) {
        case TOX_EVENT_CONFERENCE_CONNECTED: {
            tox_event_conference_connected_free(event->data.conference_connected, mem);
            break;
        }

        case TOX_EVENT_CONFERENCE_INVITE: {
            tox_event_conference_invite_free(event->data.conference_invite, mem);
            break;
        }

        case TOX_EVENT_CONFERENCE_MESSAGE: {
            tox_event_conference_message_free(event->data.conference_message, mem);
            break;
        }

        case TOX_EVENT_CONFERENCE_PEER_LIST_CHANGED: {
            tox_event_conference_peer_list_changed_free(event->data.conference_peer_list_changed, mem);
            break;
        }

        case TOX_EVENT_CONFERENCE_PEER_NAME: {
            tox_event_conference_peer_name_free(event->data.conference_peer_name, mem);
            break;
        }

        case TOX_EVENT_CONFERENCE_TITLE: {
            tox_event_conference_title_free(event->data.conference_title, mem);
            break;
        }

        case TOX_EVENT_FILE_CHUNK_REQUEST: {
            tox_event_file_chunk_request_free(event->data.file_chunk_request, mem);
            break;
        }

        case TOX_EVENT_FILE_RECV_CHUNK: {
            tox_event_file_recv_chunk_free(event->data.file_recv_chunk, mem);
            break;
        }

        case TOX_EVENT_FILE_RECV_CONTROL: {
            tox_event_file_recv_control_free(event->data.file_recv_control, mem);
            break;
        }

        case TOX_EVENT_FILE_RECV: {
            tox_event_file_recv_free(event->data.file_recv, mem);
            break;
        }

        case TOX_EVENT_FRIEND_CONNECTION_STATUS: {
            tox_event_friend_connection_status_free(event->data.friend_connection_status, mem);
            break;
        }

        case TOX_EVENT_FRIEND_LOSSLESS_PACKET: {
            tox_event_friend_lossless_packet_free(event->data.friend_lossless_packet, mem);
            break;
        }

        case TOX_EVENT_FRIEND_LOSSY_PACKET: {
            tox_event_friend_lossy_packet_free(event->data.friend_lossy_packet, mem);
            break;
        }

        case TOX_EVENT_FRIEND_MESSAGE: {
            tox_event_friend_message_free(event->data.friend_message, mem);
            break;
        }

        case TOX_EVENT_FRIEND_NAME: {
            tox_event_friend_name_free(event->data.friend_name, mem);
            break;
        }

        case TOX_EVENT_FRIEND_READ_RECEIPT: {
            tox_event_friend_read_receipt_free(event->data.friend_read_receipt, mem);
            break;
        }

        case TOX_EVENT_FRIEND_REQUEST: {
            tox_event_friend_request_free(event->data.friend_request, mem);
            break;
        }

        case TOX_EVENT_FRIEND_STATUS: {
            tox_event_friend_status_free(event->data.friend_status, mem);
            break;
        }

        case TOX_EVENT_FRIEND_STATUS_MESSAGE: {
            tox_event_friend_status_message_free(event->data.friend_status_message, mem);
            break;
        }

        case TOX_EVENT_FRIEND_TYPING: {
            tox_event_friend_typing_free(event->data.friend_typing, mem);
            break;
        }

        case TOX_EVENT_SELF_CONNECTION_STATUS: {
            tox_event_self_connection_status_free(event->data.self_connection_status, mem);
            break;
        }

        case TOX_EVENT_GROUP_PEER_NAME: {
            tox_event_group_peer_name_free(event->data.group_peer_name, mem);
            break;
        }

        case TOX_EVENT_GROUP_PEER_STATUS: {
            tox_event_group_peer_status_free(event->data.group_peer_status, mem);
            break;
        }

        case TOX_EVENT_GROUP_TOPIC: {
            tox_event_group_topic_free(event->data.group_topic, mem);
            break;
        }

        case TOX_EVENT_GROUP_PRIVACY_STATE: {
            tox_event_group_privacy_state_free(event->data.group_privacy_state, mem);
            break;
        }

        case TOX_EVENT_GROUP_VOICE_STATE: {
            tox_event_group_voice_state_free(event->data.group_voice_state, mem);
            break;
        }

        case TOX_EVENT_GROUP_TOPIC_LOCK: {
            tox_event_group_topic_lock_free(event->data.group_topic_lock, mem);
            break;
        }

        case TOX_EVENT_GROUP_PEER_LIMIT: {
            tox_event_group_peer_limit_free(event->data.group_peer_limit, mem);
            break;
        }

        case TOX_EVENT_GROUP_PASSWORD: {
            tox_event_group_password_free(event->data.group_password, mem);
            break;
        }

        case TOX_EVENT_GROUP_MESSAGE: {
            tox_event_group_message_free(event->data.group_message, mem);
            break;
        }

        case TOX_EVENT_GROUP_PRIVATE_MESSAGE: {
            tox_event_group_private_message_free(event->data.group_private_message, mem);
            break;
        }

        case TOX_EVENT_GROUP_CUSTOM_PACKET: {
            tox_event_group_custom_packet_free(event->data.group_custom_packet, mem);
            break;
        }

        case TOX_EVENT_GROUP_CUSTOM_PRIVATE_PACKET: {
            tox_event_group_custom_private_packet_free(event->data.group_custom_private_packet, mem);
            break;
        }

        case TOX_EVENT_GROUP_INVITE: {
            tox_event_group_invite_free(event->data.group_invite, mem);
            break;
        }

        case TOX_EVENT_GROUP_PEER_JOIN: {
            tox_event_group_peer_join_free(event->data.group_peer_join, mem);
            break;
        }

        case TOX_EVENT_GROUP_PEER_EXIT: {
            tox_event_group_peer_exit_free(event->data.group_peer_exit, mem);
            break;
        }

        case TOX_EVENT_GROUP_SELF_JOIN: {
            tox_event_group_self_join_free(event->data.group_self_join, mem);
            break;
        }

        case TOX_EVENT_GROUP_JOIN_FAIL: {
            tox_event_group_join_fail_free(event->data.group_join_fail, mem);
            break;
        }

        case TOX_EVENT_GROUP_MODERATION: {
            tox_event_group_moderation_free(event->data.group_moderation, mem);
            break;
        }

        case TOX_EVENT_DHT_NODES_RESPONSE: {
            tox_event_dht_nodes_response_free(event->data.dht_nodes_response, mem);
            break;
        }

        case TOX_EVENT_INVALID: {
            break;
        }
    }
}

bool tox_event_pack(const Tox_Event *event, Bin_Pack *bp)
{
    if (!bin_pack_array(bp, 2)) {
        return false;
    }

    switch (event->type) {
        case TOX_EVENT_CONFERENCE_CONNECTED:
            return bin_pack_u32(bp, (uint32_t)TOX_EVENT_CONFERENCE_CONNECTED)
                   && tox_event_conference_connected_pack(event->data.conference_connected, bp);

        case TOX_EVENT_CONFERENCE_INVITE:
            return bin_pack_u32(bp, (uint32_t)TOX_EVENT_CONFERENCE_INVITE)
                   && tox_event_conference_invite_pack(event->data.conference_invite, bp);

        case TOX_EVENT_CONFERENCE_MESSAGE:
            return bin_pack_u32(bp, (uint32_t)TOX_EVENT_CONFERENCE_MESSAGE)
                   && tox_event_conference_message_pack(event->data.conference_message, bp);

        case TOX_EVENT_CONFERENCE_PEER_LIST_CHANGED:
            return bin_pack_u32(bp, (uint32_t)TOX_EVENT_CONFERENCE_PEER_LIST_CHANGED)
                   && tox_event_conference_peer_list_changed_pack(event->data.conference_peer_list_changed, bp);

        case TOX_EVENT_CONFERENCE_PEER_NAME:
            return bin_pack_u32(bp, (uint32_t)TOX_EVENT_CONFERENCE_PEER_NAME)
                   && tox_event_conference_peer_name_pack(event->data.conference_peer_name, bp);

        case TOX_EVENT_CONFERENCE_TITLE:
            return bin_pack_u32(bp, (uint32_t)TOX_EVENT_CONFERENCE_TITLE)
                   && tox_event_conference_title_pack(event->data.conference_title, bp);

        case TOX_EVENT_FILE_CHUNK_REQUEST:
            return bin_pack_u32(bp, (uint32_t)TOX_EVENT_FILE_CHUNK_REQUEST)
                   && tox_event_file_chunk_request_pack(event->data.file_chunk_request, bp);

        case TOX_EVENT_FILE_RECV_CHUNK:
            return bin_pack_u32(bp, (uint32_t)TOX_EVENT_FILE_RECV_CHUNK)
                   && tox_event_file_recv_chunk_pack(event->data.file_recv_chunk, bp);

        case TOX_EVENT_FILE_RECV_CONTROL:
            return bin_pack_u32(bp, (uint32_t)TOX_EVENT_FILE_RECV_CONTROL)
                   && tox_event_file_recv_control_pack(event->data.file_recv_control, bp);

        case TOX_EVENT_FILE_RECV:
            return bin_pack_u32(bp, (uint32_t)TOX_EVENT_FILE_RECV)
                   && tox_event_file_recv_pack(event->data.file_recv, bp);

        case TOX_EVENT_FRIEND_CONNECTION_STATUS:
            return bin_pack_u32(bp, (uint32_t)TOX_EVENT_FRIEND_CONNECTION_STATUS)
                   && tox_event_friend_connection_status_pack(event->data.friend_connection_status, bp);

        case TOX_EVENT_FRIEND_LOSSLESS_PACKET:
            return bin_pack_u32(bp, (uint32_t)TOX_EVENT_FRIEND_LOSSLESS_PACKET)
                   && tox_event_friend_lossless_packet_pack(event->data.friend_lossless_packet, bp);

        case TOX_EVENT_FRIEND_LOSSY_PACKET:
            return bin_pack_u32(bp, (uint32_t)TOX_EVENT_FRIEND_LOSSY_PACKET)
                   && tox_event_friend_lossy_packet_pack(event->data.friend_lossy_packet, bp);

        case TOX_EVENT_FRIEND_MESSAGE:
            return bin_pack_u32(bp, (uint32_t)TOX_EVENT_FRIEND_MESSAGE)
                   && tox_event_friend_message_pack(event->data.friend_message, bp);

        case TOX_EVENT_FRIEND_NAME:
            return bin_pack_u32(bp, (uint32_t)TOX_EVENT_FRIEND_NAME)
                   && tox_event_friend_name_pack(event->data.friend_name, bp);

        case TOX_EVENT_FRIEND_READ_RECEIPT:
            return bin_pack_u32(bp, (uint32_t)TOX_EVENT_FRIEND_READ_RECEIPT)
                   && tox_event_friend_read_receipt_pack(event->data.friend_read_receipt, bp);

        case TOX_EVENT_FRIEND_REQUEST:
            return bin_pack_u32(bp, (uint32_t)TOX_EVENT_FRIEND_REQUEST)
                   && tox_event_friend_request_pack(event->data.friend_request, bp);

        case TOX_EVENT_FRIEND_STATUS:
            return bin_pack_u32(bp, (uint32_t)TOX_EVENT_FRIEND_STATUS)
                   && tox_event_friend_status_pack(event->data.friend_status, bp);

        case TOX_EVENT_FRIEND_STATUS_MESSAGE:
            return bin_pack_u32(bp, (uint32_t)TOX_EVENT_FRIEND_STATUS_MESSAGE)
                   && tox_event_friend_status_message_pack(event->data.friend_status_message, bp);

        case TOX_EVENT_FRIEND_TYPING:
            return bin_pack_u32(bp, (uint32_t)TOX_EVENT_FRIEND_TYPING)
                   && tox_event_friend_typing_pack(event->data.friend_typing, bp);

        case TOX_EVENT_SELF_CONNECTION_STATUS:
            return bin_pack_u32(bp, (uint32_t)TOX_EVENT_SELF_CONNECTION_STATUS)
                   && tox_event_self_connection_status_pack(event->data.self_connection_status, bp);

        case TOX_EVENT_GROUP_PEER_NAME:
            return bin_pack_u32(bp, (uint32_t)TOX_EVENT_GROUP_PEER_NAME)
                   && tox_event_group_peer_name_pack(event->data.group_peer_name, bp);

        case TOX_EVENT_GROUP_PEER_STATUS:
            return bin_pack_u32(bp, (uint32_t)TOX_EVENT_GROUP_PEER_STATUS)
                   && tox_event_group_peer_status_pack(event->data.group_peer_status, bp);

        case TOX_EVENT_GROUP_TOPIC:
            return bin_pack_u32(bp, (uint32_t)TOX_EVENT_GROUP_TOPIC)
                   && tox_event_group_topic_pack(event->data.group_topic, bp);

        case TOX_EVENT_GROUP_PRIVACY_STATE:
            return bin_pack_u32(bp, (uint32_t)TOX_EVENT_GROUP_PRIVACY_STATE)
                   && tox_event_group_privacy_state_pack(event->data.group_privacy_state, bp);

        case TOX_EVENT_GROUP_VOICE_STATE:
            return bin_pack_u32(bp, (uint32_t)TOX_EVENT_GROUP_VOICE_STATE)
                   && tox_event_group_voice_state_pack(event->data.group_voice_state, bp);

        case TOX_EVENT_GROUP_TOPIC_LOCK:
            return bin_pack_u32(bp, (uint32_t)TOX_EVENT_GROUP_TOPIC_LOCK)
                   && tox_event_group_topic_lock_pack(event->data.group_topic_lock, bp);

        case TOX_EVENT_GROUP_PEER_LIMIT:
            return bin_pack_u32(bp, (uint32_t)TOX_EVENT_GROUP_PEER_LIMIT)
                   && tox_event_group_peer_limit_pack(event->data.group_peer_limit, bp);

        case TOX_EVENT_GROUP_PASSWORD:
            return bin_pack_u32(bp, (uint32_t)TOX_EVENT_GROUP_PASSWORD)
                   && tox_event_group_password_pack(event->data.group_password, bp);

        case TOX_EVENT_GROUP_MESSAGE:
            return bin_pack_u32(bp, (uint32_t)TOX_EVENT_GROUP_MESSAGE)
                   && tox_event_group_message_pack(event->data.group_message, bp);

        case TOX_EVENT_GROUP_PRIVATE_MESSAGE:
            return bin_pack_u32(bp, (uint32_t)TOX_EVENT_GROUP_PRIVATE_MESSAGE)
                   && tox_event_group_private_message_pack(event->data.group_private_message, bp);

        case TOX_EVENT_GROUP_CUSTOM_PACKET:
            return bin_pack_u32(bp, (uint32_t)TOX_EVENT_GROUP_CUSTOM_PACKET)
                   && tox_event_group_custom_packet_pack(event->data.group_custom_packet, bp);

        case TOX_EVENT_GROUP_CUSTOM_PRIVATE_PACKET:
            return bin_pack_u32(bp, (uint32_t)TOX_EVENT_GROUP_CUSTOM_PRIVATE_PACKET)
                   && tox_event_group_custom_private_packet_pack(event->data.group_custom_private_packet, bp);

        case TOX_EVENT_GROUP_INVITE:
            return bin_pack_u32(bp, (uint32_t)TOX_EVENT_GROUP_INVITE)
                   && tox_event_group_invite_pack(event->data.group_invite, bp);

        case TOX_EVENT_GROUP_PEER_JOIN:
            return bin_pack_u32(bp, (uint32_t)TOX_EVENT_GROUP_PEER_JOIN)
                   && tox_event_group_peer_join_pack(event->data.group_peer_join, bp);

        case TOX_EVENT_GROUP_PEER_EXIT:
            return bin_pack_u32(bp, (uint32_t)TOX_EVENT_GROUP_PEER_EXIT)
                   && tox_event_group_peer_exit_pack(event->data.group_peer_exit, bp);

        case TOX_EVENT_GROUP_SELF_JOIN:
            return bin_pack_u32(bp, (uint32_t)TOX_EVENT_GROUP_SELF_JOIN)
                   && tox_event_group_self_join_pack(event->data.group_self_join, bp);

        case TOX_EVENT_GROUP_JOIN_FAIL:
            return bin_pack_u32(bp, (uint32_t)TOX_EVENT_GROUP_JOIN_FAIL)
                   && tox_event_group_join_fail_pack(event->data.group_join_fail, bp);

        case TOX_EVENT_GROUP_MODERATION:
            return bin_pack_u32(bp, (uint32_t)TOX_EVENT_GROUP_MODERATION)
                   && tox_event_group_moderation_pack(event->data.group_moderation, bp);

        case TOX_EVENT_DHT_NODES_RESPONSE:
            return bin_pack_u32(bp, (uint32_t)TOX_EVENT_DHT_NODES_RESPONSE)
                   && tox_event_dht_nodes_response_pack(event->data.dht_nodes_response, bp);

        case TOX_EVENT_INVALID:
            return false;
    }

    return false;
}

static bool tox_event_type_from_int(uint32_t value, Tox_Event_Type *_Nonnull out_enum)
{
    switch (value) {
        case TOX_EVENT_SELF_CONNECTION_STATUS: {
            *out_enum = TOX_EVENT_SELF_CONNECTION_STATUS;
            return true;
        }

        case TOX_EVENT_FRIEND_REQUEST: {
            *out_enum = TOX_EVENT_FRIEND_REQUEST;
            return true;
        }

        case TOX_EVENT_FRIEND_CONNECTION_STATUS: {
            *out_enum = TOX_EVENT_FRIEND_CONNECTION_STATUS;
            return true;
        }

        case TOX_EVENT_FRIEND_LOSSY_PACKET: {
            *out_enum = TOX_EVENT_FRIEND_LOSSY_PACKET;
            return true;
        }

        case TOX_EVENT_FRIEND_LOSSLESS_PACKET: {
            *out_enum = TOX_EVENT_FRIEND_LOSSLESS_PACKET;
            return true;
        }

        case TOX_EVENT_FRIEND_NAME: {
            *out_enum = TOX_EVENT_FRIEND_NAME;
            return true;
        }

        case TOX_EVENT_FRIEND_STATUS: {
            *out_enum = TOX_EVENT_FRIEND_STATUS;
            return true;
        }

        case TOX_EVENT_FRIEND_STATUS_MESSAGE: {
            *out_enum = TOX_EVENT_FRIEND_STATUS_MESSAGE;
            return true;
        }

        case TOX_EVENT_FRIEND_MESSAGE: {
            *out_enum = TOX_EVENT_FRIEND_MESSAGE;
            return true;
        }

        case TOX_EVENT_FRIEND_READ_RECEIPT: {
            *out_enum = TOX_EVENT_FRIEND_READ_RECEIPT;
            return true;
        }

        case TOX_EVENT_FRIEND_TYPING: {
            *out_enum = TOX_EVENT_FRIEND_TYPING;
            return true;
        }

        case TOX_EVENT_FILE_CHUNK_REQUEST: {
            *out_enum = TOX_EVENT_FILE_CHUNK_REQUEST;
            return true;
        }

        case TOX_EVENT_FILE_RECV: {
            *out_enum = TOX_EVENT_FILE_RECV;
            return true;
        }

        case TOX_EVENT_FILE_RECV_CHUNK: {
            *out_enum = TOX_EVENT_FILE_RECV_CHUNK;
            return true;
        }

        case TOX_EVENT_FILE_RECV_CONTROL: {
            *out_enum = TOX_EVENT_FILE_RECV_CONTROL;
            return true;
        }

        case TOX_EVENT_CONFERENCE_INVITE: {
            *out_enum = TOX_EVENT_CONFERENCE_INVITE;
            return true;
        }

        case TOX_EVENT_CONFERENCE_CONNECTED: {
            *out_enum = TOX_EVENT_CONFERENCE_CONNECTED;
            return true;
        }

        case TOX_EVENT_CONFERENCE_PEER_LIST_CHANGED: {
            *out_enum = TOX_EVENT_CONFERENCE_PEER_LIST_CHANGED;
            return true;
        }

        case TOX_EVENT_CONFERENCE_PEER_NAME: {
            *out_enum = TOX_EVENT_CONFERENCE_PEER_NAME;
            return true;
        }

        case TOX_EVENT_CONFERENCE_TITLE: {
            *out_enum = TOX_EVENT_CONFERENCE_TITLE;
            return true;
        }

        case TOX_EVENT_CONFERENCE_MESSAGE: {
            *out_enum = TOX_EVENT_CONFERENCE_MESSAGE;
            return true;
        }

        case TOX_EVENT_GROUP_PEER_NAME: {
            *out_enum = TOX_EVENT_GROUP_PEER_NAME;
            return true;
        }

        case TOX_EVENT_GROUP_PEER_STATUS: {
            *out_enum = TOX_EVENT_GROUP_PEER_STATUS;
            return true;
        }

        case TOX_EVENT_GROUP_TOPIC: {
            *out_enum = TOX_EVENT_GROUP_TOPIC;
            return true;
        }

        case TOX_EVENT_GROUP_PRIVACY_STATE: {
            *out_enum = TOX_EVENT_GROUP_PRIVACY_STATE;
            return true;
        }

        case TOX_EVENT_GROUP_VOICE_STATE: {
            *out_enum = TOX_EVENT_GROUP_VOICE_STATE;
            return true;
        }

        case TOX_EVENT_GROUP_TOPIC_LOCK: {
            *out_enum = TOX_EVENT_GROUP_TOPIC_LOCK;
            return true;
        }

        case TOX_EVENT_GROUP_PEER_LIMIT: {
            *out_enum = TOX_EVENT_GROUP_PEER_LIMIT;
            return true;
        }

        case TOX_EVENT_GROUP_PASSWORD: {
            *out_enum = TOX_EVENT_GROUP_PASSWORD;
            return true;
        }

        case TOX_EVENT_GROUP_MESSAGE: {
            *out_enum = TOX_EVENT_GROUP_MESSAGE;
            return true;
        }

        case TOX_EVENT_GROUP_PRIVATE_MESSAGE: {
            *out_enum = TOX_EVENT_GROUP_PRIVATE_MESSAGE;
            return true;
        }

        case TOX_EVENT_GROUP_CUSTOM_PACKET: {
            *out_enum = TOX_EVENT_GROUP_CUSTOM_PACKET;
            return true;
        }

        case TOX_EVENT_GROUP_CUSTOM_PRIVATE_PACKET: {
            *out_enum = TOX_EVENT_GROUP_CUSTOM_PRIVATE_PACKET;
            return true;
        }

        case TOX_EVENT_GROUP_INVITE: {
            *out_enum = TOX_EVENT_GROUP_INVITE;
            return true;
        }

        case TOX_EVENT_GROUP_PEER_JOIN: {
            *out_enum = TOX_EVENT_GROUP_PEER_JOIN;
            return true;
        }

        case TOX_EVENT_GROUP_PEER_EXIT: {
            *out_enum = TOX_EVENT_GROUP_PEER_EXIT;
            return true;
        }

        case TOX_EVENT_GROUP_SELF_JOIN: {
            *out_enum = TOX_EVENT_GROUP_SELF_JOIN;
            return true;
        }

        case TOX_EVENT_GROUP_JOIN_FAIL: {
            *out_enum = TOX_EVENT_GROUP_JOIN_FAIL;
            return true;
        }

        case TOX_EVENT_GROUP_MODERATION: {
            *out_enum = TOX_EVENT_GROUP_MODERATION;
            return true;
        }

        case TOX_EVENT_DHT_NODES_RESPONSE: {
            *out_enum = TOX_EVENT_DHT_NODES_RESPONSE;
            return true;
        }

        case TOX_EVENT_INVALID: {
            *out_enum = TOX_EVENT_INVALID;
            return true;
        }

        default: {
            *out_enum = TOX_EVENT_INVALID;
            return false;
        }
    }
}

bool tox_event_unpack_into(Tox_Event *event, Bin_Unpack *bu, const Memory *mem)
{
    uint32_t type_u32;

    if (!bin_unpack_array_fixed(bu, 2, nullptr) || !bin_unpack_u32(bu, &type_u32)) {
        return false;
    }

    Tox_Event_Type type;

    if (!tox_event_type_from_int(type_u32, &type)) {
        return false;
    }

    switch (type) {
        case TOX_EVENT_CONFERENCE_CONNECTED: {
            Tox_Event_Conference_Connected *conference_connected = nullptr;

            if (tox_event_conference_connected_unpack(&conference_connected, bu, mem)) {
                event->type = TOX_EVENT_CONFERENCE_CONNECTED;
                event->data.conference_connected = conference_connected;
                return true;
            }

            return false;
        }

        case TOX_EVENT_CONFERENCE_INVITE: {
            Tox_Event_Conference_Invite *conference_invite = nullptr;

            if (tox_event_conference_invite_unpack(&conference_invite, bu, mem)) {
                event->type = TOX_EVENT_CONFERENCE_INVITE;
                event->data.conference_invite = conference_invite;
                return true;
            }

            return false;
        }

        case TOX_EVENT_CONFERENCE_MESSAGE: {
            Tox_Event_Conference_Message *conference_message = nullptr;

            if (tox_event_conference_message_unpack(&conference_message, bu, mem)) {
                event->type = TOX_EVENT_CONFERENCE_MESSAGE;
                event->data.conference_message = conference_message;
                return true;
            }

            return false;
        }

        case TOX_EVENT_CONFERENCE_PEER_LIST_CHANGED: {
            Tox_Event_Conference_Peer_List_Changed *conference_peer_list_changed = nullptr;

            if (tox_event_conference_peer_list_changed_unpack(&conference_peer_list_changed, bu, mem)) {
                event->type = TOX_EVENT_CONFERENCE_PEER_LIST_CHANGED;
                event->data.conference_peer_list_changed = conference_peer_list_changed;
                return true;
            }

            return false;
        }

        case TOX_EVENT_CONFERENCE_PEER_NAME: {
            Tox_Event_Conference_Peer_Name *conference_peer_name = nullptr;

            if (tox_event_conference_peer_name_unpack(&conference_peer_name, bu, mem)) {
                event->type = TOX_EVENT_CONFERENCE_PEER_NAME;
                event->data.conference_peer_name = conference_peer_name;
                return true;
            }

            return false;
        }

        case TOX_EVENT_CONFERENCE_TITLE: {
            Tox_Event_Conference_Title *conference_title = nullptr;

            if (tox_event_conference_title_unpack(&conference_title, bu, mem)) {
                event->type = TOX_EVENT_CONFERENCE_TITLE;
                event->data.conference_title = conference_title;
                return true;
            }

            return false;
        }

        case TOX_EVENT_FILE_CHUNK_REQUEST: {
            Tox_Event_File_Chunk_Request *file_chunk_request = nullptr;

            if (tox_event_file_chunk_request_unpack(&file_chunk_request, bu, mem)) {
                event->type = TOX_EVENT_FILE_CHUNK_REQUEST;
                event->data.file_chunk_request = file_chunk_request;
                return true;
            }

            return false;
        }

        case TOX_EVENT_FILE_RECV_CHUNK: {
            Tox_Event_File_Recv_Chunk *file_recv_chunk = nullptr;

            if (tox_event_file_recv_chunk_unpack(&file_recv_chunk, bu, mem)) {
                event->type = TOX_EVENT_FILE_RECV_CHUNK;
                event->data.file_recv_chunk = file_recv_chunk;
                return true;
            }

            return false;
        }

        case TOX_EVENT_FILE_RECV_CONTROL: {
            Tox_Event_File_Recv_Control *file_recv_control = nullptr;

            if (tox_event_file_recv_control_unpack(&file_recv_control, bu, mem)) {
                event->type = TOX_EVENT_FILE_RECV_CONTROL;
                event->data.file_recv_control = file_recv_control;
                return true;
            }

            return false;
        }

        case TOX_EVENT_FILE_RECV: {
            Tox_Event_File_Recv *file_recv = nullptr;

            if (tox_event_file_recv_unpack(&file_recv, bu, mem)) {
                event->type = TOX_EVENT_FILE_RECV;
                event->data.file_recv = file_recv;
                return true;
            }

            return false;
        }

        case TOX_EVENT_FRIEND_CONNECTION_STATUS: {
            Tox_Event_Friend_Connection_Status *friend_connection_status = nullptr;

            if (tox_event_friend_connection_status_unpack(&friend_connection_status, bu, mem)) {
                event->type = TOX_EVENT_FRIEND_CONNECTION_STATUS;
                event->data.friend_connection_status = friend_connection_status;
                return true;
            }

            return false;
        }

        case TOX_EVENT_FRIEND_LOSSLESS_PACKET: {
            Tox_Event_Friend_Lossless_Packet *friend_lossless_packet = nullptr;

            if (tox_event_friend_lossless_packet_unpack(&friend_lossless_packet, bu, mem)) {
                event->type = TOX_EVENT_FRIEND_LOSSLESS_PACKET;
                event->data.friend_lossless_packet = friend_lossless_packet;
                return true;
            }

            return false;
        }

        case TOX_EVENT_FRIEND_LOSSY_PACKET: {
            Tox_Event_Friend_Lossy_Packet *friend_lossy_packet = nullptr;

            if (tox_event_friend_lossy_packet_unpack(&friend_lossy_packet, bu, mem)) {
                event->type = TOX_EVENT_FRIEND_LOSSY_PACKET;
                event->data.friend_lossy_packet = friend_lossy_packet;
                return true;
            }

            return false;
        }

        case TOX_EVENT_FRIEND_MESSAGE: {
            Tox_Event_Friend_Message *friend_message = nullptr;

            if (tox_event_friend_message_unpack(&friend_message, bu, mem)) {
                event->type = TOX_EVENT_FRIEND_MESSAGE;
                event->data.friend_message = friend_message;
                return true;
            }

            return false;
        }

        case TOX_EVENT_FRIEND_NAME: {
            Tox_Event_Friend_Name *friend_name = nullptr;

            if (tox_event_friend_name_unpack(&friend_name, bu, mem)) {
                event->type = TOX_EVENT_FRIEND_NAME;
                event->data.friend_name = friend_name;
                return true;
            }

            return false;
        }

        case TOX_EVENT_FRIEND_READ_RECEIPT: {
            Tox_Event_Friend_Read_Receipt *friend_read_receipt = nullptr;

            if (tox_event_friend_read_receipt_unpack(&friend_read_receipt, bu, mem)) {
                event->type = TOX_EVENT_FRIEND_READ_RECEIPT;
                event->data.friend_read_receipt = friend_read_receipt;
                return true;
            }

            return false;
        }

        case TOX_EVENT_FRIEND_REQUEST: {
            Tox_Event_Friend_Request *friend_request = nullptr;

            if (tox_event_friend_request_unpack(&friend_request, bu, mem)) {
                event->type = TOX_EVENT_FRIEND_REQUEST;
                event->data.friend_request = friend_request;
                return true;
            }

            return false;
        }

        case TOX_EVENT_FRIEND_STATUS: {
            Tox_Event_Friend_Status *friend_status = nullptr;

            if (tox_event_friend_status_unpack(&friend_status, bu, mem)) {
                event->type = TOX_EVENT_FRIEND_STATUS;
                event->data.friend_status = friend_status;
                return true;
            }

            return false;
        }

        case TOX_EVENT_FRIEND_STATUS_MESSAGE: {
            Tox_Event_Friend_Status_Message *friend_status_message = nullptr;

            if (tox_event_friend_status_message_unpack(&friend_status_message, bu, mem)) {
                event->type = TOX_EVENT_FRIEND_STATUS_MESSAGE;
                event->data.friend_status_message = friend_status_message;
                return true;
            }

            return false;
        }

        case TOX_EVENT_FRIEND_TYPING: {
            Tox_Event_Friend_Typing *friend_typing = nullptr;

            if (tox_event_friend_typing_unpack(&friend_typing, bu, mem)) {
                event->type = TOX_EVENT_FRIEND_TYPING;
                event->data.friend_typing = friend_typing;
                return true;
            }

            return false;
        }

        case TOX_EVENT_SELF_CONNECTION_STATUS: {
            Tox_Event_Self_Connection_Status *self_connection_status = nullptr;

            if (tox_event_self_connection_status_unpack(&self_connection_status, bu, mem)) {
                event->type = TOX_EVENT_SELF_CONNECTION_STATUS;
                event->data.self_connection_status = self_connection_status;
                return true;
            }

            return false;
        }

        case TOX_EVENT_GROUP_PEER_NAME: {
            Tox_Event_Group_Peer_Name *group_peer_name = nullptr;

            if (tox_event_group_peer_name_unpack(&group_peer_name, bu, mem)) {
                event->type = TOX_EVENT_GROUP_PEER_NAME;
                event->data.group_peer_name = group_peer_name;
                return true;
            }

            return false;
        }

        case TOX_EVENT_GROUP_PEER_STATUS: {
            Tox_Event_Group_Peer_Status *group_peer_status = nullptr;

            if (tox_event_group_peer_status_unpack(&group_peer_status, bu, mem)) {
                event->type = TOX_EVENT_GROUP_PEER_STATUS;
                event->data.group_peer_status = group_peer_status;
                return true;
            }

            return false;
        }

        case TOX_EVENT_GROUP_TOPIC: {
            Tox_Event_Group_Topic *group_topic = nullptr;

            if (tox_event_group_topic_unpack(&group_topic, bu, mem)) {
                event->type = TOX_EVENT_GROUP_TOPIC;
                event->data.group_topic = group_topic;
                return true;
            }

            return false;
        }

        case TOX_EVENT_GROUP_PRIVACY_STATE: {
            Tox_Event_Group_Privacy_State *group_privacy_state = nullptr;

            if (tox_event_group_privacy_state_unpack(&group_privacy_state, bu, mem)) {
                event->type = TOX_EVENT_GROUP_PRIVACY_STATE;
                event->data.group_privacy_state = group_privacy_state;
                return true;
            }

            return false;
        }

        case TOX_EVENT_GROUP_VOICE_STATE: {
            Tox_Event_Group_Voice_State *group_voice_state = nullptr;

            if (tox_event_group_voice_state_unpack(&group_voice_state, bu, mem)) {
                event->type = TOX_EVENT_GROUP_VOICE_STATE;
                event->data.group_voice_state = group_voice_state;
                return true;
            }

            return false;
        }

        case TOX_EVENT_GROUP_TOPIC_LOCK: {
            Tox_Event_Group_Topic_Lock *group_topic_lock = nullptr;

            if (tox_event_group_topic_lock_unpack(&group_topic_lock, bu, mem)) {
                event->type = TOX_EVENT_GROUP_TOPIC_LOCK;
                event->data.group_topic_lock = group_topic_lock;
                return true;
            }

            return false;
        }

        case TOX_EVENT_GROUP_PEER_LIMIT: {
            Tox_Event_Group_Peer_Limit *group_peer_limit = nullptr;

            if (tox_event_group_peer_limit_unpack(&group_peer_limit, bu, mem)) {
                event->type = TOX_EVENT_GROUP_PEER_LIMIT;
                event->data.group_peer_limit = group_peer_limit;
                return true;
            }

            return false;
        }

        case TOX_EVENT_GROUP_PASSWORD: {
            Tox_Event_Group_Password *group_password = nullptr;

            if (tox_event_group_password_unpack(&group_password, bu, mem)) {
                event->type = TOX_EVENT_GROUP_PASSWORD;
                event->data.group_password = group_password;
                return true;
            }

            return false;
        }

        case TOX_EVENT_GROUP_MESSAGE: {
            Tox_Event_Group_Message *group_message = nullptr;

            if (tox_event_group_message_unpack(&group_message, bu, mem)) {
                event->type = TOX_EVENT_GROUP_MESSAGE;
                event->data.group_message = group_message;
                return true;
            }

            return false;
        }

        case TOX_EVENT_GROUP_PRIVATE_MESSAGE: {
            Tox_Event_Group_Private_Message *group_private_message = nullptr;

            if (tox_event_group_private_message_unpack(&group_private_message, bu, mem)) {
                event->type = TOX_EVENT_GROUP_PRIVATE_MESSAGE;
                event->data.group_private_message = group_private_message;
                return true;
            }

            return false;
        }

        case TOX_EVENT_GROUP_CUSTOM_PACKET: {
            Tox_Event_Group_Custom_Packet *group_custom_packet = nullptr;

            if (tox_event_group_custom_packet_unpack(&group_custom_packet, bu, mem)) {
                event->type = TOX_EVENT_GROUP_CUSTOM_PACKET;
                event->data.group_custom_packet = group_custom_packet;
                return true;
            }

            return false;
        }

        case TOX_EVENT_GROUP_CUSTOM_PRIVATE_PACKET: {
            Tox_Event_Group_Custom_Private_Packet *group_custom_private_packet = nullptr;

            if (tox_event_group_custom_private_packet_unpack(&group_custom_private_packet, bu, mem)) {
                event->type = TOX_EVENT_GROUP_CUSTOM_PRIVATE_PACKET;
                event->data.group_custom_private_packet = group_custom_private_packet;
                return true;
            }

            return false;
        }

        case TOX_EVENT_GROUP_INVITE: {
            Tox_Event_Group_Invite *group_invite = nullptr;

            if (tox_event_group_invite_unpack(&group_invite, bu, mem)) {
                event->type = TOX_EVENT_GROUP_INVITE;
                event->data.group_invite = group_invite;
                return true;
            }

            return false;
        }

        case TOX_EVENT_GROUP_PEER_JOIN: {
            Tox_Event_Group_Peer_Join *group_peer_join = nullptr;

            if (tox_event_group_peer_join_unpack(&group_peer_join, bu, mem)) {
                event->type = TOX_EVENT_GROUP_PEER_JOIN;
                event->data.group_peer_join = group_peer_join;
                return true;
            }

            return false;
        }

        case TOX_EVENT_GROUP_PEER_EXIT: {
            Tox_Event_Group_Peer_Exit *group_peer_exit = nullptr;

            if (tox_event_group_peer_exit_unpack(&group_peer_exit, bu, mem)) {
                event->type = TOX_EVENT_GROUP_PEER_EXIT;
                event->data.group_peer_exit = group_peer_exit;
                return true;
            }

            return false;
        }

        case TOX_EVENT_GROUP_SELF_JOIN: {
            Tox_Event_Group_Self_Join *group_self_join = nullptr;

            if (tox_event_group_self_join_unpack(&group_self_join, bu, mem)) {
                event->type = TOX_EVENT_GROUP_SELF_JOIN;
                event->data.group_self_join = group_self_join;
                return true;
            }

            return false;
        }

        case TOX_EVENT_GROUP_JOIN_FAIL: {
            Tox_Event_Group_Join_Fail *group_join_fail = nullptr;

            if (tox_event_group_join_fail_unpack(&group_join_fail, bu, mem)) {
                event->type = TOX_EVENT_GROUP_JOIN_FAIL;
                event->data.group_join_fail = group_join_fail;
                return true;
            }

            return false;
        }

        case TOX_EVENT_GROUP_MODERATION: {
            Tox_Event_Group_Moderation *group_moderation = nullptr;

            if (tox_event_group_moderation_unpack(&group_moderation, bu, mem)) {
                event->type = TOX_EVENT_GROUP_MODERATION;
                event->data.group_moderation = group_moderation;
                return true;
            }

            return false;
        }

        case TOX_EVENT_DHT_NODES_RESPONSE: {
            Tox_Event_Dht_Nodes_Response *dht_nodes_response = nullptr;

            if (tox_event_dht_nodes_response_unpack(&dht_nodes_response, bu, mem)) {
                event->type = TOX_EVENT_DHT_NODES_RESPONSE;
                event->data.dht_nodes_response = dht_nodes_response;
                return true;
            }

            return false;
        }

        case TOX_EVENT_INVALID: {
            return false;
        }
    }

    return false;
}
