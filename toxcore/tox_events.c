/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2022 The TokTok team.
 */

#include "tox_events.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bin_unpack.h"
#include "ccompat.h"
#include "events/events_alloc.h"
#include "mem.h"
#include "tox.h"
#include "tox_private.h"


/*****************************************************
 *
 * :: Set up event handlers.
 *
 *****************************************************/


void tox_events_init(Tox *tox)
{
    tox_callback_conference_connected(tox, tox_events_handle_conference_connected);
    tox_callback_conference_invite(tox, tox_events_handle_conference_invite);
    tox_callback_conference_message(tox, tox_events_handle_conference_message);
    tox_callback_conference_peer_list_changed(tox, tox_events_handle_conference_peer_list_changed);
    tox_callback_conference_peer_name(tox, tox_events_handle_conference_peer_name);
    tox_callback_conference_title(tox, tox_events_handle_conference_title);
    tox_callback_file_chunk_request(tox, tox_events_handle_file_chunk_request);
    tox_callback_file_recv_chunk(tox, tox_events_handle_file_recv_chunk);
    tox_callback_file_recv_control(tox, tox_events_handle_file_recv_control);
    tox_callback_file_recv(tox, tox_events_handle_file_recv);
    tox_callback_friend_connection_status(tox, tox_events_handle_friend_connection_status);
    tox_callback_friend_lossless_packet(tox, tox_events_handle_friend_lossless_packet);
    tox_callback_friend_lossy_packet(tox, tox_events_handle_friend_lossy_packet);
    tox_callback_friend_message(tox, tox_events_handle_friend_message);
    tox_callback_friend_name(tox, tox_events_handle_friend_name);
    tox_callback_friend_read_receipt(tox, tox_events_handle_friend_read_receipt);
    tox_callback_friend_request(tox, tox_events_handle_friend_request);
    tox_callback_friend_status_message(tox, tox_events_handle_friend_status_message);
    tox_callback_friend_status(tox, tox_events_handle_friend_status);
    tox_callback_friend_typing(tox, tox_events_handle_friend_typing);
    tox_callback_self_connection_status(tox, tox_events_handle_self_connection_status);
    tox_callback_group_peer_name(tox, tox_events_handle_group_peer_name);
    tox_callback_group_peer_status(tox, tox_events_handle_group_peer_status);
    tox_callback_group_topic(tox, tox_events_handle_group_topic);
    tox_callback_group_privacy_state(tox, tox_events_handle_group_privacy_state);
    tox_callback_group_voice_state(tox, tox_events_handle_group_voice_state);
    tox_callback_group_topic_lock(tox, tox_events_handle_group_topic_lock);
    tox_callback_group_peer_limit(tox, tox_events_handle_group_peer_limit);
    tox_callback_group_password(tox, tox_events_handle_group_password);
    tox_callback_group_message(tox, tox_events_handle_group_message);
    tox_callback_group_private_message(tox, tox_events_handle_group_private_message);
    tox_callback_group_custom_packet(tox, tox_events_handle_group_custom_packet);
    tox_callback_group_custom_private_packet(tox, tox_events_handle_group_custom_private_packet);
    tox_callback_group_invite(tox, tox_events_handle_group_invite);
    tox_callback_group_peer_join(tox, tox_events_handle_group_peer_join);
    tox_callback_group_peer_exit(tox, tox_events_handle_group_peer_exit);
    tox_callback_group_self_join(tox, tox_events_handle_group_self_join);
    tox_callback_group_join_fail(tox, tox_events_handle_group_join_fail);
    tox_callback_group_moderation(tox, tox_events_handle_group_moderation);
}

Tox_Events *tox_events_iterate(Tox *tox, bool fail_hard, Tox_Err_Events_Iterate *error)
{
    Tox_Events_State state = {TOX_ERR_EVENTS_ITERATE_OK};
    tox_iterate(tox, &state);

    if (error != nullptr) {
        *error = state.error;
    }

    if (fail_hard && state.error != TOX_ERR_EVENTS_ITERATE_OK) {
        tox_events_free(state.events);
        return nullptr;
    }

    return state.events;
}

bool tox_events_pack(const Tox_Events *events, Bin_Pack *bp)
{
    const uint32_t count = tox_events_get_conference_connected_size(events)
                           + tox_events_get_conference_invite_size(events)
                           + tox_events_get_conference_message_size(events)
                           + tox_events_get_conference_peer_list_changed_size(events)
                           + tox_events_get_conference_peer_name_size(events)
                           + tox_events_get_conference_title_size(events)
                           + tox_events_get_file_chunk_request_size(events)
                           + tox_events_get_file_recv_chunk_size(events)
                           + tox_events_get_file_recv_control_size(events)
                           + tox_events_get_file_recv_size(events)
                           + tox_events_get_friend_connection_status_size(events)
                           + tox_events_get_friend_lossless_packet_size(events)
                           + tox_events_get_friend_lossy_packet_size(events)
                           + tox_events_get_friend_message_size(events)
                           + tox_events_get_friend_name_size(events)
                           + tox_events_get_friend_read_receipt_size(events)
                           + tox_events_get_friend_request_size(events)
                           + tox_events_get_friend_status_message_size(events)
                           + tox_events_get_friend_status_size(events)
                           + tox_events_get_friend_typing_size(events)
                           + tox_events_get_self_connection_status_size(events)
                           + tox_events_get_group_peer_name_size(events)
                           + tox_events_get_group_peer_status_size(events)
                           + tox_events_get_group_topic_size(events)
                           + tox_events_get_group_privacy_state_size(events)
                           + tox_events_get_group_voice_state_size(events)
                           + tox_events_get_group_topic_lock_size(events)
                           + tox_events_get_group_peer_limit_size(events)
                           + tox_events_get_group_password_size(events)
                           + tox_events_get_group_message_size(events)
                           + tox_events_get_group_private_message_size(events)
                           + tox_events_get_group_custom_packet_size(events)
                           + tox_events_get_group_custom_private_packet_size(events)
                           + tox_events_get_group_invite_size(events)
                           + tox_events_get_group_peer_join_size(events)
                           + tox_events_get_group_peer_exit_size(events)
                           + tox_events_get_group_self_join_size(events)
                           + tox_events_get_group_join_fail_size(events)
                           + tox_events_get_group_moderation_size(events);

    return bin_pack_array(bp, count)
           && tox_events_pack_conference_connected(events, bp)
           && tox_events_pack_conference_invite(events, bp)
           && tox_events_pack_conference_message(events, bp)
           && tox_events_pack_conference_peer_list_changed(events, bp)
           && tox_events_pack_conference_peer_name(events, bp)
           && tox_events_pack_conference_title(events, bp)
           && tox_events_pack_file_chunk_request(events, bp)
           && tox_events_pack_file_recv_chunk(events, bp)
           && tox_events_pack_file_recv_control(events, bp)
           && tox_events_pack_file_recv(events, bp)
           && tox_events_pack_friend_connection_status(events, bp)
           && tox_events_pack_friend_lossless_packet(events, bp)
           && tox_events_pack_friend_lossy_packet(events, bp)
           && tox_events_pack_friend_message(events, bp)
           && tox_events_pack_friend_name(events, bp)
           && tox_events_pack_friend_read_receipt(events, bp)
           && tox_events_pack_friend_request(events, bp)
           && tox_events_pack_friend_status_message(events, bp)
           && tox_events_pack_friend_status(events, bp)
           && tox_events_pack_friend_typing(events, bp)
           && tox_events_pack_self_connection_status(events, bp)
           && tox_events_pack_group_peer_name(events, bp)
           && tox_events_pack_group_peer_status(events, bp)
           && tox_events_pack_group_topic(events, bp)
           && tox_events_pack_group_privacy_state(events, bp)
           && tox_events_pack_group_voice_state(events, bp)
           && tox_events_pack_group_topic_lock(events, bp)
           && tox_events_pack_group_peer_limit(events, bp)
           && tox_events_pack_group_password(events, bp)
           && tox_events_pack_group_message(events, bp)
           && tox_events_pack_group_private_message(events, bp)
           && tox_events_pack_group_custom_packet(events, bp)
           && tox_events_pack_group_custom_private_packet(events, bp)
           && tox_events_pack_group_invite(events, bp)
           && tox_events_pack_group_peer_join(events, bp)
           && tox_events_pack_group_peer_exit(events, bp)
           && tox_events_pack_group_self_join(events, bp)
           && tox_events_pack_group_join_fail(events, bp)
           && tox_events_pack_group_moderation(events, bp);
}

non_null()
static bool tox_event_unpack(Tox_Events *events, Bin_Unpack *bu)
{
    uint32_t size;
    if (!bin_unpack_array(bu, &size)) {
        return false;
    }

    if (size != 2) {
        return false;
    }

    uint8_t type;
    if (!bin_unpack_u08(bu, &type)) {
        return false;
    }

    switch (type) {
        case TOX_EVENT_CONFERENCE_CONNECTED:
            return tox_events_unpack_conference_connected(events, bu);

        case TOX_EVENT_CONFERENCE_INVITE:
            return tox_events_unpack_conference_invite(events, bu);

        case TOX_EVENT_CONFERENCE_MESSAGE:
            return tox_events_unpack_conference_message(events, bu);

        case TOX_EVENT_CONFERENCE_PEER_LIST_CHANGED:
            return tox_events_unpack_conference_peer_list_changed(events, bu);

        case TOX_EVENT_CONFERENCE_PEER_NAME:
            return tox_events_unpack_conference_peer_name(events, bu);

        case TOX_EVENT_CONFERENCE_TITLE:
            return tox_events_unpack_conference_title(events, bu);

        case TOX_EVENT_FILE_CHUNK_REQUEST:
            return tox_events_unpack_file_chunk_request(events, bu);

        case TOX_EVENT_FILE_RECV_CHUNK:
            return tox_events_unpack_file_recv_chunk(events, bu);

        case TOX_EVENT_FILE_RECV_CONTROL:
            return tox_events_unpack_file_recv_control(events, bu);

        case TOX_EVENT_FILE_RECV:
            return tox_events_unpack_file_recv(events, bu);

        case TOX_EVENT_FRIEND_CONNECTION_STATUS:
            return tox_events_unpack_friend_connection_status(events, bu);

        case TOX_EVENT_FRIEND_LOSSLESS_PACKET:
            return tox_events_unpack_friend_lossless_packet(events, bu);

        case TOX_EVENT_FRIEND_LOSSY_PACKET:
            return tox_events_unpack_friend_lossy_packet(events, bu);

        case TOX_EVENT_FRIEND_MESSAGE:
            return tox_events_unpack_friend_message(events, bu);

        case TOX_EVENT_FRIEND_NAME:
            return tox_events_unpack_friend_name(events, bu);

        case TOX_EVENT_FRIEND_READ_RECEIPT:
            return tox_events_unpack_friend_read_receipt(events, bu);

        case TOX_EVENT_FRIEND_REQUEST:
            return tox_events_unpack_friend_request(events, bu);

        case TOX_EVENT_FRIEND_STATUS_MESSAGE:
            return tox_events_unpack_friend_status_message(events, bu);

        case TOX_EVENT_FRIEND_STATUS:
            return tox_events_unpack_friend_status(events, bu);

        case TOX_EVENT_FRIEND_TYPING:
            return tox_events_unpack_friend_typing(events, bu);

        case TOX_EVENT_SELF_CONNECTION_STATUS:
            return tox_events_unpack_self_connection_status(events, bu);

		case TOX_EVENT_GROUP_PEER_NAME:
            return tox_events_unpack_group_peer_name(events, bu);

		case TOX_EVENT_GROUP_PEER_STATUS:
            return tox_events_unpack_group_peer_status(events, bu);

		case TOX_EVENT_GROUP_TOPIC:
            return tox_events_unpack_group_topic(events, bu);

		case TOX_EVENT_GROUP_PRIVACY_STATE:
            return tox_events_unpack_group_privacy_state(events, bu);

		case TOX_EVENT_GROUP_VOICE_STATE:
            return tox_events_unpack_group_voice_state(events, bu);

		case TOX_EVENT_GROUP_TOPIC_LOCK:
            return tox_events_unpack_group_topic_lock(events, bu);

		case TOX_EVENT_GROUP_PEER_LIMIT:
            return tox_events_unpack_group_peer_limit(events, bu);

		case TOX_EVENT_GROUP_PASSWORD:
            return tox_events_unpack_group_password(events, bu);

		case TOX_EVENT_GROUP_MESSAGE:
            return tox_events_unpack_group_message(events, bu);

		case TOX_EVENT_GROUP_PRIVATE_MESSAGE:
            return tox_events_unpack_group_private_message(events, bu);

		case TOX_EVENT_GROUP_CUSTOM_PACKET:
            return tox_events_unpack_group_custom_packet(events, bu);

		case TOX_EVENT_GROUP_CUSTOM_PRIVATE_PACKET:
            return tox_events_unpack_group_custom_private_packet(events, bu);

		case TOX_EVENT_GROUP_INVITE:
            return tox_events_unpack_group_invite(events, bu);

		case TOX_EVENT_GROUP_PEER_JOIN:
            return tox_events_unpack_group_peer_join(events, bu);

		case TOX_EVENT_GROUP_PEER_EXIT:
            return tox_events_unpack_group_peer_exit(events, bu);

		case TOX_EVENT_GROUP_SELF_JOIN:
            return tox_events_unpack_group_self_join(events, bu);

		case TOX_EVENT_GROUP_JOIN_FAIL:
            return tox_events_unpack_group_join_fail(events, bu);

		case TOX_EVENT_GROUP_MODERATION:
            return tox_events_unpack_group_moderation(events, bu);

        default:
            return false;
    }

    return true;
}

bool tox_events_unpack(Tox_Events *events, Bin_Unpack *bu)
{
    uint32_t size;
    if (!bin_unpack_array(bu, &size)) {
        return false;
    }

    for (uint32_t i = 0; i < size; ++i) {
        if (!tox_event_unpack(events, bu)) {
            return false;
        }
    }

    return true;
}

non_null(1) nullable(2)
static bool tox_events_bin_pack_handler(Bin_Pack *bp, const void *obj)
{
    return tox_events_pack((const Tox_Events *)obj, bp);
}

uint32_t tox_events_bytes_size(const Tox_Events *events)
{
    return bin_pack_obj_size(tox_events_bin_pack_handler, events);
}

void tox_events_get_bytes(const Tox_Events *events, uint8_t *bytes)
{
    bin_pack_obj(tox_events_bin_pack_handler, events, bytes, UINT32_MAX);
}

Tox_Events *tox_events_load(const Tox_System *sys, const uint8_t *bytes, uint32_t bytes_size)
{
    Bin_Unpack *bu = bin_unpack_new(bytes, bytes_size);

    if (bu == nullptr) {
        return nullptr;
    }

    Tox_Events *events = (Tox_Events *)mem_alloc(sys->mem, sizeof(Tox_Events));

    if (events == nullptr) {
        bin_unpack_free(bu);
        return nullptr;
    }

    *events = (Tox_Events) {
        nullptr
    };

    if (!tox_events_unpack(events, bu)) {
        tox_events_free(events);
        bin_unpack_free(bu);
        return nullptr;
    }

    bin_unpack_free(bu);
    return events;
}

bool tox_events_equal(const Tox_System *sys, const Tox_Events *a, const Tox_Events *b)
{
    assert(sys != nullptr);
    assert(sys->mem != nullptr);

    const uint32_t a_size = tox_events_bytes_size(a);
    const uint32_t b_size = tox_events_bytes_size(b);

    if (a_size != b_size) {
        return false;
    }

    uint8_t *a_bytes = (uint8_t *)mem_balloc(sys->mem, a_size);
    uint8_t *b_bytes = (uint8_t *)mem_balloc(sys->mem, b_size);

    if (a_bytes == nullptr || b_bytes == nullptr) {
        mem_delete(sys->mem, b_bytes);
        mem_delete(sys->mem, a_bytes);
        return false;
    }

    tox_events_get_bytes(a, a_bytes);
    tox_events_get_bytes(b, b_bytes);

    const bool ret = memcmp(a_bytes, b_bytes, a_size) == 0;

    mem_delete(sys->mem, b_bytes);
    mem_delete(sys->mem, a_bytes);

    return ret;
}
