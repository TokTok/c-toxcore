/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2022 The TokTok team.
 */

#include "tox_events.h"

#include <msgpack.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ccompat.h"
#include "events/events_alloc.h"
#include "tox.h"


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

void tox_events_pack(const Tox_Events *events, cmp_ctx_t *ctx)
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
                           + tox_events_get_self_connection_status_size(events);

    cmp_write_array(ctx, count);

    tox_events_pack_conference_connected(events, ctx);
    tox_events_pack_conference_invite(events, ctx);
    tox_events_pack_conference_message(events, ctx);
    tox_events_pack_conference_peer_list_changed(events, ctx);
    tox_events_pack_conference_peer_name(events, ctx);
    tox_events_pack_conference_title(events, ctx);
    tox_events_pack_file_chunk_request(events, ctx);
    tox_events_pack_file_recv_chunk(events, ctx);
    tox_events_pack_file_recv_control(events, ctx);
    tox_events_pack_file_recv(events, ctx);
    tox_events_pack_friend_connection_status(events, ctx);
    tox_events_pack_friend_lossless_packet(events, ctx);
    tox_events_pack_friend_lossy_packet(events, ctx);
    tox_events_pack_friend_message(events, ctx);
    tox_events_pack_friend_name(events, ctx);
    tox_events_pack_friend_read_receipt(events, ctx);
    tox_events_pack_friend_request(events, ctx);
    tox_events_pack_friend_status_message(events, ctx);
    tox_events_pack_friend_status(events, ctx);
    tox_events_pack_friend_typing(events, ctx);
    tox_events_pack_self_connection_status(events, ctx);
}

non_null()
static bool tox_event_unpack(Tox_Events *events, const msgpack_object *obj)
{
    if (obj->type != MSGPACK_OBJECT_ARRAY || obj->via.array.size != 2 ||
            obj->via.array.ptr[0].type != MSGPACK_OBJECT_POSITIVE_INTEGER) {
        return false;
    }

    const msgpack_object *inner = &obj->via.array.ptr[1];

    switch (obj->via.array.ptr[0].via.u64) {
        case TOX_EVENT_CONFERENCE_CONNECTED:
            return tox_events_unpack_conference_connected(events, inner);

        case TOX_EVENT_CONFERENCE_INVITE:
            return tox_events_unpack_conference_invite(events, inner);

        case TOX_EVENT_CONFERENCE_MESSAGE:
            return tox_events_unpack_conference_message(events, inner);

        case TOX_EVENT_CONFERENCE_PEER_LIST_CHANGED:
            return tox_events_unpack_conference_peer_list_changed(events, inner);

        case TOX_EVENT_CONFERENCE_PEER_NAME:
            return tox_events_unpack_conference_peer_name(events, inner);

        case TOX_EVENT_CONFERENCE_TITLE:
            return tox_events_unpack_conference_title(events, inner);

        case TOX_EVENT_FILE_CHUNK_REQUEST:
            return tox_events_unpack_file_chunk_request(events, inner);

        case TOX_EVENT_FILE_RECV_CHUNK:
            return tox_events_unpack_file_recv_chunk(events, inner);

        case TOX_EVENT_FILE_RECV_CONTROL:
            return tox_events_unpack_file_recv_control(events, inner);

        case TOX_EVENT_FILE_RECV:
            return tox_events_unpack_file_recv(events, inner);

        case TOX_EVENT_FRIEND_CONNECTION_STATUS:
            return tox_events_unpack_friend_connection_status(events, inner);

        case TOX_EVENT_FRIEND_LOSSLESS_PACKET:
            return tox_events_unpack_friend_lossless_packet(events, inner);

        case TOX_EVENT_FRIEND_LOSSY_PACKET:
            return tox_events_unpack_friend_lossy_packet(events, inner);

        case TOX_EVENT_FRIEND_MESSAGE:
            return tox_events_unpack_friend_message(events, inner);

        case TOX_EVENT_FRIEND_NAME:
            return tox_events_unpack_friend_name(events, inner);

        case TOX_EVENT_FRIEND_READ_RECEIPT:
            return tox_events_unpack_friend_read_receipt(events, inner);

        case TOX_EVENT_FRIEND_REQUEST:
            return tox_events_unpack_friend_request(events, inner);

        case TOX_EVENT_FRIEND_STATUS_MESSAGE:
            return tox_events_unpack_friend_status_message(events, inner);

        case TOX_EVENT_FRIEND_STATUS:
            return tox_events_unpack_friend_status(events, inner);

        case TOX_EVENT_FRIEND_TYPING:
            return tox_events_unpack_friend_typing(events, inner);

        case TOX_EVENT_SELF_CONNECTION_STATUS:
            return tox_events_unpack_self_connection_status(events, inner);

        default:
            return false;
    }

    return true;
}

bool tox_events_unpack(Tox_Events *events, const msgpack_object *obj)
{
    if (obj->type != MSGPACK_OBJECT_ARRAY) {
        return false;
    }

    for (uint32_t i = 0; i < obj->via.array.size; ++i) {
        if (!tox_event_unpack(events, &obj->via.array.ptr[i])) {
            return false;
        }
    }

    return true;
}

static bool null_reader(cmp_ctx_t *ctx, void *data, size_t limit)
{
    return false;
}

static bool null_skipper(cmp_ctx_t *ctx, size_t limit)
{
    return false;
}

non_null()
static size_t count_writer(cmp_ctx_t *ctx, const void *data, size_t count)
{
    uint32_t *total_count = (uint32_t *)ctx->buf;
    assert(total_count != nullptr);
    *total_count += count;
    return 0;
}

uint32_t tox_events_bytes_size(const Tox_Events *events)
{
    uint32_t count = 0;
    cmp_ctx_t ctx;
    cmp_init(&ctx, &count, null_reader, null_skipper, count_writer);
    tox_events_pack(events, &ctx);
    return count;
}

non_null()
static size_t buf_writer(cmp_ctx_t *ctx, const void *data, size_t count)
{
    uint8_t **bytes = (uint8_t **)ctx->buf;
    assert(bytes != nullptr && *bytes != nullptr);
    memcpy(*bytes, data, count);
    *bytes += count;
    return count;
}

void tox_events_get_bytes(const Tox_Events *events, uint8_t *bytes)
{
    cmp_ctx_t ctx;
    cmp_init(&ctx, &bytes, null_reader, null_skipper, buf_writer);
    tox_events_pack(events, &ctx);
}

Tox_Events *tox_events_load(const uint8_t *bytes, uint32_t bytes_size)
{
    msgpack_unpacked msg;

    size_t offset = 0;
    msgpack_unpacked_init(&msg);
    const msgpack_unpack_return result = msgpack_unpack_next(&msg, (const char *)bytes, bytes_size, &offset);

    if (result != MSGPACK_UNPACK_SUCCESS) {
        msgpack_unpacked_destroy(&msg);
        return nullptr;
    }

    Tox_Events *events = (Tox_Events *)calloc(1, sizeof(Tox_Events));

    if (events == nullptr) {
        msgpack_unpacked_destroy(&msg);
        return nullptr;
    }

    *events = (Tox_Events) {
        nullptr
    };

    if (!tox_events_unpack(events, &msg.data)) {
        tox_events_free(events);
        msgpack_unpacked_destroy(&msg);
        return nullptr;
    }

    msgpack_unpacked_destroy(&msg);
    return events;
}

non_null()
static size_t sbuffer_writer(cmp_ctx_t *ctx, const void *data, size_t count)
{
    msgpack_sbuffer_write(ctx->buf, data, count);
    return count;
}

non_null(2, 3) nullable(1)
static bool tox_events_to_object(const Tox_Events *events, msgpack_unpacked *msg, msgpack_sbuffer *sbuf)
{
    msgpack_sbuffer_init(sbuf);

    cmp_ctx_t ctx;
    cmp_init(&ctx, sbuf, null_reader, null_skipper, sbuffer_writer);

    tox_events_pack(events, &ctx);

    size_t offset = 0;
    msgpack_unpacked_init(msg);
    const msgpack_unpack_return result = msgpack_unpack_next(msg, sbuf->data, sbuf->size, &offset);

    return result == MSGPACK_UNPACK_SUCCESS;
}

void tox_events_print(const Tox_Events *events)
{
    msgpack_sbuffer sbuf;
    msgpack_unpacked msg;
    tox_events_to_object(events, &msg, &sbuf);
    msgpack_object_print(stdout, msg.data);
    fputc('\n', stdout);
    msgpack_unpacked_destroy(&msg);
    msgpack_sbuffer_destroy(&sbuf);
}

bool tox_events_equal(const Tox_Events *a, const Tox_Events *b)
{
    msgpack_sbuffer sbuf_a = {0};
    msgpack_unpacked msg_a = {nullptr};
    msgpack_sbuffer sbuf_b = {0};
    msgpack_unpacked msg_b = {nullptr};

    const bool success = tox_events_to_object(a, &msg_a, &sbuf_a)
                         && tox_events_to_object(b, &msg_b, &sbuf_b);

    const bool ret = success && msgpack_object_equal(msg_a.data, msg_b.data);

    msgpack_unpacked_destroy(&msg_b);
    msgpack_sbuffer_destroy(&sbuf_a);
    msgpack_unpacked_destroy(&msg_a);
    msgpack_sbuffer_destroy(&sbuf_b);

    return ret;
}
