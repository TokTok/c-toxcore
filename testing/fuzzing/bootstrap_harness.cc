#include <cassert>
#include <cstdio>
#include <cstring>
#include <memory>

#include "../../toxcore/tox.h"
#include "../../toxcore/tox_dispatch.h"
#include "../../toxcore/tox_events.h"
#include "../../toxcore/tox_private.h"
#include "../../toxcore/tox_struct.h"
#include "../../toxcore/util.h"
#include "fuzz_support.h"
#include "fuzz_tox.h"

namespace {

void setup_callbacks(Tox_Dispatch *dispatch)
{
    tox_events_callback_conference_connected(
        dispatch, [](Tox *tox, const Tox_Event_Conference_Connected *event, void *user_data) {
            assert(event == nullptr);
        });
    tox_events_callback_conference_connected(
        dispatch, [](Tox *tox, const Tox_Event_Conference_Connected *event, void *user_data) {
            assert(event == nullptr);
        });
    tox_events_callback_conference_invite(
        dispatch, [](Tox *tox, const Tox_Event_Conference_Invite *event, void *user_data) {
            assert(event == nullptr);
        });
    tox_events_callback_conference_message(
        dispatch, [](Tox *tox, const Tox_Event_Conference_Message *event, void *user_data) {
            assert(event == nullptr);
        });
    tox_events_callback_conference_peer_list_changed(dispatch,
        [](Tox *tox, const Tox_Event_Conference_Peer_List_Changed *event, void *user_data) {
            assert(event == nullptr);
        });
    tox_events_callback_conference_peer_name(
        dispatch, [](Tox *tox, const Tox_Event_Conference_Peer_Name *event, void *user_data) {
            assert(event == nullptr);
        });
    tox_events_callback_conference_title(
        dispatch, [](Tox *tox, const Tox_Event_Conference_Title *event, void *user_data) {
            assert(event == nullptr);
        });
    tox_events_callback_file_chunk_request(
        dispatch, [](Tox *tox, const Tox_Event_File_Chunk_Request *event, void *user_data) {
            assert(event == nullptr);
        });
    tox_events_callback_file_recv(
        dispatch, [](Tox *tox, const Tox_Event_File_Recv *event, void *user_data) {
            assert(event == nullptr);
        });
    tox_events_callback_file_recv_chunk(
        dispatch, [](Tox *tox, const Tox_Event_File_Recv_Chunk *event, void *user_data) {
            assert(event == nullptr);
        });
    tox_events_callback_file_recv_control(
        dispatch, [](Tox *tox, const Tox_Event_File_Recv_Control *event, void *user_data) {
            assert(event == nullptr);
        });
    tox_events_callback_friend_connection_status(
        dispatch, [](Tox *tox, const Tox_Event_Friend_Connection_Status *event, void *user_data) {
            // OK: friend came online.
            const uint32_t friend_number
                = tox_event_friend_connection_status_get_friend_number(event);
            assert(friend_number == 0);
            const uint8_t message = 'A';
            Tox_Err_Friend_Send_Message err;
            tox_friend_send_message(tox, friend_number, TOX_MESSAGE_TYPE_NORMAL, &message, 1, &err);
            assert(err == TOX_ERR_FRIEND_SEND_MESSAGE_OK);
        });
    tox_events_callback_friend_lossless_packet(
        dispatch, [](Tox *tox, const Tox_Event_Friend_Lossless_Packet *event, void *user_data) {
            assert(event == nullptr);
        });
    tox_events_callback_friend_lossy_packet(
        dispatch, [](Tox *tox, const Tox_Event_Friend_Lossy_Packet *event, void *user_data) {
            assert(event == nullptr);
        });
    tox_events_callback_friend_message(
        dispatch, [](Tox *tox, const Tox_Event_Friend_Message *event, void *user_data) {
            const uint32_t friend_number = tox_event_friend_message_get_friend_number(event);
            const uint32_t message_length = tox_event_friend_message_get_message_length(event);
            if (message_length == 0) {
                return;
            }
            const uint8_t reply = 'B';
            tox_friend_send_message(
                tox, friend_number, TOX_MESSAGE_TYPE_NORMAL, &reply, 1, nullptr);
        });
    tox_events_callback_friend_name(
        dispatch, [](Tox *tox, const Tox_Event_Friend_Name *event, void *user_data) {
            // OK: friend name received.
        });
    tox_events_callback_friend_read_receipt(
        dispatch, [](Tox *tox, const Tox_Event_Friend_Read_Receipt *event, void *user_data) {
            // OK: message has been received.
        });
    tox_events_callback_friend_request(
        dispatch, [](Tox *tox, const Tox_Event_Friend_Request *event, void *user_data) {
            Tox_Err_Friend_Add err;
            tox_friend_add_norequest(tox, tox_event_friend_request_get_public_key(event), &err);
            assert(err == TOX_ERR_FRIEND_ADD_OK || err == TOX_ERR_FRIEND_ADD_OWN_KEY
                || err == TOX_ERR_FRIEND_ADD_ALREADY_SENT
                || err == TOX_ERR_FRIEND_ADD_BAD_CHECKSUM);
        });
    tox_events_callback_friend_status(
        dispatch, [](Tox *tox, const Tox_Event_Friend_Status *event, void *user_data) {
            // OK: friend status received.
        });
    tox_events_callback_friend_status_message(
        dispatch, [](Tox *tox, const Tox_Event_Friend_Status_Message *event, void *user_data) {
            // OK: friend status message received.
        });
    tox_events_callback_friend_typing(
        dispatch, [](Tox *tox, const Tox_Event_Friend_Typing *event, void *user_data) {
            // OK: friend may be typing.
        });
    tox_events_callback_self_connection_status(
        dispatch, [](Tox *tox, const Tox_Event_Self_Connection_Status *event, void *user_data) {
            // OK: we got connected.
        });
}

static char tox_log_level_name(Tox_Log_Level level)
{
    switch (level) {
    case TOX_LOG_LEVEL_TRACE:
        return 'T';
    case TOX_LOG_LEVEL_DEBUG:
        return 'D';
    case TOX_LOG_LEVEL_INFO:
        return 'I';
    case TOX_LOG_LEVEL_WARNING:
        return 'W';
    case TOX_LOG_LEVEL_ERROR:
        return 'E';
    }

    return '?';
}

void TestBootstrap(Fuzz_Data &input)
{
    Fuzz_System sys(input);

    Ptr<Tox_Options> opts(tox_options_new(nullptr), tox_options_free);
    assert(opts != nullptr);
    tox_options_set_operating_system(opts.get(), sys.sys.get());
    tox_options_set_local_discovery_enabled(opts.get(), false);

    tox_options_set_log_callback(opts.get(),
        [](Tox *tox, Tox_Log_Level level, const char *file, uint32_t line, const char *func,
            const char *message, void *user_data) {
            // Log to stdout.
            if (DEBUG) {
                std::printf("[tox1] %c %s:%d(%s): %s\n", tox_log_level_name(level), file, line,
                    func, message);
            }
        });

    CONSUME1_OR_RETURN(const bool want_bootstrap, input);

    CONSUME1_OR_RETURN(const uint8_t proxy_type, input);
    if (proxy_type == 0) {
        tox_options_set_proxy_type(opts.get(), TOX_PROXY_TYPE_NONE);
    } else if (proxy_type == 1) {
        tox_options_set_proxy_type(opts.get(), TOX_PROXY_TYPE_SOCKS5);
        tox_options_set_proxy_host(opts.get(), "127.0.0.1");
        tox_options_set_proxy_port(opts.get(), 8080);
    } else if (proxy_type == 2) {
        tox_options_set_proxy_type(opts.get(), TOX_PROXY_TYPE_HTTP);
        tox_options_set_proxy_host(opts.get(), "127.0.0.1");
        tox_options_set_proxy_port(opts.get(), 8080);
    }

    Tox_Err_New error_new;
    Tox *tox = tox_new(opts.get(), &error_new);

    if (tox == nullptr) {
        // It might fail, because some I/O happens in tox_new, and the fuzzer
        // might do things that make that I/O fail.
        return;
    }

    assert(error_new == TOX_ERR_NEW_OK);

    if (want_bootstrap) {
        uint8_t pub_key[TOX_PUBLIC_KEY_SIZE] = {0};

        const bool udp_success = tox_bootstrap(tox, "192.168.0.127", 33446, pub_key, nullptr);
        assert(udp_success);

        const bool tcp_success = tox_add_tcp_relay(tox, "192.168.0.127", 33446, pub_key, nullptr);
        assert(tcp_success);
    }

    tox_events_init(tox);

    Tox_Dispatch *dispatch = tox_dispatch_new(nullptr);
    assert(dispatch != nullptr);
    setup_callbacks(dispatch);

    while (input.size > 0) {
        Tox_Err_Events_Iterate error_iterate;
        Tox_Events *events = tox_events_iterate(tox, true, &error_iterate);
        assert(tox_events_equal(events, events));
        tox_dispatch_invoke(dispatch, events, tox, nullptr);
        tox_events_free(events);
        // Move the clock forward a decent amount so all the time-based checks
        // trigger more quickly.
        sys.clock += 200;
    }

    tox_dispatch_free(dispatch);
    tox_kill(tox);
}

}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    Fuzz_Data input{data, size};
    TestBootstrap(input);
    return 0;  // Non-zero return values are reserved for future use.
}
