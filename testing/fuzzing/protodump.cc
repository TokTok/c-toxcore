/** @file
 * @brief Generates a valid input for e2e_fuzz_test.
 *
 * This bootstraps 2 toxes tox1 and tox2, adds tox1 as tox2's friend, waits for
 * the friend request, then tox1 adds tox2 in response, waits for the friend to
 * come online, sends a 2-message exchange, and waits for the read receipt.
 *
 * All random inputs and network traffic is recorded and dumped to files at the
 * end. This can then be fed to e2e_fuzz_test for replay (only of tox1) and
 * further code path exploration using fuzzer mutations.
 *
 * We write 2 files: an init file that contains all the inputs needed to reach
 * the "friend online" state, and a smaller file containing things to mutate
 * once the tox instance is in that state. This allows for more specific
 * exploration of code paths starting from "friend is online". DHT and onion
 * packet parsing is explored more in bootstrap_fuzz_test.
 */
#include <cassert>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <memory>

#include "../../toxcore/tox.h"
#include "../../toxcore/tox_dispatch.h"
#include "../../toxcore/tox_events.h"
#include "../../toxcore/tox_private.h"
#include "../../toxcore/tox_struct.h"
#include "../../toxcore/util.h"
#include "fuzz_support.h"

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
            assert(friend_number == 0);
            const uint32_t message_length = tox_event_friend_message_get_message_length(event);
            assert(message_length == 1);
            const uint8_t *message = tox_event_friend_message_get_message(event);
            if (message[0] == 'A') {
                const uint8_t reply = 'B';
                Tox_Err_Friend_Send_Message err;
                tox_friend_send_message(
                    tox, friend_number, TOX_MESSAGE_TYPE_NORMAL, &reply, 1, &err);
                assert(err == TOX_ERR_FRIEND_SEND_MESSAGE_OK);
            } else {
                assert(message[0] == 'B');
            }
        });
    tox_events_callback_friend_name(
        dispatch, [](Tox *tox, const Tox_Event_Friend_Name *event, void *user_data) {
            const uint32_t friend_number = tox_event_friend_name_get_friend_number(event);
            assert(friend_number == 0);
        });
    tox_events_callback_friend_read_receipt(
        dispatch, [](Tox *tox, const Tox_Event_Friend_Read_Receipt *event, void *user_data) {
            const uint32_t friend_number = tox_event_friend_read_receipt_get_friend_number(event);
            assert(friend_number == 0);
            const uint32_t message_id = tox_event_friend_read_receipt_get_message_id(event);
            if (message_id == 2) {
                *static_cast<bool *>(user_data) = true;
            }
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
            const uint32_t friend_number = tox_event_friend_status_get_friend_number(event);
            assert(friend_number == 0);
        });
    tox_events_callback_friend_status_message(
        dispatch, [](Tox *tox, const Tox_Event_Friend_Status_Message *event, void *user_data) {
            const uint32_t friend_number = tox_event_friend_status_message_get_friend_number(event);
            assert(friend_number == 0);
        });
    tox_events_callback_friend_typing(
        dispatch, [](Tox *tox, const Tox_Event_Friend_Typing *event, void *user_data) {
            const uint32_t friend_number = tox_event_friend_typing_get_friend_number(event);
            assert(friend_number == 0);
            assert(!tox_event_friend_typing_get_typing(event));
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

void dump(std::vector<uint8_t> &recording, const char *filename)
{
    std::printf("%zu bytes: %s\n", recording.size(), filename);
    std::ofstream out_init(filename);
    out_init.write(reinterpret_cast<const char *>(recording.data()), recording.size());
    recording.clear();
}

void RecordBootstrap()
{
    Record_System::Global global;

    Tox_Options *opts = tox_options_new(nullptr);
    assert(opts != nullptr);

    tox_options_set_local_discovery_enabled(opts, false);

    tox_options_set_log_callback(opts,
        [](Tox *tox, Tox_Log_Level level, const char *file, uint32_t line, const char *func,
            const char *message, void *user_data) {
            // Log to stdout.
            std::printf("[%s] %c %s:%d(%s): %s\n", static_cast<Record_System *>(user_data)->name_,
                tox_log_level_name(level), file, line, func, message);
        });

    Tox_Err_New error_new;

    Record_System sys1(global, 4, "tox1");  // fair dice roll
    tox_options_set_log_user_data(opts, &sys1);
    tox_options_set_operating_system(opts, sys1.sys.get());
    Tox *tox1 = tox_new(opts, &error_new);
    assert(tox1 != nullptr);
    assert(error_new == TOX_ERR_NEW_OK);
    std::array<uint8_t, TOX_ADDRESS_SIZE> address1;
    tox_self_get_address(tox1, address1.data());
    std::array<uint8_t, TOX_PUBLIC_KEY_SIZE> pk1;
    tox_self_get_public_key(tox1, pk1.data());
    std::array<uint8_t, TOX_PUBLIC_KEY_SIZE> dht_key1;
    tox_self_get_dht_id(tox1, dht_key1.data());

    Record_System sys2(global, 5, "tox2");  // unfair dice roll
    tox_options_set_log_user_data(opts, &sys2);
    tox_options_set_operating_system(opts, sys2.sys.get());
    Tox *tox2 = tox_new(opts, &error_new);
    assert(tox2 != nullptr);
    assert(error_new == TOX_ERR_NEW_OK);
    std::array<uint8_t, TOX_ADDRESS_SIZE> address2;
    tox_self_get_address(tox2, address2.data());
    std::array<uint8_t, TOX_PUBLIC_KEY_SIZE> pk2;
    tox_self_get_public_key(tox2, pk2.data());
    std::array<uint8_t, TOX_PUBLIC_KEY_SIZE> dht_key2;
    tox_self_get_dht_id(tox2, dht_key2.data());

    assert(address1 != address2);
    assert(pk1 != pk2);
    assert(dht_key1 != dht_key2);

    tox_options_free(opts);

    const uint16_t port = tox_self_get_udp_port(tox1, nullptr);

    const bool udp_success = tox_bootstrap(tox2, "192.168.0.127", port, dht_key1.data(), nullptr);
    assert(udp_success);

    tox_events_init(tox1);
    tox_events_init(tox2);

    Tox_Dispatch *dispatch = tox_dispatch_new(nullptr);
    assert(dispatch != nullptr);
    setup_callbacks(dispatch);

    bool done1 = false;
    bool done2 = false;

    const auto iterate = [&] {
        Tox_Err_Events_Iterate error_iterate;
        Tox_Events *events;

        events = tox_events_iterate(tox1, true, &error_iterate);
        assert(tox_events_equal(events, events));
        tox_dispatch_invoke(dispatch, events, tox1, &done1);
        tox_events_free(events);

        events = tox_events_iterate(tox2, true, &error_iterate);
        assert(tox_events_equal(events, events));
        tox_dispatch_invoke(dispatch, events, tox2, &done2);
        tox_events_free(events);

        // Move the clock forward a decent amount so all the time-based checks
        // trigger more quickly.
        sys1.clock += 200;
        sys2.clock += 200;
    };

    while (tox_self_get_connection_status(tox1) == TOX_CONNECTION_NONE
        || tox_self_get_connection_status(tox2) == TOX_CONNECTION_NONE) {
        if (DEBUG) {
            std::printf("tox1: %d, tox2: %d\n", tox_self_get_connection_status(tox1),
                tox_self_get_connection_status(tox2));
        }
        iterate();
    }

    std::printf("toxes are online\n");

    const uint8_t msg = 'A';
    const uint32_t friend_number = tox_friend_add(tox2, address1.data(), &msg, 1, nullptr);
    assert(friend_number == 0);

    while (tox_friend_get_connection_status(tox2, friend_number, nullptr) == TOX_CONNECTION_NONE) {
        if (DEBUG) {
            std::printf("tox1: %d, tox2: %d, tox1 -> tox2: %d, tox2 -> tox1: %d\n",
                tox_self_get_connection_status(tox1), tox_self_get_connection_status(tox2),
                tox_friend_get_connection_status(tox1, 0, nullptr),
                tox_friend_get_connection_status(tox2, 0, nullptr));
        }
        iterate();
    }

    std::printf("tox clients connected\n");

    dump(sys1.recording, "tools/toktok-fuzzer/init/e2e_fuzz_test.dat");

    while (!done1 && !done2) {
        if (DEBUG) {
            std::printf("tox1: %d, tox2: %d, tox1 -> tox2: %d, tox2 -> tox1: %d\n",
                tox_self_get_connection_status(tox1), tox_self_get_connection_status(tox2),
                tox_friend_get_connection_status(tox1, 0, nullptr),
                tox_friend_get_connection_status(tox2, 0, nullptr));
        }
        iterate();
    }

    std::printf("test complete\n");

    tox_dispatch_free(dispatch);
    tox_kill(tox2);
    tox_kill(tox1);

    dump(sys1.recording, "tools/toktok-fuzzer/corpus/e2e_fuzz_test/bootstrap.dat");
}

}

int main(void) { RecordBootstrap(); }
