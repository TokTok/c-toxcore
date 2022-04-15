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
            assert(event == nullptr);
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
            assert(event == nullptr);
        });
    tox_events_callback_friend_name(
        dispatch, [](Tox *tox, const Tox_Event_Friend_Name *event, void *user_data) {
            assert(event == nullptr);
        });
    tox_events_callback_friend_read_receipt(
        dispatch, [](Tox *tox, const Tox_Event_Friend_Read_Receipt *event, void *user_data) {
            assert(event == nullptr);
        });
    tox_events_callback_friend_request(
        dispatch, [](Tox *tox, const Tox_Event_Friend_Request *event, void *user_data) {
            assert(event == nullptr);
            Tox_Err_Friend_Add err;
            tox_friend_add_norequest(tox, tox_event_friend_request_get_public_key(event), &err);
            assert(err == TOX_ERR_FRIEND_ADD_OK || err == TOX_ERR_FRIEND_ADD_OWN_KEY
                || err == TOX_ERR_FRIEND_ADD_ALREADY_SENT
                || err == TOX_ERR_FRIEND_ADD_BAD_CHECKSUM);
        });
    tox_events_callback_friend_status(
        dispatch, [](Tox *tox, const Tox_Event_Friend_Status *event, void *user_data) {
            assert(event == nullptr);
        });
    tox_events_callback_friend_status_message(
        dispatch, [](Tox *tox, const Tox_Event_Friend_Status_Message *event, void *user_data) {
            assert(event == nullptr);
        });
    tox_events_callback_friend_typing(
        dispatch, [](Tox *tox, const Tox_Event_Friend_Typing *event, void *user_data) {
            assert(event == nullptr);
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
            printf("[%s] %c %s:%d(%s): %s\n", static_cast<Record_System *>(user_data)->name_,
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
    std::array<uint8_t, TOX_PUBLIC_KEY_SIZE> dht_key2;
    tox_self_get_dht_id(tox2, dht_key2.data());

    assert(address1 != address2);
    assert(dht_key1 != dht_key2);

    tox_options_free(opts);

    sys1.setup(sys2);
    sys2.setup(sys1);

    const uint16_t port = tox_self_get_udp_port(tox1, nullptr);

    const bool udp_success = tox_bootstrap(tox2, "192.168.0.127", port, dht_key1.data(), nullptr);
    assert(udp_success);

#if 1
    Tox_Err_Friend_Add error_add;
    const uint32_t friend_number = tox_friend_add_norequest(tox2, address1.data(), &error_add);
    assert(friend_number == 0);
    assert(tox_friend_add_norequest(tox1, address2.data(), &error_add) == 0);
#endif

    tox_events_init(tox1);
    tox_events_init(tox2);

    Tox_Dispatch *dispatch = tox_dispatch_new(nullptr);
    assert(dispatch != nullptr);
    setup_callbacks(dispatch);

    while (tox_friend_get_connection_status(tox2, 0, nullptr) == TOX_CONNECTION_NONE) {
        printf("tox1: %d, tox2: %d, tox1 -> tox2: %d, tox2 -> tox1: %d\n",
            tox_self_get_connection_status(tox1), tox_self_get_connection_status(tox2),
            tox_friend_get_connection_status(tox1, 0, nullptr),
            tox_friend_get_connection_status(tox2, 0, nullptr));
        Tox_Err_Events_Iterate error_iterate;
        Tox_Events *events;

        events = tox_events_iterate(tox1, true, &error_iterate);
        assert(tox_events_equal(events, events));
        tox_dispatch_invoke(dispatch, events, tox1, nullptr);
        tox_events_free(events);

        events = tox_events_iterate(tox2, true, &error_iterate);
        assert(tox_events_equal(events, events));
        tox_dispatch_invoke(dispatch, events, tox2, nullptr);
        tox_events_free(events);

        // Move the clock forward a decent amount so all the time-based checks
        // trigger more quickly.
        sys1.clock += 200;
        sys2.clock += 200;
    }

    tox_dispatch_free(dispatch);
    tox_kill(tox2);
    tox_kill(tox1);
}

}

int main(void) { RecordBootstrap(); }
