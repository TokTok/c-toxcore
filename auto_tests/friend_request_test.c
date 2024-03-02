/* Tests that we can add friends.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "../toxcore/ccompat.h"
#include "../toxcore/tox.h"
#include "../toxcore/util.h"
#include "../testing/misc_tools.h"

#include "auto_test_support.h"
#include "check_compat.h"

#define REQUEST_MESSAGE "Hello, I would like to be your friend. Please respond."

typedef struct Callback_Data {
    Tox      *tox1;  // request sender
    Tox      *tox2;  // request receiver
    uint8_t  message[TOX_MAX_FRIEND_REQUEST_LENGTH];
    uint16_t length;
} Callback_Data;

static void accept_friend_request(const Tox_Event_Friend_Request *event, void *userdata)
{
    Callback_Data *cb_data = (Callback_Data *)userdata;

    const uint8_t *public_key = tox_event_friend_request_get_public_key(event);
    const uint8_t *data = tox_event_friend_request_get_message(event);
    const size_t length = tox_event_friend_request_get_message_length(event);

    ck_assert_msg(length == cb_data->length && memcmp(cb_data->message, data, cb_data->length) == 0,
                  "unexpected friend request message");

    fprintf(stderr, "Tox2 accepts friend request.\n");

    Tox_Err_Friend_Add err;
    tox_friend_add_norequest(cb_data->tox2, public_key, &err);

    ck_assert_msg(err == TOX_ERR_FRIEND_ADD_OK, "tox_friend_add_norequest failed: %d", err);
}

static void iterate2_wait(const Tox_Dispatch *dispatch, Callback_Data *cb_data)
{
    Tox_Err_Events_Iterate err;
    Tox_Events *events;

    events = tox_events_iterate(cb_data->tox1, true, &err);
    ck_assert(err == TOX_ERR_EVENTS_ITERATE_OK);
    tox_dispatch_invoke(dispatch, events, cb_data);
    tox_events_free(events);

    events = tox_events_iterate(cb_data->tox2, true, &err);
    ck_assert(err == TOX_ERR_EVENTS_ITERATE_OK);
    tox_dispatch_invoke(dispatch, events, cb_data);
    tox_events_free(events);

    c_sleep(ITERATION_INTERVAL);
}

static void test_friend_request(const uint8_t *message, uint16_t length)
{
    printf("Initialising 2 toxes.\n");
    uint32_t index[] = { 1, 2 };
    const time_t cur_time = time(nullptr);
    Tox *const tox1 = tox_new_log(nullptr, nullptr, &index[0]);
    Tox *const tox2 = tox_new_log(nullptr, nullptr, &index[1]);

    ck_assert_msg(tox1 && tox2, "failed to create 2 tox instances");

    tox_events_init(tox1);
    tox_events_init(tox2);

    printf("Bootstrapping Tox2 off Tox1.\n");
    uint8_t dht_key[TOX_PUBLIC_KEY_SIZE];
    tox_self_get_dht_id(tox1, dht_key);
    const uint16_t dht_port = tox_self_get_udp_port(tox1, nullptr);

    tox_bootstrap(tox2, "localhost", dht_port, dht_key, nullptr);

    Tox_Dispatch *dispatch = tox_dispatch_new(nullptr);
    ck_assert(dispatch != nullptr);

    Callback_Data cb_data = {nullptr};
    cb_data.tox1 = tox1;
    cb_data.tox2 = tox2;

    ck_assert(length <= sizeof(cb_data.message));
    memcpy(cb_data.message, message, length);
    cb_data.length = length;

    do {
        iterate2_wait(dispatch, &cb_data);
    } while (tox_self_get_connection_status(tox1) == TOX_CONNECTION_NONE ||
             tox_self_get_connection_status(tox2) == TOX_CONNECTION_NONE);

    printf("Toxes are online, took %lu seconds.\n", (unsigned long)(time(nullptr) - cur_time));
    const time_t con_time = time(nullptr);

    printf("Tox1 adds Tox2 as friend. Waiting for Tox2 to accept.\n");
    tox_events_callback_friend_request(dispatch, accept_friend_request);

    uint8_t address[TOX_ADDRESS_SIZE];
    tox_self_get_address(tox2, address);

    Tox_Err_Friend_Add err;
    const uint32_t test = tox_friend_add(tox1, address, message, length, &err);

    ck_assert_msg(err == TOX_ERR_FRIEND_ADD_OK, "tox_friend_add failed: %d", err);
    ck_assert_msg(test == 0, "failed to add friend error code: %u", test);

    do {
        iterate2_wait(dispatch, &cb_data);
    } while (tox_friend_get_connection_status(tox1, 0, nullptr) != TOX_CONNECTION_UDP ||
             tox_friend_get_connection_status(tox2, 0, nullptr) != TOX_CONNECTION_UDP);

    printf("Tox clients connected took %lu seconds.\n", (unsigned long)(time(nullptr) - con_time));
    printf("friend_request_test succeeded, took %lu seconds.\n", (unsigned long)(time(nullptr) - cur_time));

    tox_dispatch_free(dispatch);
    tox_kill(tox1);
    tox_kill(tox2);
}

int main(void)
{
    setvbuf(stdout, nullptr, _IONBF, 0);

    fprintf(stderr, "Testing friend request with the smallest allowed message length.\n");
    test_friend_request((const uint8_t *)"a", 1);

    fprintf(stderr, "Testing friend request with an average sized message length.\n");
    test_friend_request((const uint8_t *)REQUEST_MESSAGE, sizeof(REQUEST_MESSAGE) - 1);

    uint8_t long_message[TOX_MAX_FRIEND_REQUEST_LENGTH];

    for (uint16_t i = 0; i < sizeof(long_message); ++i) {
        long_message[i] = 'a';
    }

    fprintf(stderr, "Testing friend request with the largest allowed message length.\n");
    test_friend_request(long_message, sizeof(long_message));

    return 0;
}
