/* Tests that we can set our status message
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "../testing/misc_tools.h"
#include "../toxcore/ccompat.h"
#include "../toxcore/tox.h"
#include "../toxcore/util.h"
#include "auto_test_support.h"
#include "check_compat.h"

#define STATUS_MESSAGE "Installing Gentoo"

static void status_callback(const Tox_Event_Friend_Status_Message *event, void *user_data)
{
    //uint32_t friend_number = tox_event_friend_status_message_get_friend_number(event);
    const uint8_t *message = tox_event_friend_status_message_get_message(event);
    uint32_t message_length = tox_event_friend_status_message_get_message_length(event);

    ck_assert_msg(message_length == sizeof(STATUS_MESSAGE) &&
                  memcmp(message, STATUS_MESSAGE, sizeof(STATUS_MESSAGE)) == 0,
                  "incorrect data in status callback");
    bool *status_updated = (bool *)user_data;
    *status_updated = true;
}

static void test_set_status_message(void)
{
    printf("initialising 2 toxes\n");
    uint32_t index[] = { 1, 2 };
    const time_t cur_time = time(nullptr);
    Tox *const tox1 = tox_new_log(nullptr, nullptr, &index[0]);
    Tox *const tox2 = tox_new_log(nullptr, nullptr, &index[1]);

    ck_assert_msg(tox1 && tox2, "failed to create 2 tox instances");

    // we only run events on tox2 in this test case
    tox_events_init(tox2);

    Tox_Dispatch *dispatch2 = tox_dispatch_new(nullptr);
    ck_assert(dispatch2 != nullptr);

    printf("tox1 adds tox2 as friend, tox2 adds tox1\n");
    uint8_t public_key[TOX_PUBLIC_KEY_SIZE];
    tox_self_get_public_key(tox2, public_key);
    tox_friend_add_norequest(tox1, public_key, nullptr);
    tox_self_get_public_key(tox1, public_key);
    tox_friend_add_norequest(tox2, public_key, nullptr);

    printf("bootstrapping tox2 off tox1\n");
    uint8_t dht_key[TOX_PUBLIC_KEY_SIZE];
    tox_self_get_dht_id(tox1, dht_key);
    const uint16_t dht_port = tox_self_get_udp_port(tox1, nullptr);

    tox_bootstrap(tox2, "localhost", dht_port, dht_key, nullptr);

    do {
        tox_iterate(tox1, nullptr);

        Tox_Err_Events_Iterate err = TOX_ERR_EVENTS_ITERATE_OK;
        Tox_Events *events = tox_events_iterate(tox2, true, &err);
        ck_assert(err == TOX_ERR_EVENTS_ITERATE_OK);
        //tox_dispatch_invoke(dispatch2, events, nullptr);
        tox_events_free(events);

        c_sleep(ITERATION_INTERVAL);
    } while (tox_self_get_connection_status(tox1) == TOX_CONNECTION_NONE ||
             tox_self_get_connection_status(tox2) == TOX_CONNECTION_NONE);

    printf("toxes are online, took %lu seconds\n", (unsigned long)(time(nullptr) - cur_time));
    const time_t con_time = time(nullptr);

    do {
        tox_iterate(tox1, nullptr);

        Tox_Err_Events_Iterate err = TOX_ERR_EVENTS_ITERATE_OK;
        Tox_Events *events = tox_events_iterate(tox2, true, &err);
        ck_assert(err == TOX_ERR_EVENTS_ITERATE_OK);
        //tox_dispatch_invoke(dispatch2, events, nullptr);
        tox_events_free(events);

        c_sleep(ITERATION_INTERVAL);
    } while (tox_friend_get_connection_status(tox1, 0, nullptr) != TOX_CONNECTION_UDP ||
             tox_friend_get_connection_status(tox2, 0, nullptr) != TOX_CONNECTION_UDP);

    printf("tox clients connected took %lu seconds\n", (unsigned long)(time(nullptr) - con_time));

    tox_events_callback_friend_status_message(dispatch2, status_callback);
    Tox_Err_Set_Info err_n;
    bool ret = tox_self_set_status_message(tox1, (const uint8_t *)STATUS_MESSAGE, sizeof(STATUS_MESSAGE),
                                           &err_n);
    ck_assert_msg(ret && err_n == TOX_ERR_SET_INFO_OK, "tox_self_set_status_message failed because %u\n", err_n);

    bool status_updated = false;

    do {
        tox_iterate(tox1, nullptr);

        Tox_Err_Events_Iterate err = TOX_ERR_EVENTS_ITERATE_OK;
        Tox_Events *events = tox_events_iterate(tox2, true, &err);
        ck_assert(err == TOX_ERR_EVENTS_ITERATE_OK);
        tox_dispatch_invoke(dispatch2, events, &status_updated);
        tox_events_free(events);

        c_sleep(ITERATION_INTERVAL);
    } while (!status_updated);

    ck_assert_msg(tox_friend_get_status_message_size(tox2, 0, nullptr) == sizeof(STATUS_MESSAGE),
                  "status message length not correct");
    uint8_t cmp_status[sizeof(STATUS_MESSAGE)];
    tox_friend_get_status_message(tox2, 0, cmp_status, nullptr);
    ck_assert_msg(memcmp(cmp_status, STATUS_MESSAGE, sizeof(STATUS_MESSAGE)) == 0,
                  "status message not correct");

    printf("test_set_status_message succeeded, took %lu seconds\n", (unsigned long)(time(nullptr) - cur_time));

    tox_dispatch_free(dispatch2);

    tox_kill(tox1);
    tox_kill(tox2);
}

int main(void)
{
    setvbuf(stdout, nullptr, _IONBF, 0);

    test_set_status_message();
    return 0;
}
