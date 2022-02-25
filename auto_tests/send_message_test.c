/* Tests that we can send messages to friends.
 */

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

typedef struct State {
    bool message_received;
} State;

#include "auto_test_support.h"

#define MESSAGE_FILLER 'G'

static void message_callback(
    Tox *m, const Tox_Event_Friend_Message *event, void *user_data)
{
    const AutoTox *autotox = (AutoTox *)user_data;
    State *state = (State *)autotox->state;

    if (tox_event_friend_message_get_type(event) != TOX_MESSAGE_TYPE_NORMAL) {
        ck_abort_msg("Bad type");
    }

    const size_t cmp_msg_len = tox_max_message_length();
    uint8_t *cmp_msg = (uint8_t *)malloc(cmp_msg_len);
    ck_assert(cmp_msg != nullptr);
    memset(cmp_msg, MESSAGE_FILLER, cmp_msg_len);

    if (tox_event_friend_message_get_message_length(event) == tox_max_message_length() &&
            memcmp(tox_event_friend_message_get_message(event), cmp_msg, cmp_msg_len) == 0) {
        state->message_received = true;
    }

    free(cmp_msg);
}

static void send_message_test(AutoTox *autotoxes)
{
    const size_t msgs_len = tox_max_message_length() + 1;
    uint8_t *msgs = (uint8_t *)malloc(msgs_len);
    memset(msgs, MESSAGE_FILLER, msgs_len);

    Tox_Err_Friend_Send_Message errm;
    tox_friend_send_message(autotoxes[0].tox, 0, TOX_MESSAGE_TYPE_NORMAL, msgs, msgs_len, &errm);
    ck_assert_msg(errm == TOX_ERR_FRIEND_SEND_MESSAGE_TOO_LONG, "tox_max_message_length() is too small? error=%d", errm);

    tox_friend_send_message(autotoxes[0].tox, 0, TOX_MESSAGE_TYPE_NORMAL, msgs, tox_max_message_length(), &errm);
    ck_assert_msg(errm == TOX_ERR_FRIEND_SEND_MESSAGE_OK, "tox_max_message_length() is too big? error=%d", errm);

    free(msgs);

    do {
        iterate_all_wait(autotoxes, 2, ITERATION_INTERVAL);
    } while (!((State *)autotoxes[1].state)->message_received);
}

int main(void)
{
    setvbuf(stdout, nullptr, _IONBF, 0);

    Tox_Dispatch *dispatch = tox_dispatch_new(nullptr);
    ck_assert(dispatch != nullptr);
    tox_events_callback_friend_message(dispatch, &message_callback);

    struct Tox_Options *tox_options = tox_options_new(nullptr);
    ck_assert(tox_options != nullptr);

    Run_Auto_Options options = default_run_auto_options();
    options.graph = GRAPH_LINEAR;
    tox_options_set_ipv6_enabled(tox_options, true);
    run_auto_test(tox_options, 2, send_message_test, sizeof(State), dispatch, &options);

    tox_options_set_ipv6_enabled(tox_options, false);
    run_auto_test(tox_options, 2, send_message_test, sizeof(State), dispatch, &options);

    tox_options_free(tox_options);
    tox_dispatch_free(dispatch);

    return 0;
}
