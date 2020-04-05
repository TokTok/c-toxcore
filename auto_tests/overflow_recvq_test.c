/* Try to overflow the net_crypto packet buffer.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdint.h>

typedef struct State {
    uint32_t recv_count;
} State;

#include "run_auto_test.h"

#define NUM_MSGS 40000

static void handle_friend_message(Tox *tox, uint32_t friend_number, Tox_Message_Type type,
                                  const uint8_t *message, size_t length, void *user_data)
{
    const AutoTox *autotox = (AutoTox *)user_data;
    State *state = (State *)autotox->state;
    state->recv_count++;
}

static void net_crypto_overflow_test(AutoTox *autotoxes)
{
    tox_callback_friend_message(autotoxes[0].tox, handle_friend_message);

    printf("sending many messages to tox0\n");

    for (uint32_t tox_index = 1; tox_index < 3; tox_index++) {
        for (uint32_t i = 0; i < NUM_MSGS; i++) {
            uint8_t message[128] = {0};
            snprintf((char *)message, sizeof(message), "%u-%u", tox_index, i);

            Tox_Err_Friend_Send_Message err;
            tox_friend_send_message(autotoxes[tox_index].tox, 0, TOX_MESSAGE_TYPE_NORMAL, message, sizeof message, &err);

            if (err == TOX_ERR_FRIEND_SEND_MESSAGE_SENDQ) {
                printf("tox%u sent %u messages to friend 0\n", tox_index, i);
                break;
            }

            ck_assert_msg(err == TOX_ERR_FRIEND_SEND_MESSAGE_OK,
                          "tox%u failed to send message number %u: %d", tox_index, i, err);
        }
    }

    // TODO(iphydf): Wait until all messages have arrived. Currently, not all
    // messages arrive, so this test would always fail.
    for (uint32_t i = 0; i < 200; i++) {
        iterate_all_wait(3, autotoxes, ITERATION_INTERVAL);
    }

    printf("tox%u received %u messages\n", autotoxes[0].index, ((State *)autotoxes[0].state)->recv_count);
}

int main(void)
{
    setvbuf(stdout, nullptr, _IONBF, 0);

    run_auto_test(3, net_crypto_overflow_test, sizeof(State), &default_run_auto_options);
    return 0;
}
