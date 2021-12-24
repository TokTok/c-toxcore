/*
 * Does a basic functionality test for TCP connections.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#define NUM_GROUP_TOXES 3
#define CODEWORD "RONALD MCDONALD"
#define CODEWORD_LEN (sizeof(CODEWORD) - 1)

typedef struct State {
    uint32_t index;
    uint64_t clock;
    size_t   num_peers;
    bool     got_code;
    uint32_t peer_id[NUM_GROUP_TOXES - 1];
} State;

#include "run_auto_test.h"

static void group_peer_join_handler(Tox *tox, uint32_t groupnumber, uint32_t peer_id, void *user_data)
{
    State *state = (State *)user_data;
    ck_assert(state != nullptr);
    ck_assert(state->num_peers < NUM_GROUP_TOXES - 1);

    state->peer_id[state->num_peers++] = peer_id;
}

static void group_private_message_handler(Tox *tox, uint32_t groupnumber, uint32_t peer_id, TOX_MESSAGE_TYPE type,
        const uint8_t *message, size_t length, void *user_data)
{
    State *state = (State *)user_data;
    ck_assert(state != nullptr);
    ck_assert(length == CODEWORD_LEN);
    ck_assert(memcmp(CODEWORD, message, length) == 0);

    state->got_code = true;
}

/*
 * We need different constants to make TCP run smoothly. TODO(Jfreegman): is this because of the group
 * implementation or just an autotest quirk?
 */
#define GROUP_ITERATION_INTERVAL 30
static void iterate_group(Tox **toxes, uint32_t num_toxes, State *state)
{
    for (uint32_t i = 0; i < num_toxes; i++) {
        tox_iterate(toxes[i], &state[i]);
        state[i].clock += GROUP_ITERATION_INTERVAL;
    }

    c_sleep(20);
}

static void group_tcp_test(Tox **toxes, State *state)
{
#ifndef VANILLA_NACL

    for (size_t i = 0; i < NUM_GROUP_TOXES; ++i) {
        tox_callback_group_peer_join(toxes[i], group_peer_join_handler);
        tox_callback_group_private_message(toxes[i], group_private_message_handler);
    }

    TOX_ERR_GROUP_NEW new_err;
    uint32_t groupnumber = tox_group_new(toxes[0], TOX_GROUP_PRIVACY_STATE_PUBLIC, (const uint8_t *)"test", 4,
                                         (const uint8_t *)"test", 4, &new_err);
    ck_assert_msg(new_err == TOX_ERR_GROUP_NEW_OK, "tox_group_new failed: %d", new_err);

    iterate_group(toxes, NUM_GROUP_TOXES, state);

    TOX_ERR_GROUP_STATE_QUERIES id_err;
    uint8_t chat_id[TOX_GROUP_CHAT_ID_SIZE];

    tox_group_get_chat_id(toxes[0], groupnumber, chat_id, &id_err);
    ck_assert_msg(id_err == TOX_ERR_GROUP_STATE_QUERIES_OK, "%d", id_err);

    printf("Tox 0 created new group...\n");

    for (size_t i = 1; i < NUM_GROUP_TOXES; ++i) {
        TOX_ERR_GROUP_JOIN jerr;
        tox_group_join(toxes[i], chat_id, (const uint8_t *)"test", 4, nullptr, 0, &jerr);
        ck_assert_msg(jerr == TOX_ERR_GROUP_JOIN_OK, "%d", jerr);
    }

    while (true) {
        iterate_group(toxes, NUM_GROUP_TOXES, state);

        size_t count = 0;

        for (size_t i = 0; i < NUM_GROUP_TOXES; ++i) {
            if (state[i].num_peers == NUM_GROUP_TOXES - 1) {
                ++count;
            }
        }

        if (count == NUM_GROUP_TOXES) {
            break;
        }
    }

    printf("%d peers connected\n", NUM_GROUP_TOXES);
    printf("Tox 0 sending secret code to all peers\n");

    for (size_t i = 0; i < NUM_GROUP_TOXES - 1; ++i) {
        TOX_ERR_GROUP_SEND_PRIVATE_MESSAGE perr;
        tox_group_send_private_message(toxes[0], groupnumber, state[0].peer_id[i], TOX_MESSAGE_TYPE_NORMAL,
                                       (const uint8_t *)CODEWORD, CODEWORD_LEN, &perr);
        ck_assert_msg(perr == TOX_ERR_GROUP_SEND_PRIVATE_MESSAGE_OK, "%d", perr);
    }

    while (true) {
        iterate_group(toxes, NUM_GROUP_TOXES, state);

        size_t count = 0;

        for (size_t i = 0; i < NUM_GROUP_TOXES; ++i) {
            if (state[i].got_code) {
                ++count;
            }
        }

        if (count == NUM_GROUP_TOXES - 1) {
            break;
        }
    }

    for (size_t i = 0; i < NUM_GROUP_TOXES; i++) {
        TOX_ERR_GROUP_LEAVE err_exit;
        tox_group_leave(toxes[i], groupnumber, nullptr, 0, &err_exit);
        ck_assert(err_exit == TOX_ERR_GROUP_LEAVE_OK);
    }

    printf("Test passed!\n");

#endif // VANILLA_NACL
}

int main(void)
{
    setvbuf(stdout, nullptr, _IONBF, 0);

    struct Tox_Options *options = (struct Tox_Options *)calloc(1, sizeof(struct Tox_Options));
    ck_assert(options != nullptr);

    tox_options_default(options);
    tox_options_set_udp_enabled(options, false);

    run_auto_test(options, NUM_GROUP_TOXES, group_tcp_test, false);

    tox_options_free(options);

    return 0;
}


