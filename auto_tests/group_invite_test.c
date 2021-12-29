/*
 * Tests group invites as well as join restrictions, including password protection, privacy state,
 * and peer limits. Ensures sure that the peer being blocked from joining successfully receives
 * the invite fail packet with the correct message.
 *
 * This test also checks that many peers can successfully join the group simultaneously.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <string.h>
#include <stdio.h>
#include <stdint.h>

#include "check_compat.h"

typedef struct State {
    uint32_t index;
    uint64_t clock;
    uint32_t num_peers;
    bool peer_limit_fail;
    bool password_fail;
    bool connected;
    size_t messages_received;
} State;

#include "run_auto_test.h"

#define NUM_GROUP_TOXES 15  // must be > 7

#define PASSWORD "dadada"
#define PASS_LEN (sizeof(PASSWORD) - 1)

#define WRONG_PASS "dadadada"
#define WRONG_PASS_LEN (sizeof(WRONG_PASS) - 1)

#define SECRET_CODE "RONALD MCDONALD"
#define SECRET_CODE_LEN (sizeof(SECRET_CODE) - 1)

static bool group_has_full_graph(Tox **toxes, State *state, uint32_t group_number, uint32_t expected_peer_count)
{
    for (size_t i = 7; i < NUM_GROUP_TOXES; ++i) {
        if (state[i].num_peers != expected_peer_count) {
            return false;
        }
    }

    if (state[0].num_peers != expected_peer_count || state[1].num_peers != expected_peer_count
            || state[5].num_peers != expected_peer_count) {
        return false;
    }


    return true;
}

static bool group_received_all_messages(Tox **toxes, State *state, uint32_t group_number, size_t expected_msg_count)
{
    for (size_t i = 7; i < NUM_GROUP_TOXES; ++i) {
        if (state[i].messages_received != expected_msg_count) {
            return false;
        }
    }

    if (state[0].messages_received != expected_msg_count || state[1].messages_received != expected_msg_count
            || state[5].messages_received != expected_msg_count) {
        return false;
    }


    return true;
}

static void group_join_fail_handler(Tox *tox, uint32_t group_number, TOX_GROUP_JOIN_FAIL fail_type, void *user_data)
{
    State *state = (State *)user_data;
    ck_assert(state != nullptr);

    switch (fail_type) {
        case TOX_GROUP_JOIN_FAIL_PEER_LIMIT: {
            state->peer_limit_fail = true;
            break;
        }

        case TOX_GROUP_JOIN_FAIL_INVALID_PASSWORD: {
            state->password_fail = true;
            break;
        }

        case TOX_GROUP_JOIN_FAIL_UNKNOWN:

        // intentional fallthrough
        default: {
            ck_assert_msg(false, "Got unknown join fail");
            return;
        }
    }
}

static void group_message_handler(Tox *tox, uint32_t groupnumber, uint32_t peer_id, TOX_MESSAGE_TYPE type,
                                  const uint8_t *message, size_t length, void *user_data)
{
    State *state = (State *)user_data;
    ck_assert(state != nullptr);

    ck_assert(length == SECRET_CODE_LEN);
    ck_assert(memcmp(message, SECRET_CODE, length) == 0);

    state->messages_received++;
}

static void group_self_join_handler(Tox *tox, uint32_t group_number, void *user_data)
{
    State *state = (State *)user_data;
    ck_assert(state != nullptr);

    state->connected = true;
}

static void group_peer_join_handler(Tox *tox, uint32_t group_number, uint32_t peer_id, void *user_data)
{
    State *state = (State *)user_data;
    ck_assert(state != nullptr);

    ++state->num_peers;
    ck_assert(state->num_peers < NUM_GROUP_TOXES);
}

static void group_invite_test(Tox **toxes, State *state)
{
#ifndef VANILLA_NACL
    ck_assert_msg(NUM_GROUP_TOXES > 7, "NUM_GROUP_TOXES is too small: %d", NUM_GROUP_TOXES);

    for (size_t i = 0; i < NUM_GROUP_TOXES; ++i) {
        tox_callback_group_peer_join(toxes[i], group_peer_join_handler);
        tox_callback_group_join_fail(toxes[i], group_join_fail_handler);
        tox_callback_group_self_join(toxes[i], group_self_join_handler);
        tox_callback_group_message(toxes[i], group_message_handler);
    }

    TOX_ERR_GROUP_NEW new_err;
    uint32_t groupnumber = tox_group_new(toxes[0], TOX_GROUP_PRIVACY_STATE_PUBLIC, (const uint8_t *)"test", 4,
                                         (const uint8_t *)"test", 4, &new_err);
    ck_assert_msg(new_err == TOX_ERR_GROUP_NEW_OK, "tox_group_new failed: %d", new_err);

    iterate_all_wait(NUM_GROUP_TOXES, toxes, state, ITERATION_INTERVAL);

    TOX_ERR_GROUP_STATE_QUERIES id_err;
    uint8_t chat_id[TOX_GROUP_CHAT_ID_SIZE];

    tox_group_get_chat_id(toxes[0], groupnumber, chat_id, &id_err);
    ck_assert_msg(id_err == TOX_ERR_GROUP_STATE_QUERIES_OK, "%d", id_err);

    // peer 1 joins public group with no password
    TOX_ERR_GROUP_JOIN join_err;
    tox_group_join(toxes[1], chat_id, (const uint8_t *)"Test", 4, nullptr, 0, &join_err);
    ck_assert_msg(join_err == TOX_ERR_GROUP_JOIN_OK, "%d", join_err);

    while (state[0].num_peers < 1) {
        iterate_all_wait(NUM_GROUP_TOXES, toxes, state, ITERATION_INTERVAL);
    }

    printf("Peer 1 joined group\n");

    // founder sets a password
    TOX_ERR_GROUP_FOUNDER_SET_PASSWORD pass_set_err;
    tox_group_founder_set_password(toxes[0], groupnumber, (const uint8_t *)PASSWORD, PASS_LEN, &pass_set_err);
    ck_assert_msg(pass_set_err == TOX_ERR_GROUP_FOUNDER_SET_PASSWORD_OK, "%d", pass_set_err);

    iterate_all_wait(NUM_GROUP_TOXES, toxes, state, 5000);

    // peer 2 attempts to join with no password
    tox_group_join(toxes[2], chat_id, (const uint8_t *)"Test", 4, nullptr, 0, &join_err);
    ck_assert_msg(join_err == TOX_ERR_GROUP_JOIN_OK, "%d", join_err);

    while (!state[2].password_fail) {
        iterate_all_wait(NUM_GROUP_TOXES, toxes, state, ITERATION_INTERVAL);
    }

    printf("Peer 2 successfully blocked with no password\n");

    // peer 3 attempts to join with invalid password
    tox_group_join(toxes[3], chat_id, (const uint8_t *)"Test", 4, (const uint8_t *)WRONG_PASS, WRONG_PASS_LEN, &join_err);
    ck_assert_msg(join_err == TOX_ERR_GROUP_JOIN_OK, "%d", join_err);

    while (!state[3].password_fail) {
        iterate_all_wait(NUM_GROUP_TOXES, toxes, state, ITERATION_INTERVAL);
    }

    printf("Peer 3 successfully blocked with invalid password\n");

    // founder sets peer limit to 1
    TOX_ERR_GROUP_FOUNDER_SET_PEER_LIMIT limit_set_err;
    tox_group_founder_set_peer_limit(toxes[0], groupnumber, 1, &limit_set_err);
    ck_assert_msg(limit_set_err == TOX_ERR_GROUP_FOUNDER_SET_PEER_LIMIT_OK, "%d", limit_set_err);

    iterate_all_wait(NUM_GROUP_TOXES, toxes, state, 5000);

    // peer 4 attempts to join with correct password
    tox_group_join(toxes[4], chat_id, (const uint8_t *)"Test", 4, (const uint8_t *)PASSWORD, PASS_LEN, &join_err);
    ck_assert_msg(join_err == TOX_ERR_GROUP_JOIN_OK, "%d", join_err);

    while (!state[4].peer_limit_fail) {
        iterate_all_wait(NUM_GROUP_TOXES, toxes, state, ITERATION_INTERVAL);
    }

    printf("Peer 4 successfully blocked from joining full group\n");

    // founder removes password and increases peer limit to 100
    tox_group_founder_set_password(toxes[0], groupnumber, nullptr, 0, &pass_set_err);
    ck_assert_msg(pass_set_err == TOX_ERR_GROUP_FOUNDER_SET_PASSWORD_OK, "%d", pass_set_err);

    tox_group_founder_set_peer_limit(toxes[0], groupnumber, 100, &limit_set_err);
    ck_assert_msg(limit_set_err == TOX_ERR_GROUP_FOUNDER_SET_PEER_LIMIT_OK, "%d", limit_set_err);

    iterate_all_wait(NUM_GROUP_TOXES, toxes, state, 5000);

    // peer 5 attempts to join group
    tox_group_join(toxes[5], chat_id, (const uint8_t *)"Test", 4, nullptr, 0, &join_err);
    ck_assert_msg(join_err == TOX_ERR_GROUP_JOIN_OK, "%d", join_err);

    while (!state[5].connected) {
        iterate_all_wait(NUM_GROUP_TOXES, toxes, state, ITERATION_INTERVAL);
    }

    printf("Peer 5 successfully joined the group\n");

    // founder makes group private
    TOX_ERR_GROUP_FOUNDER_SET_PRIVACY_STATE priv_err;
    tox_group_founder_set_privacy_state(toxes[0], groupnumber, TOX_GROUP_PRIVACY_STATE_PRIVATE, &priv_err);
    ck_assert_msg(priv_err == TOX_ERR_GROUP_FOUNDER_SET_PRIVACY_STATE_OK, "%d", priv_err);

    iterate_all_wait(NUM_GROUP_TOXES, toxes, state, 5000);

    // peer 6 attempts to join group via chat ID
    tox_group_join(toxes[6], chat_id, (const uint8_t *)"Test", 4, nullptr, 0, &join_err);
    ck_assert_msg(join_err == TOX_ERR_GROUP_JOIN_OK, "%d", join_err);

    // since we don't receive a fail packet in this case we just wait a while and check if we're in the group
    iterate_all_wait(NUM_GROUP_TOXES, toxes, state, 20000);

    ck_assert(!state[6].connected);

    printf("Peer 6 failed to join private group via chat ID\n");

    // founder makes group public again
    tox_group_founder_set_privacy_state(toxes[0], groupnumber, TOX_GROUP_PRIVACY_STATE_PUBLIC, &priv_err);
    ck_assert_msg(priv_err == TOX_ERR_GROUP_FOUNDER_SET_PRIVACY_STATE_OK, "%d", priv_err);

    iterate_all_wait(NUM_GROUP_TOXES, toxes, state, ITERATION_INTERVAL);

    const uint32_t num_new_peers = NUM_GROUP_TOXES - 7;
    printf("Connecting %d peers at the same time\n", num_new_peers);

    for (size_t i = 7; i < NUM_GROUP_TOXES; ++i) {
        tox_group_join(toxes[i], chat_id, (const uint8_t *)"Test", 4, nullptr, 0, &join_err);
        ck_assert_msg(join_err == TOX_ERR_GROUP_JOIN_OK, "%d", join_err);
    }

    const uint32_t expected_peer_count = num_new_peers + state[0].num_peers + 1;

    while (!group_has_full_graph(toxes, state, groupnumber, expected_peer_count)) {
        iterate_all_wait(NUM_GROUP_TOXES, toxes, state, ITERATION_INTERVAL);
    }

    printf("Every peer sees every other peer\n");

    for (size_t i = 0; i < NUM_GROUP_TOXES; ++i) {
        // don't error check this call because all the peers who couldn't join will
        // fail to send a message
        tox_group_send_message(toxes[i], groupnumber, TOX_MESSAGE_TYPE_NORMAL, (const uint8_t *)SECRET_CODE,
                               SECRET_CODE_LEN, nullptr);
    }

    while (!group_received_all_messages(toxes, state, groupnumber, expected_peer_count)) {
        iterate_all_wait(NUM_GROUP_TOXES, toxes, state, ITERATION_INTERVAL);
    }

    printf("Every present peer received a message from every other peer\n");

    for (size_t i = 0; i < NUM_GROUP_TOXES; ++i) {
        TOX_ERR_GROUP_LEAVE err_exit;
        tox_group_leave(toxes[i], groupnumber, nullptr, 0, &err_exit);
        ck_assert_msg(err_exit == TOX_ERR_GROUP_LEAVE_OK, "%d", err_exit);
    }

    printf("All tests passed!\n");

#endif // VANILLA_NACL
}

int main(void)
{
    setvbuf(stdout, nullptr, _IONBF, 0);

    run_auto_test(nullptr, NUM_GROUP_TOXES, group_invite_test, false);

    return 0;
}

#undef NUM_GROUP_TOXES
#undef PASSWORD
#undef PASS_LEN
#undef WRONG_PASS
#undef WRONG_PASS_LEN

