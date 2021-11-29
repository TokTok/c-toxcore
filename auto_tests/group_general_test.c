/*
 * Tests that we can connect to a public group chat through the DHT and make basic queries
 * about the group, other peers, and ourselves.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

typedef struct State {
    uint32_t index;
    uint64_t clock;
    bool peer_joined;
    bool self_joined;
    bool peer_exited;
    bool peer_nick;
    bool peer_status;
    uint32_t peer_id;
} State;

#include "run_auto_test.h"

#define NUM_GROUP_TOXES 2

#define GROUP_NAME "NASA Headquarters"
#define GROUP_NAME_LEN (sizeof(GROUP_NAME) - 1)

#define PEER0_NICK "Lois"
#define PEER0_NICK_LEN (sizeof(PEER0_NICK) - 1)

#define PEER0_NICK2 "Terry Davis"
#define PEER0_NICK2_LEN (sizeof(PEER0_NICK2) - 1)

#define PEER1_NICK "Bran"
#define PEER1_NICK_LEN (sizeof(PEER1_NICK) - 1)

#define EXIT_MESSAGE "Goodbye world"
#define EXIT_MESSAGE_LEN (sizeof(EXIT_MESSAGE) - 1)

#define PEER_LIMIT 20

static bool all_group_peers_connected(uint32_t tox_count, Tox **toxes, uint32_t groupnumber, size_t name_length)
{
    for (size_t i = 0; i < tox_count; ++i) {
        // make sure we got an invite response
        if (tox_group_get_name_size(toxes[i], groupnumber, nullptr) != name_length) {
            return false;
        }

        // make sure we got a sync response
        if (tox_group_get_peer_limit(toxes[i], groupnumber, nullptr) != PEER_LIMIT) {
            return false;
        }

        // make sure we're actually connected
        if (!tox_group_is_connected(toxes[i], groupnumber, nullptr)) {
            return false;
        }
    }

    return true;
}

static void group_join_fail_handler(Tox *tox, uint32_t groupnumber, TOX_GROUP_JOIN_FAIL fail_type, void *user_data)
{
    fprintf(stderr, "Failed to join group: %d", fail_type);
}

static void group_peer_join_handler(Tox *tox, uint32_t groupnumber, uint32_t peer_id, void *user_data)
{
    State *state = (State *)user_data;
    ck_assert(state != nullptr);

    // we also do a connection test here for fun
    TOX_ERR_GROUP_PEER_QUERY pq_err;
    TOX_CONNECTION connection_status = tox_group_peer_get_connection_status(tox, groupnumber, peer_id, &pq_err);
    ck_assert(pq_err == TOX_ERR_GROUP_PEER_QUERY_OK);
    ck_assert(connection_status != TOX_CONNECTION_NONE);

    state->peer_id = peer_id;
    state->peer_joined = true;
}

static void group_peer_self_join_handler(Tox *tox, uint32_t groupnumber, void *user_data)
{
    State *state = (State *)user_data;
    ck_assert(state != nullptr);
    state->self_joined = true;
}

static void group_peer_exit_handler(Tox *tox, uint32_t groupnumber, uint32_t peer_id, TOX_GROUP_EXIT_TYPE exit_type,
                                    const uint8_t *name, size_t name_length, const uint8_t *part_message,
                                    size_t length, void *user_data)
{
    State *state = (State *)user_data;
    ck_assert(state != nullptr);
    ck_assert(length == EXIT_MESSAGE_LEN);
    ck_assert(memcmp(part_message, EXIT_MESSAGE, length) == 0);
    state->peer_exited = true;
}

static void group_peer_name_handler(Tox *tox, uint32_t groupnumber, uint32_t peer_id, const uint8_t *name,
                                    size_t length, void *user_data)
{
    State *state = (State *)user_data;
    ck_assert(state != nullptr);

    // note: we already test the name_get api call elsewhere

    ck_assert(length == PEER0_NICK2_LEN);
    ck_assert(memcmp(name, PEER0_NICK2, length) == 0);

    state->peer_nick = true;
}

static void group_peer_status_handler(Tox *tox, uint32_t groupnumber, uint32_t peer_id, TOX_USER_STATUS status,
                                      void *user_data)
{
    State *state = (State *)user_data;
    ck_assert(state != nullptr);

    TOX_ERR_GROUP_PEER_QUERY err;
    TOX_USER_STATUS cur_status = tox_group_peer_get_status(tox, groupnumber, peer_id, &err);

    ck_assert_msg(cur_status == status, "%d, %d", cur_status, status);
    ck_assert(status == TOX_USER_STATUS_BUSY);

    state->peer_status = true;
}

static void group_announce_test(Tox **toxes, State *state)
{
#ifndef VANILLA_NACL
    ck_assert_msg(NUM_GROUP_TOXES == 2, "NUM_GROUP_TOXES needs to be 2");

    tox_callback_group_join_fail(toxes[0], group_join_fail_handler);
    tox_callback_group_peer_join(toxes[1], group_peer_join_handler);
    tox_callback_group_self_join(toxes[0], group_peer_self_join_handler);
    tox_callback_group_self_join(toxes[1], group_peer_self_join_handler);
    tox_callback_group_peer_name(toxes[1], group_peer_name_handler);
    tox_callback_group_peer_status(toxes[1], group_peer_status_handler);
    tox_callback_group_peer_exit(toxes[1], group_peer_exit_handler);

    // tox0 makes new group.
    TOX_ERR_GROUP_NEW err_new;
    uint32_t groupnumber = tox_group_new(toxes[0], TOX_GROUP_PRIVACY_STATE_PUBLIC, (const uint8_t *) GROUP_NAME,
                                         GROUP_NAME_LEN, (const uint8_t *)PEER0_NICK, PEER0_NICK_LEN,
                                         &err_new);
    ck_assert(err_new == TOX_ERR_GROUP_NEW_OK);

    iterate_all_wait(NUM_GROUP_TOXES, toxes, state, ITERATION_INTERVAL);

    // changes the state (for sync check purposes)
    TOX_ERR_GROUP_FOUNDER_SET_PEER_LIMIT limit_set_err;
    tox_group_founder_set_peer_limit(toxes[0], groupnumber, PEER_LIMIT, &limit_set_err);
    ck_assert_msg(limit_set_err == TOX_ERR_GROUP_FOUNDER_SET_PEER_LIMIT_OK, "failed to set peer limit: %d", limit_set_err);

    // get the chat id of the new group.
    TOX_ERR_GROUP_STATE_QUERIES err_id;
    uint8_t chat_id[TOX_GROUP_CHAT_ID_SIZE];
    tox_group_get_chat_id(toxes[0], groupnumber, chat_id, &err_id);
    ck_assert(err_id == TOX_ERR_GROUP_STATE_QUERIES_OK);

    // tox1 joins it.
    TOX_ERR_GROUP_JOIN err_join;
    tox_group_join(toxes[1], chat_id, (const uint8_t *)PEER1_NICK, PEER1_NICK_LEN, nullptr, 0, &err_join);
    ck_assert(err_join == TOX_ERR_GROUP_JOIN_OK);

    // peers see each other and themselves join
    while (!state[0].peer_joined && !state[1].peer_joined && !state[0].self_joined && !state[1].self_joined) {
        iterate_all_wait(NUM_GROUP_TOXES, toxes, state, ITERATION_INTERVAL);
    }

    // wait for group syncing to finish
    while (!all_group_peers_connected(NUM_GROUP_TOXES, toxes, groupnumber, GROUP_NAME_LEN)) {
        iterate_all_wait(NUM_GROUP_TOXES, toxes, state, ITERATION_INTERVAL);
    }

    for (size_t i = 0; i < 200; ++i) {
        iterate_all_wait(NUM_GROUP_TOXES, toxes, state, ITERATION_INTERVAL);
    }

    fprintf(stderr, "Peers connected to group\n");

    // tox 0 changes name
    TOX_ERR_GROUP_SELF_NAME_SET n_err;
    tox_group_self_set_name(toxes[0], groupnumber, (const uint8_t *)PEER0_NICK2, PEER0_NICK2_LEN, &n_err);
    ck_assert(n_err == TOX_ERR_GROUP_SELF_NAME_SET_OK);

    iterate_all_wait(NUM_GROUP_TOXES, toxes, state, ITERATION_INTERVAL);

    TOX_ERR_GROUP_SELF_QUERY sq_err;
    size_t self_length = tox_group_self_get_name_size(toxes[0], groupnumber, &sq_err);
    ck_assert(sq_err == TOX_ERR_GROUP_SELF_QUERY_OK);
    ck_assert(self_length == PEER0_NICK2_LEN);

    uint8_t self_name[TOX_MAX_NAME_LENGTH];
    tox_group_self_get_name(toxes[0], groupnumber, self_name, &sq_err);
    ck_assert(sq_err == TOX_ERR_GROUP_SELF_QUERY_OK);
    ck_assert(memcmp(self_name, PEER0_NICK2, self_length) == 0);

    fprintf(stderr, "Peer 0 successfully changed nick\n");

    // tox 0 changes status
    TOX_ERR_GROUP_SELF_STATUS_SET s_err;
    tox_group_self_set_status(toxes[0], groupnumber, TOX_USER_STATUS_BUSY, &s_err);
    ck_assert(s_err == TOX_ERR_GROUP_SELF_STATUS_SET_OK);

    iterate_all_wait(NUM_GROUP_TOXES, toxes, state, ITERATION_INTERVAL);

    TOX_USER_STATUS self_status = tox_group_self_get_status(toxes[0], groupnumber, &sq_err);
    ck_assert(sq_err == TOX_ERR_GROUP_SELF_QUERY_OK);
    ck_assert(self_status == TOX_USER_STATUS_BUSY);

    fprintf(stderr, "Peer 0 successfully changed status\n");

    while (!state[1].peer_nick && !state[1].peer_status) {
        iterate_all_wait(NUM_GROUP_TOXES, toxes, state, ITERATION_INTERVAL);
    }

    // tox 0 and tox 1 should see the same public key for tox 0
    uint8_t tox0_self_pk[TOX_GROUP_PEER_PUBLIC_KEY_SIZE];
    tox_group_self_get_public_key(toxes[0], groupnumber, tox0_self_pk, &sq_err);
    ck_assert(sq_err == TOX_ERR_GROUP_SELF_QUERY_OK);

    TOX_ERR_GROUP_PEER_QUERY pq_err;
    uint8_t tox0_pk_query[TOX_GROUP_PEER_PUBLIC_KEY_SIZE];
    tox_group_peer_get_public_key(toxes[1], groupnumber, state[1].peer_id, tox0_pk_query, &pq_err);
    ck_assert(pq_err == TOX_ERR_GROUP_PEER_QUERY_OK);
    ck_assert(memcmp(tox0_pk_query, tox0_self_pk, TOX_GROUP_PEER_PUBLIC_KEY_SIZE) == 0);

    TOX_ERR_GROUP_LEAVE err_exit;
    tox_group_leave(toxes[0], groupnumber, (const uint8_t *)EXIT_MESSAGE, EXIT_MESSAGE_LEN, &err_exit);
    ck_assert(err_exit == TOX_ERR_GROUP_LEAVE_OK);

    while (!state[1].peer_exited) {
        iterate_all_wait(NUM_GROUP_TOXES, toxes, state, ITERATION_INTERVAL);
    }

    tox_group_leave(toxes[1], groupnumber, nullptr, 0, &err_exit);
    ck_assert(err_exit == TOX_ERR_GROUP_LEAVE_OK);

    printf("All tests passed!\n");
#endif  // VANILLA_NACL
}

int main(void)
{
    setvbuf(stdout, nullptr, _IONBF, 0);

    run_auto_test(NUM_GROUP_TOXES, group_announce_test, false);
    return 0;
}

#undef NUM_GROUP_TOXES
#undef PEER1_NICK
#undef PEER0_NICK
#undef PEER0_NICK_LEN
#undef PEER1_NICK_LEN
#undef GROUP_NAME
#undef GROUP_NAME_LEN
#undef PEER_LIMIT
