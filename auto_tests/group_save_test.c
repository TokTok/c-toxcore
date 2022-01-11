/*
 * Tests that we can save a groupchat and load a groupchat with the saved data.
 */

#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>

typedef struct State {
    uint32_t index;
    uint64_t clock;
    size_t   peers;
} State;

#include "run_auto_test.h"

#define NUM_GROUP_TOXES 2
#define GROUP_NAME "The Test Chamber"
#define GROUP_NAME_LEN (sizeof(GROUP_NAME) - 1)
#define TOPIC "They're waiting for you Jordan..."
#define TOPIC_LEN (sizeof(TOPIC) - 1)
#define NEW_PRIV_STATE TOX_GROUP_PRIVACY_STATE_PRIVATE
#define PASSWORD "password123"
#define PASS_LEN (sizeof(PASSWORD) - 1)
#define PEER_LIMIT 69

static void group_invite_handler(Tox *tox, uint32_t friend_number, const uint8_t *invite_data, size_t length,
                                 const uint8_t *group_name, size_t group_name_length, void *user_data)
{

    TOX_ERR_GROUP_INVITE_ACCEPT err_accept;
    tox_group_invite_accept(tox, friend_number, invite_data, length, (const uint8_t *)"test2", 5,
                            nullptr, 0, &err_accept);
    ck_assert(err_accept == TOX_ERR_GROUP_INVITE_ACCEPT_OK);

}

static void group_peer_join_handler(Tox *tox, uint32_t group_number, uint32_t peer_id, void *user_data)
{
    State *state = (State *)user_data;
    ck_assert(state != nullptr);
    ++state->peers;
}

/* Checks that group has the same state according to the above defines
 *
 * Returns 0 if state is correct.
 * Returns a value < 0 if state is incorrect.
 */
static int has_correct_state(Tox *tox, uint32_t group_number, const uint8_t *expected_chat_id)
{
    TOX_ERR_GROUP_STATE_QUERIES query_err;

    TOX_GROUP_PRIVACY_STATE priv_state = tox_group_get_privacy_state(tox, group_number, &query_err);
    ck_assert(query_err == TOX_ERR_GROUP_STATE_QUERIES_OK);

    if (priv_state != NEW_PRIV_STATE) {
        return -1;
    }

    size_t pass_len = tox_group_get_password_size(tox, group_number, &query_err);
    ck_assert(query_err == TOX_ERR_GROUP_STATE_QUERIES_OK);

    if (pass_len != PASS_LEN) {
        return -2;
    }

    uint8_t password[TOX_GROUP_MAX_PASSWORD_SIZE];
    tox_group_get_password(tox, group_number, password, &query_err);
    ck_assert(query_err == TOX_ERR_GROUP_STATE_QUERIES_OK);

    if (memcmp(password, PASSWORD, pass_len) != 0) {
        return -3;
    }

    size_t gname_len = tox_group_get_name_size(tox, group_number, &query_err);
    ck_assert(query_err == TOX_ERR_GROUP_STATE_QUERIES_OK);

    if (gname_len != GROUP_NAME_LEN) {
        return -4;
    }

    uint8_t group_name[TOX_GROUP_MAX_GROUP_NAME_LENGTH];
    tox_group_get_name(tox, group_number, group_name, &query_err);

    if (memcmp(group_name, GROUP_NAME, gname_len) != 0) {
        return -5;
    }

    if (tox_group_get_peer_limit(tox, group_number, nullptr) != PEER_LIMIT) {
        return -6;
    }

    TOX_GROUP_TOPIC_LOCK topic_lock = tox_group_get_topic_lock(tox, group_number, &query_err);
    ck_assert(query_err == TOX_ERR_GROUP_STATE_QUERIES_OK);

    if (topic_lock != TOX_GROUP_TOPIC_LOCK_DISABLED) {
        return -7;
    }

    TOX_ERR_GROUP_STATE_QUERIES id_err;
    uint8_t chat_id[TOX_GROUP_CHAT_ID_SIZE];
    tox_group_get_chat_id(tox, group_number, chat_id, &id_err);

    ck_assert(id_err == TOX_ERR_GROUP_STATE_QUERIES_OK);

    if (memcmp(chat_id, expected_chat_id, TOX_GROUP_CHAT_ID_SIZE) != 0) {
        return -8;
    }

    return 0;
}

static void group_save_test(Tox **toxes, State *state)
{
#ifndef VANILLA_NACL
    ck_assert_msg(NUM_GROUP_TOXES > 1, "NUM_GROUP_TOXES is too small: %d", NUM_GROUP_TOXES);

    for (size_t i = 0; i < NUM_GROUP_TOXES; ++i) {
        tox_callback_group_invite(toxes[i], group_invite_handler);
        tox_callback_group_peer_join(toxes[i], group_peer_join_handler);
    }

    TOX_ERR_GROUP_NEW err_new;
    uint32_t group_number = tox_group_new(toxes[0], TOX_GROUP_PRIVACY_STATE_PRIVATE, (const uint8_t *)GROUP_NAME,
                                          GROUP_NAME_LEN, (const uint8_t *)"test", 4, &err_new);

    ck_assert(err_new == TOX_ERR_GROUP_NEW_OK);

    TOX_ERR_GROUP_STATE_QUERIES id_err;
    uint8_t chat_id[TOX_GROUP_CHAT_ID_SIZE];
    tox_group_get_chat_id(toxes[0], group_number, chat_id, &id_err);

    ck_assert(id_err == TOX_ERR_GROUP_STATE_QUERIES_OK);

    TOX_ERR_GROUP_INVITE_FRIEND err_invite;
    tox_group_invite_friend(toxes[0], group_number, 0, &err_invite);

    ck_assert(err_invite == TOX_ERR_GROUP_INVITE_FRIEND_OK);

    while (!state[0].peers && !state[1].peers) {
        iterate_all_wait(NUM_GROUP_TOXES, toxes, state, ITERATION_INTERVAL);
    }

    printf("tox0 invites tox1 to group\n");

    // change group state
    TOX_ERR_GROUP_TOPIC_SET top_err;
    tox_group_set_topic(toxes[0], group_number, (const uint8_t *)TOPIC, TOPIC_LEN, &top_err);
    ck_assert(top_err == TOX_ERR_GROUP_TOPIC_SET_OK);

    TOX_ERR_GROUP_FOUNDER_SET_TOPIC_LOCK lock_set_err;
    tox_group_founder_set_topic_lock(toxes[0], group_number, TOX_GROUP_TOPIC_LOCK_DISABLED, &lock_set_err);
    ck_assert(lock_set_err == TOX_ERR_GROUP_FOUNDER_SET_TOPIC_LOCK_OK);

    TOX_ERR_GROUP_FOUNDER_SET_PRIVACY_STATE priv_err;
    tox_group_founder_set_privacy_state(toxes[0], group_number, NEW_PRIV_STATE, &priv_err);
    ck_assert(priv_err == TOX_ERR_GROUP_FOUNDER_SET_PRIVACY_STATE_OK);

    TOX_ERR_GROUP_FOUNDER_SET_PASSWORD pass_set_err;
    tox_group_founder_set_password(toxes[0], group_number, (const uint8_t *)PASSWORD, PASS_LEN, &pass_set_err);
    ck_assert(pass_set_err == TOX_ERR_GROUP_FOUNDER_SET_PASSWORD_OK);

    TOX_ERR_GROUP_FOUNDER_SET_PEER_LIMIT limit_set_err;
    tox_group_founder_set_peer_limit(toxes[0], group_number, PEER_LIMIT, &limit_set_err);
    ck_assert(limit_set_err == TOX_ERR_GROUP_FOUNDER_SET_PEER_LIMIT_OK);

    iterate_all_wait(NUM_GROUP_TOXES, toxes, state, ITERATION_INTERVAL);

    printf("tox0 changes group state\n");

    size_t save_length = tox_get_savedata_size(toxes[0]);

    uint8_t *save = (uint8_t *)malloc(save_length);

    ck_assert(save != nullptr);

    tox_get_savedata(toxes[0], save);

    for (size_t i = 0; i < NUM_GROUP_TOXES; i++) {
        tox_group_leave(toxes[i], group_number, nullptr, 0, nullptr);
    }

    struct Tox_Options *const options = tox_options_new(nullptr);
    tox_options_set_savedata_type(options, TOX_SAVEDATA_TYPE_TOX_SAVE);
    tox_options_set_savedata_data(options, save, save_length);

    Tox *new_tox = tox_new_log(options, nullptr, nullptr);
    ck_assert(new_tox != nullptr);

    printf("tox0 saves group and reloads client\n");

    int ret = has_correct_state(new_tox, group_number, chat_id);
    ck_assert_msg(ret == 0, "incorrect state: %d", ret);

    tox_group_leave(new_tox, group_number, nullptr, 0, nullptr);

    free(save);
    tox_options_free(options);
    tox_kill(new_tox);

    printf("All tests passed!\n");
#endif  // VANILLA_NACL
}

int main(void)
{
    setvbuf(stdout, nullptr, _IONBF, 0);

    run_auto_test(nullptr, NUM_GROUP_TOXES, group_save_test, false);

    return 0;
}

#undef NUM_GROUP_TOXES
#undef GROUP_NAME
#undef GROUP_NAME_LEN
#undef TOPIC
#undef TOPIC_LEN
#undef NEW_PRIV_STATE
#undef PASSWORD
#undef PASS_LEN
#undef PEER_LIMIT

