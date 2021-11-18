/*
 * Tests that we can successfully change the group state and that all peers in the group
 * receive the correct state changes.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include "../toxcore/tox.h"
#include "check_compat.h"

#define NUM_GROUP_TOXES 3

#define TOPIC "They're waiting for you Gordon...in the test chamber"
#define TOPIC_LEN (sizeof(TOPIC) - 1)

#define GROUP_NAME "The Test Chamber"
#define GROUP_NAME_LEN (sizeof(GROUP_NAME) - 1)

#define PEER0_NICK "Koresh"
#define PEER0_NICK_LEN  (sizeof(PEER0_NICK) - 1)

typedef struct State {
    uint32_t index;
    uint64_t clock;
    uint32_t peer_id;  // the id of the peer we set to observer
} State;

#include "run_auto_test.h"



static void group_peer_join_handler(Tox *tox, uint32_t group_number, uint32_t peer_id, void *user_data)
{
    if (user_data) {
        State *state = (State *)user_data;
        state->peer_id = peer_id;
    }
}

/* Sets group topic.
 *
 * Return 0 on success.
 * Return -1 on failure.
 */
static int set_topic(Tox *tox, uint32_t groupnumber, const char *topic, size_t length)
{
    TOX_ERR_GROUP_TOPIC_SET err;
    tox_group_set_topic(tox, groupnumber, (const uint8_t *)topic, length, &err);

    if (err != TOX_ERR_GROUP_TOPIC_SET_OK) {
        return -1;
    }

    return 0;
}

/* Returns 0 if group topic matches expected topic.
 * Returns a value < 0 on failure.
 */
static int check_topic(Tox *tox, uint32_t groupnumber, const char *expected_topic, size_t expected_length)
{
    TOX_ERR_GROUP_STATE_QUERIES query_err;
    size_t topic_length = tox_group_get_topic_size(tox, groupnumber, &query_err);

    if (query_err != TOX_ERR_GROUP_STATE_QUERIES_OK) {
        return -1;
    }

    if (expected_length != topic_length) {
        return -2;
    }

    uint8_t topic[TOX_GROUP_MAX_TOPIC_LENGTH];
    tox_group_get_topic(tox, groupnumber, topic, &query_err);

    if (query_err != TOX_ERR_GROUP_STATE_QUERIES_OK) {
        return -3;
    }

    if (memcmp(expected_topic, (const char *)topic, topic_length) != 0) {
        return -4;
    }

    return 0;
}

/* Waits for all peers in group to see the same topic */
static void wait_state_topic(Tox **toxes, State *state, uint32_t groupnumber, const char *topic, size_t length)
{
    while (1) {
        iterate_all_wait(NUM_GROUP_TOXES, toxes, state, ITERATION_INTERVAL);

        uint32_t count = 0;

        for (size_t i = 0; i < NUM_GROUP_TOXES; ++i) {
            int c_ret = check_topic(toxes[i], groupnumber, topic, length);

            if (c_ret == 0) {
                ++count;
            }
        }

        if (count == NUM_GROUP_TOXES) {
            break;
        }
    }

    fprintf(stderr, "All peers saw topic: %s\n", topic);
}

static void group_topic_test(Tox **toxes, State *state)
{
#ifndef VANILLA_NACL
    time_t cur_time = time(nullptr);

    ck_assert_msg(NUM_GROUP_TOXES >= 3, "NUM_GROUP_TOXES is too small: %d", NUM_GROUP_TOXES);

    for (size_t i = 0; i < NUM_GROUP_TOXES; ++i) {
        char name[16];
        snprintf(name, sizeof(name), "test-%zu", i);
        tox_self_set_name(toxes[i], (const uint8_t *)name, strlen(name), nullptr);

        uint8_t dht_key[TOX_PUBLIC_KEY_SIZE];
        tox_self_get_dht_id(toxes[0], dht_key);
        const uint16_t dht_port = tox_self_get_udp_port(toxes[0], nullptr);
        tox_bootstrap(toxes[i], "localhost", dht_port, dht_key, nullptr);

        iterate_all_wait(NUM_GROUP_TOXES, toxes, state, ITERATION_INTERVAL);
    }

    tox_callback_group_peer_join(toxes[0], group_peer_join_handler);

    uint32_t num_connected = 0;

    while (1) {
        iterate_all_wait(NUM_GROUP_TOXES, toxes, state, ITERATION_INTERVAL);

        for (size_t i = 0; i < NUM_GROUP_TOXES; ++i) {
            if (tox_self_get_connection_status(toxes[i])) {
                ++num_connected;
            }
        }

        if (num_connected == NUM_GROUP_TOXES) {
            break;
        }
    }

    printf("%u Tox instances connected after %u seconds!\n", num_connected, (unsigned)(time(nullptr) - cur_time));

    /* Tox1 creates a group and is the founder of a newly created group */
    TOX_ERR_GROUP_NEW new_err;
    uint32_t groupnumber = tox_group_new(toxes[0], TOX_GROUP_PRIVACY_STATE_PUBLIC, (const uint8_t *)GROUP_NAME,
                                         GROUP_NAME_LEN,
                                         (const uint8_t *)PEER0_NICK, PEER0_NICK_LEN, &new_err);

    ck_assert_msg(new_err == TOX_ERR_GROUP_NEW_OK, "tox_group_new failed: %d", new_err);

    /* Founder sets group topic before anyone else joins */
    int s_ret = set_topic(toxes[0], groupnumber, TOPIC, TOPIC_LEN);
    ck_assert_msg(s_ret == 0, "Founder failed to set topic: %d\n", s_ret);

    /* Founder gets the Chat ID and implicitly shares it publicly */
    TOX_ERR_GROUP_STATE_QUERIES id_err;
    uint8_t chat_id[TOX_GROUP_CHAT_ID_SIZE];
    tox_group_get_chat_id(toxes[0], groupnumber, chat_id, &id_err);

    ck_assert_msg(id_err == TOX_ERR_GROUP_STATE_QUERIES_OK, "tox_group_get_chat_id failed %d", id_err);

    /* All other peers join the group using the Chat ID */
    for (size_t i = 1; i < NUM_GROUP_TOXES; ++i) {
        iterate_all_wait(NUM_GROUP_TOXES, toxes, state, ITERATION_INTERVAL);

        char nick[TOX_MAX_NAME_LENGTH + 1];
        snprintf(nick, sizeof(nick), "Follower%zu", i);
        TOX_ERR_GROUP_JOIN join_err;
        tox_group_join(toxes[i], chat_id, (const uint8_t *)nick, strlen(nick), NULL, 0, &join_err);
        ck_assert_msg(join_err == TOX_ERR_GROUP_JOIN_OK, "tox_group_join failed: %d", join_err);
    }

    fprintf(stderr, "Peers attempting to join group\n");

    /* Keep checking if all instances have connected to the group until test times out */
    while (1) {
        iterate_all_wait(NUM_GROUP_TOXES, toxes, state, ITERATION_INTERVAL);

        uint32_t count = 0;

        for (size_t i = 0; i < NUM_GROUP_TOXES; ++i) {
            if (tox_group_get_name_size(toxes[i], 0, nullptr) == GROUP_NAME_LEN) { // if we have the name we're connected
                ++count;
            }
        }

        if (count == NUM_GROUP_TOXES) {
            fprintf(stderr, "%u peers successfully joined\n", count);
            break;
        }
    }

    wait_state_topic(toxes, state, groupnumber, TOPIC, TOPIC_LEN);

    /* Founder disables topic lock */
    TOX_ERR_GROUP_FOUNDER_SET_TOPIC_LOCK lock_set_err;
    tox_group_founder_set_topic_lock(toxes[0], groupnumber, TOX_GROUP_TOPIC_LOCK_DISABLED, &lock_set_err);
    ck_assert_msg(lock_set_err == TOX_ERR_GROUP_FOUNDER_SET_TOPIC_LOCK_OK, "failed to disable topic lock: %d",
                  lock_set_err);

    fprintf(stderr, "Topic lock disabled\n");
    iterate_all_wait(NUM_GROUP_TOXES, toxes, state, ITERATION_INTERVAL);

    /* All peers should be able to change the topic now */
    for (size_t i = 0; i < NUM_GROUP_TOXES; ++i) {
        char new_topic[TOX_GROUP_MAX_TOPIC_LENGTH];
        snprintf(new_topic, sizeof(new_topic), "peer %zu changes topic first time", i);
        size_t length = strlen(new_topic);

        int s_ret = set_topic(toxes[i], groupnumber, new_topic, length);
        ck_assert_msg(s_ret == 0, "Peer %zu failed to set topic with topic lock disabled", i);

        // make sure every peer can see every other peer's topic change
        wait_state_topic(toxes, state, groupnumber, new_topic, length);
    }

    /* founder silences the last peer he saw join */
    TOX_ERR_GROUP_MOD_SET_ROLE merr;
    tox_group_mod_set_role(toxes[0], groupnumber, state[0].peer_id, TOX_GROUP_ROLE_OBSERVER, &merr);
    ck_assert_msg(merr == TOX_ERR_GROUP_MOD_SET_ROLE_OK, "Failed to set %u to observer role: %d", state[0].peer_id, merr);

    fprintf(stderr, "Peer id %u set to observer\n", state[0].peer_id);

    iterate_all_wait(NUM_GROUP_TOXES, toxes, state, ITERATION_INTERVAL);

    /* All peers except one should now be able to change the topic */
    uint32_t change_count = 0;

    for (size_t i = 0; i < NUM_GROUP_TOXES; ++i) {
        char new_topic[TOX_GROUP_MAX_TOPIC_LENGTH];
        snprintf(new_topic, sizeof(new_topic), "peer %zu changes topic second time", i);
        size_t length = strlen(new_topic);

        if (set_topic(toxes[i], groupnumber, new_topic, length) == 0) {
            wait_state_topic(toxes, state, groupnumber, new_topic, length);
            ++change_count;
        } else {
            fprintf(stderr, "Peer %zu couldn't set the topic\n", i);
        }
    }

    ck_assert_msg(change_count == NUM_GROUP_TOXES - 1, "%u peers changed the topic", change_count);

    /* Founder enables topic lock and sets topic back to original */
    tox_group_founder_set_topic_lock(toxes[0], groupnumber, TOX_GROUP_TOPIC_LOCK_ENABLED, &lock_set_err);
    ck_assert_msg(lock_set_err == TOX_ERR_GROUP_FOUNDER_SET_TOPIC_LOCK_OK, "failed to enable topic lock: %d",
                  lock_set_err);

    fprintf(stderr, "Topic lock enabled\n");

    iterate_all_wait(NUM_GROUP_TOXES, toxes, state, ITERATION_INTERVAL);

    s_ret = set_topic(toxes[0], groupnumber, TOPIC, TOPIC_LEN);
    ck_assert_msg(s_ret == 0, "Founder failed to set topic second time: %d", s_ret);

    wait_state_topic(toxes, state, groupnumber, TOPIC, TOPIC_LEN);

    /* Other peers attempt to change topic */
    for (size_t i = 1; i < NUM_GROUP_TOXES; ++i) {
        int s_ret = set_topic(toxes[i], groupnumber, "test", strlen("test"));
        ck_assert_msg(s_ret != 0, "Peer %zu changed the topic with the topic lock on", i);
        fprintf(stderr, "Peer %zu couldn't set the topic\n", i);
    }

    iterate_all_wait(NUM_GROUP_TOXES, toxes, state, ITERATION_INTERVAL);

    /* A final check that the topic is unchanged */
    wait_state_topic(toxes, state, groupnumber, TOPIC, TOPIC_LEN);

    fprintf(stderr, "All tests passed!\n");

#endif /* VANILLA_NACL */
}

int main(void)
{
    setvbuf(stdout, nullptr, _IONBF, 0);

    run_auto_test(NUM_GROUP_TOXES, group_topic_test, false);

    return 0;
}

#undef TOPIC
#undef TOPIC_LEN
#undef NUM_GROUP_TOXES
#undef GROUP_NAME
#undef GROUP_NAME_LEN
#undef PEER0_NICK
#undef PEER0

