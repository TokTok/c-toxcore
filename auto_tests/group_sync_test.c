/*
 * Tests syncing capabilities of groups: we attempt to have multiple peers change the
 * group state in a number of ways and make sure that all peers end up with the same
 * resulting state after a short period.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "../toxcore/tox.h"

#define NUM_GROUP_TOXES 10

typedef struct State {
    uint32_t  index;
    uint64_t  clock;
    uint32_t  num_peers;
    uint32_t  peer_ids[NUM_GROUP_TOXES - 1];
    uint8_t   callback_topic[TOX_GROUP_MAX_TOPIC_LENGTH];
    size_t    topic_length;
} State;

#include "run_auto_test.h"

static bool all_peers_invited(Tox **toxes, State *state, uint32_t groupnumber)
{
    for (size_t i = 0; i < NUM_GROUP_TOXES; ++i) {
        if (!tox_group_is_connected(toxes[i], groupnumber, nullptr) && state->num_peers == NUM_GROUP_TOXES - 1) {
            return false;
        }
    }

    return true;
}

static void group_invite_handler(Tox *tox, uint32_t friend_number, const uint8_t *invite_data, size_t length,
                                 const uint8_t *group_name, size_t group_name_length, void *user_data)
{
    TOX_ERR_GROUP_INVITE_ACCEPT err_accept;
    tox_group_invite_accept(tox, friend_number, invite_data, length, (const uint8_t *)"test", 4,
                            nullptr, 0, &err_accept);
    ck_assert(err_accept == TOX_ERR_GROUP_INVITE_ACCEPT_OK);
}

static void group_peer_join_handler(Tox *tox, uint32_t group_number, uint32_t peer_id, void *user_data)
{
    State *state = (State *)user_data;

    ck_assert(state->num_peers < NUM_GROUP_TOXES);

    state->peer_ids[state->num_peers] = peer_id;
    ++state->num_peers;
}

static void group_join_fail_handler(Tox *tox, uint32_t groupnumber, TOX_GROUP_JOIN_FAIL fail_type, void *user_data)
{
    ck_assert_msg(false, "invite failed: %d", fail_type);
}

static void group_topic_handler(Tox *tox, uint32_t groupnumber, uint32_t peer_id, const uint8_t *topic,
                                size_t length, void *user_data)
{
    State *state = (State *)user_data;

    ck_assert(length <= TOX_GROUP_MAX_TOPIC_LENGTH);

    memcpy(state->callback_topic, (const char *)topic, length);
    state->topic_length = length;
}

static uint32_t get_peer_roles_checksum(Tox *tox, State *state, uint32_t groupnumber)
{
    uint32_t checksum = (uint32_t)tox_group_self_get_role(tox, groupnumber, nullptr);

    for (size_t i = 0; i < NUM_GROUP_TOXES - 1; ++i) {
        checksum += (uint32_t)tox_group_peer_get_role(tox, groupnumber, state->peer_ids[i], nullptr);
    }

    return checksum;
}

static bool all_peers_see_same_roles(Tox **toxes, State *state, uint32_t num_peers, uint32_t groupnumber)
{
    uint32_t expected_checksum = get_peer_roles_checksum(toxes[0], &state[0], groupnumber);

    fprintf(stderr, "founder: %u\n", expected_checksum);
    bool ret = true;

    for (size_t i = 0; i < num_peers; ++i) {
        uint32_t checksum = get_peer_roles_checksum(toxes[i], &state[i], groupnumber);

        fprintf(stderr, "peer %llu: %u\n", (unsigned long long)i, checksum);

        if (checksum != expected_checksum) {
            //fprintf(stderr, "%i: %u - %u\n",i, checksum, expected_checksum);
            ret = false;
        }
    }

    return ret;
}

static void observer_spam(Tox **toxes, State *state, uint32_t num_peers, uint32_t groupnumber)
{
    for (size_t i = 1; i < 7; ++i) {
        for (size_t j = 7; j < num_peers; ++j) {
            Tox_Group_Role role = random_u32() % 2 == 0 ? TOX_GROUP_ROLE_OBSERVER : TOX_GROUP_ROLE_OBSERVER;
            tox_group_mod_set_role(toxes[j], groupnumber, state[j].peer_ids[i], role, nullptr);
        }

        iterate_all_wait(num_peers, toxes, state, ITERATION_INTERVAL);
    }

    do {
        iterate_all_wait(num_peers, toxes, state, ITERATION_INTERVAL);
    } while (!all_peers_see_same_roles(toxes, state, num_peers, groupnumber));
}

/* All peers attempt to set a unique topic.
 *
 * Return true if all peers successfully changed the topic.
 */
static bool set_topic_all_peers(Tox **toxes, State *state, size_t num_peers, uint32_t groupnumber)
{
    for (size_t i = 0; i < num_peers; ++i) {
        char new_topic[TOX_GROUP_MAX_TOPIC_LENGTH];
        snprintf(new_topic, sizeof(new_topic), "peer %zu's topic %u", i, random_u32());
        const size_t length = sizeof(new_topic);

        TOX_ERR_GROUP_TOPIC_SET err;
        tox_group_set_topic(toxes[i], groupnumber, (const uint8_t *)new_topic, length, &err);

        if (err != TOX_ERR_GROUP_TOPIC_SET_OK) {
            return false;
        }
    }

    return true;
}

/* Returns true if all peers have the same topic, and the topic from the get_topic API function
 * matches the last topic they received in the topic callback.
 */
static bool all_peers_have_same_topic(Tox **toxes, State *state, uint32_t num_peers, uint32_t groupnumber)
{
    uint8_t expected_topic[TOX_GROUP_MAX_TOPIC_LENGTH];

    TOX_ERR_GROUP_STATE_QUERIES query_err;
    size_t expected_topic_length = tox_group_get_topic_size(toxes[0], groupnumber, &query_err);

    ck_assert(query_err == TOX_ERR_GROUP_STATE_QUERIES_OK);

    tox_group_get_topic(toxes[0], groupnumber, expected_topic, &query_err);

    ck_assert(query_err == TOX_ERR_GROUP_STATE_QUERIES_OK);

    if (expected_topic_length != state[0].topic_length) {
        return false;
    }

    if (memcmp(state->callback_topic, expected_topic, expected_topic_length) != 0) {
        return false;
    }

    for (size_t i = 1; i < num_peers; ++i) {
        size_t topic_length = tox_group_get_topic_size(toxes[i], groupnumber, &query_err);

        ck_assert(query_err == TOX_ERR_GROUP_STATE_QUERIES_OK);

        if (topic_length != expected_topic_length) {
            return false;
        }

        uint8_t topic[TOX_GROUP_MAX_TOPIC_LENGTH];
        tox_group_get_topic(toxes[i], groupnumber, topic, &query_err);

        ck_assert(query_err == TOX_ERR_GROUP_STATE_QUERIES_OK);

        if (memcmp(expected_topic, (const char *)topic, topic_length) != 0) {
            return false;
        }

        if (topic_length != state[i].topic_length) {
            return false;
        }

        if (memcmp(state[i].callback_topic, (const char *)topic, topic_length) != 0) {
            return false;
        }
    }

    return true;
}

static void topic_spam(Tox **toxes, State *state, uint32_t num_peers, uint32_t groupnumber)
{
    for (size_t i = 0; i < 2; ++i) {
        do {
            iterate_all_wait(num_peers, toxes, state, ITERATION_INTERVAL);
        } while (!set_topic_all_peers(toxes, state, num_peers, groupnumber));
    }

    fprintf(stderr, "all peers set the topic at the same time\n");

    do {
        iterate_all_wait(num_peers, toxes, state, ITERATION_INTERVAL);
    } while (!all_peers_have_same_topic(toxes, state, num_peers, groupnumber));

    fprintf(stderr, "all peers see the same topic\n");
}

static void group_sync_test(Tox **toxes, State *state)
{
#ifndef VANILLA_NACL
    ck_assert(NUM_GROUP_TOXES >= 10);

    for (size_t i = 0; i < NUM_GROUP_TOXES; ++i) {
        tox_callback_group_invite(toxes[i], group_invite_handler);
        tox_callback_group_join_fail(toxes[i], group_join_fail_handler);
        tox_callback_group_peer_join(toxes[i], group_peer_join_handler);
        tox_callback_group_topic(toxes[i], group_topic_handler);
    }

    TOX_ERR_GROUP_NEW err_new;
    uint32_t groupnumber = tox_group_new(toxes[0], TOX_GROUP_PRIVACY_STATE_PRIVATE, (const uint8_t *) "test", 4,
                                         (const uint8_t *)"test", 4,  &err_new);

    ck_assert(err_new == TOX_ERR_GROUP_NEW_OK);

    fprintf(stderr, "tox0 creats new group and invites all his friends");

    // tox0 invites all his friends to the group
    for (size_t i = 0; i < NUM_GROUP_TOXES - 1; ++i) {
        TOX_ERR_GROUP_INVITE_FRIEND err_invite;
        tox_group_invite_friend(toxes[0], groupnumber, i, &err_invite);
        ck_assert(err_invite == TOX_ERR_GROUP_INVITE_FRIEND_OK);
    }

    // make sure every peer has gotten an invite to the group
    do {
        iterate_all_wait(NUM_GROUP_TOXES, toxes, state, ITERATION_INTERVAL);
    } while (!all_peers_invited(toxes, state, groupnumber));

    fprintf(stderr, "%d peers joined the group\n", NUM_GROUP_TOXES);

    TOX_ERR_GROUP_FOUNDER_SET_TOPIC_LOCK lock_set_err;
    tox_group_founder_set_topic_lock(toxes[0], groupnumber, TOX_GROUP_TOPIC_LOCK_DISABLED, &lock_set_err);
    ck_assert_msg(lock_set_err == TOX_ERR_GROUP_FOUNDER_SET_TOPIC_LOCK_OK, "failed to disable topic lock: %d",
                  lock_set_err);

    iterate_all_wait(NUM_GROUP_TOXES, toxes, state, ITERATION_INTERVAL);

    fprintf(stderr, "founder disabled topic lock; all peers try to set the topic\n");

    topic_spam(toxes, state, NUM_GROUP_TOXES, groupnumber);

    tox_group_founder_set_topic_lock(toxes[0], groupnumber, TOX_GROUP_TOPIC_LOCK_ENABLED, &lock_set_err);
    ck_assert_msg(lock_set_err == TOX_ERR_GROUP_FOUNDER_SET_TOPIC_LOCK_OK, "failed to enable topic lock: %d",
                  lock_set_err);

    TOX_ERR_GROUP_MOD_SET_ROLE role_err;

    for (size_t i = 0; i < NUM_GROUP_TOXES - 1; ++i) {
        tox_group_mod_set_role(toxes[0], groupnumber, state[0].peer_ids[i], TOX_GROUP_ROLE_MODERATOR, &role_err);
        ck_assert_msg(role_err == TOX_ERR_GROUP_MOD_SET_ROLE_OK, "Failed to set moderator. error: %d", role_err);
    }

    fprintf(stderr, "founder enabled topic lock and set all peers to moderator role\n");

    topic_spam(toxes, state, NUM_GROUP_TOXES, groupnumber);

    /*     fprintf(stderr, "founder demotes peers 0 through 7 to user\n"); */

    /*     iterate_all_wait(NUM_GROUP_TOXES, toxes, state, ITERATION_INTERVAL * 20); */

    /*     for (size_t i = 0; i < 7; ++i) { */
    /*         tox_group_mod_set_role(toxes[0], groupnumber, state[0].peer_ids[i], TOX_GROUP_ROLE_USER, &role_err); */
    /*         ck_assert_msg(role_err == TOX_ERR_GROUP_MOD_SET_ROLE_OK, "Failed to set user. error: %d", role_err); */
    /*     } */

    /*     iterate_all_wait(NUM_GROUP_TOXES, toxes, state, ITERATION_INTERVAL * 20); */

    /*     observer_spam(toxes, state, NUM_GROUP_TOXES, groupnumber); */

    fprintf(stderr, "test passed!\n");

#endif  // VANILLA_NACL
}

int main(void)
{
    setvbuf(stdout, nullptr, _IONBF, 0);

    run_auto_test(nullptr, NUM_GROUP_TOXES, group_sync_test, false);

    return 0;
}
