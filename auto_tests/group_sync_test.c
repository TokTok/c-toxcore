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

#define NUM_GROUP_TOXES 6
#define PEER_LIMIT 30

typedef struct State {
    uint32_t  index;
    uint64_t  clock;
    uint32_t  num_peers;
    uint32_t  peer_ids[NUM_GROUP_TOXES - 1];
    uint8_t   callback_topic[TOX_GROUP_MAX_TOPIC_LENGTH];
    size_t    topic_length;
} State;

#include "run_auto_test.h"

static bool all_peers_connected(Tox **toxes, State *state, uint32_t groupnumber)
{
    for (uint32_t i = 0; i < NUM_GROUP_TOXES; ++i) {
        // make sure we got an invite response
        if (tox_group_get_name_size(toxes[i], groupnumber, nullptr) != 4) {
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

        // make sure all peers are connected to one another
        if (state[i].num_peers == NUM_GROUP_TOXES - 1) {
            return false;
        }
    }

    return true;
}

static void group_peer_join_handler(Tox *tox, uint32_t group_number, uint32_t peer_id, void *user_data)
{
    State *state = (State *)user_data;

    ck_assert(state->num_peers < NUM_GROUP_TOXES);

    state->peer_ids[state->num_peers] = peer_id;
    ++state->num_peers;
}

static void group_topic_handler(Tox *tox, uint32_t groupnumber, uint32_t peer_id, const uint8_t *topic,
                                size_t length, void *user_data)
{
    State *state = (State *)user_data;

    ck_assert(length <= TOX_GROUP_MAX_TOPIC_LENGTH);

    memcpy(state->callback_topic, (const char *)topic, length);
    state->topic_length = length;
}

static unsigned int get_peer_roles_checksum(Tox *tox, State *state, uint32_t groupnumber)
{
    Tox_Group_Role role = tox_group_self_get_role(tox, groupnumber, nullptr);
    unsigned int checksum = (unsigned int)role;

    for (size_t i = 0; i < NUM_GROUP_TOXES - 1; ++i) {
        role = tox_group_peer_get_role(tox, groupnumber, state->peer_ids[i], nullptr);
        checksum += (unsigned int)role;
    }

    return checksum;
}

static bool all_peers_see_same_roles(Tox **toxes, State *state, uint32_t num_peers, uint32_t groupnumber)
{
    unsigned int expected_checksum = get_peer_roles_checksum(toxes[0], &state[0], groupnumber);

    for (size_t i = 0; i < num_peers; ++i) {
        unsigned int checksum = get_peer_roles_checksum(toxes[i], &state[i], groupnumber);

        if (checksum != expected_checksum) {
            return false;
        }
    }

    return true;
}

static void role_spam(Tox **toxes, State *state, uint32_t num_peers, uint32_t num_demoted, uint32_t groupnumber)
{
    for (size_t iters = 0; iters < 1; ++iters) {
        // founder randomly promotes or demotes one of the non-mods
        size_t idx = random_u32() % num_demoted;
        Tox_Group_Role f_role = random_u32() % 2 == 0 ? TOX_GROUP_ROLE_MODERATOR : TOX_GROUP_ROLE_USER;
        tox_group_mod_set_role(toxes[0], groupnumber, state[0].peer_ids[idx], f_role, nullptr);

        // mods randomly promote or demote one of the non-mods
        for (size_t i = 1; i < num_demoted; ++i) {
            for (size_t j = num_demoted; j < num_peers; ++j) {
                Tox_Group_Role role = random_u32() % 2 == 0 ? TOX_GROUP_ROLE_USER : TOX_GROUP_ROLE_OBSERVER;
                tox_group_mod_set_role(toxes[j], groupnumber, state[j].peer_ids[i], role, nullptr);
            }
        }
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
    for (size_t i = 0; i < 5; ++i) {
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
    ck_assert(NUM_GROUP_TOXES >= 5);

    for (size_t i = 0; i < NUM_GROUP_TOXES; ++i) {
        tox_callback_group_peer_join(toxes[i], group_peer_join_handler);
        tox_callback_group_topic(toxes[i], group_topic_handler);
    }

    TOX_ERR_GROUP_NEW err_new;
    uint32_t groupnumber = tox_group_new(toxes[0], TOX_GROUP_PRIVACY_STATE_PUBLIC, (const uint8_t *) "test", 4,
                                         (const uint8_t *)"test", 4,  &err_new);

    ck_assert(err_new == TOX_ERR_GROUP_NEW_OK);

    fprintf(stderr, "tox0 creats new group and invites all his friends");

    TOX_ERR_GROUP_FOUNDER_SET_PEER_LIMIT limit_set_err;
    tox_group_founder_set_peer_limit(toxes[0], groupnumber, PEER_LIMIT, &limit_set_err);
    ck_assert(limit_set_err == TOX_ERR_GROUP_FOUNDER_SET_PEER_LIMIT_OK);

    TOX_ERR_GROUP_STATE_QUERIES id_err;
    uint8_t chat_id[TOX_GROUP_CHAT_ID_SIZE];

    tox_group_get_chat_id(toxes[0], groupnumber, chat_id, &id_err);
    ck_assert_msg(id_err == TOX_ERR_GROUP_STATE_QUERIES_OK, "%d", id_err);

    for (size_t i = 1; i < NUM_GROUP_TOXES; ++i) {
        TOX_ERR_GROUP_JOIN join_err;
        tox_group_join(toxes[i], chat_id, (const uint8_t *)"Test", 4, nullptr, 0, &join_err);
        ck_assert_msg(join_err == TOX_ERR_GROUP_JOIN_OK, "%d", join_err);
    }

    do {
        iterate_all_wait(NUM_GROUP_TOXES, toxes, state, ITERATION_INTERVAL);
    } while (!all_peers_connected(toxes, state, groupnumber));

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

    do {
        iterate_all_wait(NUM_GROUP_TOXES, toxes, state, ITERATION_INTERVAL);
    } while (!all_peers_have_same_topic(toxes, state, NUM_GROUP_TOXES, groupnumber)
             && !all_peers_see_same_roles(toxes, state, NUM_GROUP_TOXES, groupnumber));

    TOX_ERR_GROUP_MOD_SET_ROLE role_err;

    for (size_t i = 0; i < NUM_GROUP_TOXES - 1; ++i) {
        tox_group_mod_set_role(toxes[0], groupnumber, state[0].peer_ids[i], TOX_GROUP_ROLE_MODERATOR, &role_err);
        ck_assert_msg(role_err == TOX_ERR_GROUP_MOD_SET_ROLE_OK, "Failed to set moderator. error: %d", role_err);
    }

    fprintf(stderr, "founder enabled topic lock and set all peers to moderator role\n");

    do {
        iterate_all_wait(NUM_GROUP_TOXES, toxes, state, ITERATION_INTERVAL);
    } while (!all_peers_see_same_roles(toxes, state, NUM_GROUP_TOXES, groupnumber));

    topic_spam(toxes, state, NUM_GROUP_TOXES, groupnumber);

    const unsigned int num_demoted = NUM_GROUP_TOXES / 2;

    fprintf(stderr, "founder demoting %u moderators to user\n", num_demoted);

    for (size_t i = 0; i < num_demoted; ++i) {
        tox_group_mod_set_role(toxes[0], groupnumber, state[0].peer_ids[i], TOX_GROUP_ROLE_USER, &role_err);
        ck_assert_msg(role_err == TOX_ERR_GROUP_MOD_SET_ROLE_OK, "Failed to set user. error: %d", role_err);
    }

    do {
        iterate_all_wait(NUM_GROUP_TOXES, toxes, state, ITERATION_INTERVAL);
    } while (!all_peers_see_same_roles(toxes, state, NUM_GROUP_TOXES, groupnumber));

    fprintf(stderr, "Remaining moderators spam change non-moderator roles\n");

    role_spam(toxes, state, NUM_GROUP_TOXES, num_demoted, groupnumber);

    fprintf(stderr, "All peers see the same roles\n");

    for (size_t i = 0; i < NUM_GROUP_TOXES; i++) {
        tox_group_leave(toxes[i], groupnumber, nullptr, 0, nullptr);
    }

    fprintf(stderr, "All tests passed!\n");

#endif  // VANILLA_NACL
}

int main(void)
{
    setvbuf(stdout, nullptr, _IONBF, 0);

    run_auto_test(nullptr, NUM_GROUP_TOXES, group_sync_test, false);

    return 0;
}

#undef NUM_GROUP_TOXES
#undef PEER_LIMIT

