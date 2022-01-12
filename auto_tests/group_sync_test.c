/*
 * Tests syncing capabilities of groups: we attempt to have multiple peers change the
 * group state in a number of ways and make sure that all peers end up with the same
 * resulting state after a short period.
 */

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "../toxcore/tox.h"
#include "../toxcore/util.h"

// these should be kept relatively low so integration tests don't always flake out
// but they can be increased for local stress testing
#define NUM_GROUP_TOXES 7
#define ROLE_SPAM_ITERATIONS 1
#define TOPIC_SPAM_ITERATIONS 3

typedef struct Peers {
    uint32_t  num_peers;
    int64_t   *peer_ids;
} Peers;

typedef struct State {
    uint32_t  index;
    uint64_t  clock;
    uint8_t   callback_topic[TOX_GROUP_MAX_TOPIC_LENGTH];
    size_t    topic_length;
    Peers     *peers;
} State;

#include "run_auto_test.h"


static int add_peer(Peers *peers, uint32_t peer_id)
{
    const uint32_t new_idx = peers->num_peers;

    int64_t *tmp_list = (int64_t *)realloc(peers->peer_ids, sizeof(int64_t) * (peers->num_peers + 1));

    if (tmp_list == nullptr) {
        return -1;
    }

    ++peers->num_peers;

    tmp_list[new_idx] = (int64_t)peer_id;

    peers->peer_ids = tmp_list;

    return 0;
}

static int del_peer(Peers *peers, uint32_t peer_id)
{
    int64_t i = -1;

    for (i = 0; i < peers->num_peers; ++i) {
        if (peers->peer_ids[i] == peer_id) {
            break;
        }
    }

    if (i == -1) {
        return -1;
    }

    --peers->num_peers;

    if (peers->num_peers != i) {
        peers->peer_ids[i] = peers->peer_ids[peers->num_peers];
    }

    peers->peer_ids[peers->num_peers] = -1;

    int64_t *tmp_list = (int64_t *)realloc(peers->peer_ids, sizeof(int64_t) * (peers->num_peers));

    if (tmp_list == nullptr) {
        return -1;
    }

    peers->peer_ids = tmp_list;

    return 0;
}

static void peers_cleanup(Peers *peers)
{
    free(peers->peer_ids);
    free(peers);
}

static void group_peer_join_handler(Tox *tox, uint32_t group_number, uint32_t peer_id, void *user_data)
{
    State *state = (State *)user_data;
    ck_assert(state != nullptr);

    ck_assert(add_peer(state->peers, peer_id) == 0);

}

static void group_peer_exit_handler(Tox *tox, uint32_t groupnumber, uint32_t peer_id, TOX_GROUP_EXIT_TYPE exit_type,
                                    const uint8_t *name, size_t name_length, const uint8_t *part_message,
                                    size_t length, void *user_data)
{
    State *state = (State *)user_data;
    ck_assert(state != nullptr);

    ck_assert(del_peer(state->peers, peer_id) == 0);

}

static void group_topic_handler(Tox *tox, uint32_t groupnumber, uint32_t peer_id, const uint8_t *topic,
                                size_t length, void *user_data)
{
    State *state = (State *)user_data;

    ck_assert(length <= TOX_GROUP_MAX_TOPIC_LENGTH);

    memcpy(state->callback_topic, (const char *)topic, length);
    state->topic_length = length;
}

static bool all_peers_connected(Tox **toxes, State *state, uint32_t groupnumber)
{
    for (uint32_t i = 0; i < NUM_GROUP_TOXES; ++i) {
        // make sure we got an invite response
        if (tox_group_get_name_size(toxes[i], groupnumber, nullptr) != 4) {
            return false;
        }

        // make sure we're actually connected
        if (!tox_group_is_connected(toxes[i], groupnumber, nullptr)) {
            return false;
        }

        // make sure all peers are connected to one another
        if (state[i].peers->num_peers == NUM_GROUP_TOXES - 1) {
            return false;
        }
    }

    return true;
}

static unsigned int get_peer_roles_checksum(Tox *tox, State *state, uint32_t groupnumber)
{
    Tox_Group_Role role = tox_group_self_get_role(tox, groupnumber, nullptr);
    unsigned int checksum = (unsigned int)role;

    for (size_t i = 0; i < state->peers->num_peers; ++i) {
        role = tox_group_peer_get_role(tox, groupnumber, (uint32_t)state->peers->peer_ids[i], nullptr);
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
    for (size_t iters = 0; iters < ROLE_SPAM_ITERATIONS; ++iters) {
        // founder randomly promotes or demotes one of the non-mods
        uint32_t idx = min_u32(random_u32() % num_demoted, state[0].peers->num_peers);
        Tox_Group_Role f_role = random_u32() % 2 == 0 ? TOX_GROUP_ROLE_MODERATOR : TOX_GROUP_ROLE_USER;
        int64_t peer_id = state[0].peers->peer_ids[idx];

        if (peer_id >= 0) {
            tox_group_mod_set_role(toxes[0], groupnumber, (uint32_t)peer_id, f_role, nullptr);
        }

        // mods randomly promote or demote one of the non-mods
        for (uint32_t i = 1; i < num_peers; ++i) {
            for (uint32_t j = num_demoted; j < num_peers; ++j) {
                if (i >= state[i].peers->num_peers) {
                    continue;
                }

                Tox_Group_Role role = random_u32() % 2 == 0 ? TOX_GROUP_ROLE_USER : TOX_GROUP_ROLE_OBSERVER;
                peer_id = state[j].peers->peer_ids[i];

                if (peer_id >= 0) {
                    tox_group_mod_set_role(toxes[j], groupnumber, (uint32_t)peer_id, role, nullptr);
                }
            }
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
    for (size_t i = 0; i < TOPIC_SPAM_ITERATIONS; ++i) {
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
        tox_callback_group_peer_exit(toxes[i], group_peer_exit_handler);

        state[i].peers = (Peers *)calloc(1, sizeof(Peers));

        ck_assert(state[i].peers != nullptr);
    }

    TOX_ERR_GROUP_NEW err_new;
    uint32_t groupnumber = tox_group_new(toxes[0], TOX_GROUP_PRIVACY_STATE_PUBLIC, (const uint8_t *) "test", 4,
                                         (const uint8_t *)"test", 4,  &err_new);

    ck_assert(err_new == TOX_ERR_GROUP_NEW_OK);

    fprintf(stderr, "tox0 creats new group and invites all his friends");

    TOX_ERR_GROUP_STATE_QUERIES id_err;
    uint8_t chat_id[TOX_GROUP_CHAT_ID_SIZE];

    tox_group_get_chat_id(toxes[0], groupnumber, chat_id, &id_err);
    ck_assert_msg(id_err == TOX_ERR_GROUP_STATE_QUERIES_OK, "%d", id_err);

    for (size_t i = 1; i < NUM_GROUP_TOXES; ++i) {
        TOX_ERR_GROUP_JOIN join_err;
        tox_group_join(toxes[i], chat_id, (const uint8_t *)"Test", 4, nullptr, 0, &join_err);
        ck_assert_msg(join_err == TOX_ERR_GROUP_JOIN_OK, "%d", join_err);
        iterate_all_wait(NUM_GROUP_TOXES, toxes, state, ITERATION_INTERVAL);
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

    iterate_all_wait(NUM_GROUP_TOXES, toxes, state, ITERATION_INTERVAL);

    tox_group_founder_set_topic_lock(toxes[0], groupnumber, TOX_GROUP_TOPIC_LOCK_ENABLED, &lock_set_err);
    ck_assert_msg(lock_set_err == TOX_ERR_GROUP_FOUNDER_SET_TOPIC_LOCK_OK, "failed to enable topic lock: %d",
                  lock_set_err);

    do {
        iterate_all_wait(NUM_GROUP_TOXES, toxes, state, ITERATION_INTERVAL);
    } while (!all_peers_have_same_topic(toxes, state, NUM_GROUP_TOXES, groupnumber)
             && !all_peers_see_same_roles(toxes, state, NUM_GROUP_TOXES, groupnumber)
             && state[0].peers->num_peers != NUM_GROUP_TOXES - 1);

    TOX_ERR_GROUP_MOD_SET_ROLE role_err;

    for (size_t i = 0; i < state[0].peers->num_peers; ++i) {
        tox_group_mod_set_role(toxes[0], groupnumber, (uint32_t)state[0].peers->peer_ids[i], TOX_GROUP_ROLE_MODERATOR,
                               &role_err);
        ck_assert_msg(role_err == TOX_ERR_GROUP_MOD_SET_ROLE_OK, "Failed to set moderator. error: %d", role_err);
    }

    fprintf(stderr, "founder enabled topic lock and set all peers to moderator role\n");

    do {
        iterate_all_wait(NUM_GROUP_TOXES, toxes, state, ITERATION_INTERVAL);
    } while (!all_peers_see_same_roles(toxes, state, NUM_GROUP_TOXES, groupnumber));

    topic_spam(toxes, state, NUM_GROUP_TOXES, groupnumber);

    const unsigned int num_demoted = state[0].peers->num_peers / 2;

    fprintf(stderr, "founder demoting %u moderators to user\n", num_demoted);

    for (size_t i = 0; i < num_demoted; ++i) {
        tox_group_mod_set_role(toxes[0], groupnumber, (uint32_t)state[0].peers->peer_ids[i], TOX_GROUP_ROLE_USER,
                               &role_err);
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
        peers_cleanup(state[i].peers);
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
#undef ROLE_SPAM_ITERATIONS
#undef TOPIC_SPAM_ITERATIONS

