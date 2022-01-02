/*
 * Tests group moderation functionality.
 *
 * Note that making the peer count too high will break things. This test should not be relied on
 * for general group/syncing functionality.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "../toxcore/tox.h"

#include "check_compat.h"

#define NUM_GROUP_TOXES 5
#define GROUP_NAME "NASA Headquarters"
#define GROUP_NAME_LEN (sizeof(GROUP_NAME) - 1)

typedef struct Peer {
    char name[TOX_MAX_NAME_LENGTH];
    size_t name_length;
    uint32_t peer_id;
} Peer;

typedef struct State {
    uint32_t index;
    uint64_t clock;

    char self_name[TOX_MAX_NAME_LENGTH];
    size_t self_name_length;

    uint32_t group_number;

    uint32_t num_peers;
    Peer peers[NUM_GROUP_TOXES - 1];

    bool mod_check;
    size_t mod_event_count;
    char mod_name1[TOX_MAX_NAME_LENGTH];
    char mod_name2[TOX_MAX_NAME_LENGTH];


    bool observer_check;
    size_t observer_event_count;
    char observer_name1[TOX_MAX_NAME_LENGTH];
    char observer_name2[TOX_MAX_NAME_LENGTH];

    bool user_check;
    size_t user_event_count;

    bool kick_check;  // moderater gets kicked
} State;


#include "run_auto_test.h"

static bool all_peers_connected(Tox **toxes, State *state)
{
    for (size_t i = 0; i < NUM_GROUP_TOXES; ++i) {
        if (state[i].num_peers != NUM_GROUP_TOXES - 1) {
            return false;
        }

        if (!tox_group_is_connected(toxes[i], state[i].group_number, nullptr)) {
            return false;
        }
    }

    return true;
}

/*
 * Waits for all peers to receive the mod event.
 */
static void check_mod_event(State *state, Tox **toxes, size_t num_peers, TOX_GROUP_MOD_EVENT event)
{
    uint32_t peers_recv_changes = 0;

    do {
        peers_recv_changes = 0;

        iterate_all_wait(NUM_GROUP_TOXES, toxes, state, ITERATION_INTERVAL);

        for (size_t i = 0; i < num_peers; ++i) {
            bool check = false;

            switch (event) {
                case TOX_GROUP_MOD_EVENT_MODERATOR: {
                    if (state[i].mod_check) {
                        check = true;
                        state[i].mod_check = false;
                    }

                    break;
                }

                case TOX_GROUP_MOD_EVENT_OBSERVER: {
                    if (state[i].observer_check) {
                        check = true;
                        state[i].observer_check = false;
                    }

                    break;
                }

                case TOX_GROUP_MOD_EVENT_USER: {
                    if (state[i].user_check) {
                        check = true;
                        state[i].user_check = false;
                    }

                    break;
                }

                case TOX_GROUP_MOD_EVENT_KICK: {
                    check = state[i].kick_check;
                    break;
                }

                default: {
                    ck_assert(0);
                }
            }

            if (check) {
                ++peers_recv_changes;
            }
        }
    } while (peers_recv_changes < num_peers - 1);
}

static uint32_t get_peer_id_by_nick(Peer *peers, uint32_t num_peers, const char *name)
{
    ck_assert(name != nullptr);

    for (uint32_t i = 0; i < num_peers; ++i) {
        if (memcmp(peers[i].name, name, peers[i].name_length) == 0) {
            return peers[i].peer_id;
        }
    }

    ck_assert_msg(0, "Failed to find peer id");
}

static size_t get_state_index_by_nick(State *state, size_t num_peers, const char *name, size_t name_length)
{
    ck_assert(name != nullptr && name_length <= TOX_MAX_NAME_LENGTH);

    for (size_t i = 0; i < num_peers; ++i) {
        if (memcmp(state[i].self_name, name, name_length) == 0) {
            return i;
        }
    }

    ck_assert_msg(0, "Failed to find index");
}

static void group_join_fail_handler(Tox *tox, uint32_t group_number, TOX_GROUP_JOIN_FAIL fail_type, void *user_data)
{
    fprintf(stderr, "Failed to join group: %d", fail_type);
}

static void group_peer_join_handler(Tox *tox, uint32_t group_number, uint32_t peer_id, void *user_data)
{
    State *state = (State *)user_data;

    ck_assert(state->group_number == group_number);

    char peer_name[TOX_MAX_NAME_LENGTH + 1];

    TOX_ERR_GROUP_PEER_QUERY q_err;
    size_t peer_name_len = tox_group_peer_get_name_size(tox, group_number, peer_id, &q_err);

    ck_assert(q_err == TOX_ERR_GROUP_PEER_QUERY_OK);
    ck_assert(peer_name_len <= TOX_MAX_NAME_LENGTH);

    tox_group_peer_get_name(tox, group_number, peer_id, (uint8_t *) peer_name, &q_err);
    peer_name[peer_name_len] = 0;
    ck_assert(q_err == TOX_ERR_GROUP_PEER_QUERY_OK);

    Peer *peer = &state->peers[state->num_peers];

    peer->peer_id = peer_id;
    memcpy(peer->name, peer_name, peer_name_len);
    peer->name_length = peer_name_len;

    ++state->num_peers;

    ck_assert(state->num_peers < NUM_GROUP_TOXES);
}

static void group_mod_event_handler(Tox *tox, uint32_t group_number, uint32_t source_peer_id, uint32_t target_peer_id,
                                    TOX_GROUP_MOD_EVENT event, void *user_data)
{
    State *state = (State *)user_data;

    ck_assert(state != nullptr);
    ck_assert(state->group_number == group_number);

    char peer_name[TOX_MAX_NAME_LENGTH + 1];

    TOX_ERR_GROUP_PEER_QUERY q_err;
    size_t peer_name_len = tox_group_peer_get_name_size(tox, group_number, target_peer_id, &q_err);

    ck_assert(q_err == TOX_ERR_GROUP_PEER_QUERY_OK);
    ck_assert(peer_name_len <= TOX_MAX_NAME_LENGTH);

    tox_group_peer_get_name(tox, group_number, target_peer_id, (uint8_t *) peer_name, &q_err);
    peer_name[peer_name_len] = 0;
    ck_assert(q_err == TOX_ERR_GROUP_PEER_QUERY_OK);

    TOX_GROUP_ROLE role = tox_group_peer_get_role(tox, group_number, target_peer_id, &q_err);
    ck_assert(q_err == TOX_ERR_GROUP_PEER_QUERY_OK);

    switch (event) {
        case TOX_GROUP_MOD_EVENT_MODERATOR: {
            if (state->mod_event_count == 0) {
                ck_assert(memcmp(peer_name, state->mod_name1, peer_name_len) == 0);
            } else if (state->mod_event_count == 1) {
                ck_assert(memcmp(peer_name, state->mod_name2, peer_name_len) == 0);
            } else {
                ck_assert(false);
            }

            ++state->mod_event_count;
            state->mod_check = true;
            ck_assert(role == TOX_GROUP_ROLE_MODERATOR);

            break;
        }

        case TOX_GROUP_MOD_EVENT_OBSERVER: {
            if (state->observer_event_count == 0) {
                ck_assert(memcmp(peer_name, state->observer_name1, peer_name_len) == 0);
            } else if (state->observer_event_count == 1) {
                ck_assert(memcmp(peer_name, state->observer_name2, peer_name_len) == 0);
            } else {
                ck_assert(false);
            }

            ++state->observer_event_count;
            state->observer_check = true;
            ck_assert(role == TOX_GROUP_ROLE_OBSERVER);

            break;
        }

        case TOX_GROUP_MOD_EVENT_USER: {
            // event 1: observer1 gets promoted back to user
            // event 2: observer2 gets promoted to moderator
            // event 3: moderator 1 gets kicked
            // event 4: moderator 2 gets demoted to moderator
            if (state->user_event_count == 0) {
                ck_assert(memcmp(peer_name, state->observer_name1, peer_name_len) == 0);
            } else if (state->user_event_count == 1) {
                ck_assert(memcmp(peer_name, state->observer_name2, peer_name_len) == 0);
            } else if (state->user_event_count == 2) {
                ck_assert(memcmp(peer_name, state->mod_name1, peer_name_len) == 0);
            } else if (state->user_event_count == 3) {
                ck_assert(memcmp(peer_name, state->mod_name2, peer_name_len) == 0);
            } else {
                ck_assert(false);
            }

            ++state->user_event_count;
            state->user_check = true;
            ck_assert(role == TOX_GROUP_ROLE_USER);

            break;
        }

        case TOX_GROUP_MOD_EVENT_KICK: {
            ck_assert(memcmp(peer_name, state->mod_name1, peer_name_len) == 0);
            state->kick_check = true;
            break;
        }

        default: {
            ck_assert_msg(0, "Got invalid moderator event %d", event);
            return;
        }
    }
}

/* Checks that `peer_id` sees itself with the role `role`. */
static void check_self_role(State *state, Tox **toxes, uint32_t peer_id, TOX_GROUP_ROLE role)
{
    TOX_ERR_GROUP_SELF_QUERY sq_err;

    for (size_t i = 0; i < NUM_GROUP_TOXES; ++i) {
        uint32_t self_peer_id = tox_group_self_get_peer_id(toxes[i], state[i].group_number, &sq_err);
        ck_assert(sq_err == TOX_ERR_GROUP_SELF_QUERY_OK);

        if (self_peer_id == peer_id) {
            TOX_GROUP_ROLE self_role = tox_group_self_get_role(toxes[i], state[i].group_number, &sq_err);
            ck_assert(sq_err == TOX_ERR_GROUP_SELF_QUERY_OK);
            ck_assert(self_role == role);
            return;
        }
    }
}

static void group_moderation_test(Tox **toxes, State *state)
{
#ifndef VANILLA_NACL
    ck_assert_msg(NUM_GROUP_TOXES >= 4, "NUM_GROUP_TOXES is too small: %d", NUM_GROUP_TOXES);
    ck_assert_msg(NUM_GROUP_TOXES < 10, "NUM_GROUP_TOXES is too big: %d", NUM_GROUP_TOXES);

    uint16_t name_length = 6;

    for (size_t i = 0; i < NUM_GROUP_TOXES; ++i) {
        state[i].self_name_length = name_length;
        snprintf(state[i].self_name, sizeof(state[i].self_name), "peer_%zu", i);
        state[i].self_name[name_length] = 0;

        tox_callback_group_join_fail(toxes[i], group_join_fail_handler);
        tox_callback_group_peer_join(toxes[i], group_peer_join_handler);
        tox_callback_group_moderation(toxes[i], group_mod_event_handler);
    }

    iterate_all_wait(NUM_GROUP_TOXES, toxes, state, ITERATION_INTERVAL);

    fprintf(stderr, "Creating new group\n");

    /* Founder makes new group */
    TOX_ERR_GROUP_NEW err_new;
    state[0].group_number = tox_group_new(toxes[0], TOX_GROUP_PRIVACY_STATE_PUBLIC, (const uint8_t *)GROUP_NAME,
                                          GROUP_NAME_LEN, (const uint8_t *)state[0].self_name, state[0].self_name_length,
                                          &err_new);

    ck_assert_msg(err_new == TOX_ERR_GROUP_NEW_OK, "Failed to create group. error: %d\n", err_new);

    /* Founder gets chat ID */
    TOX_ERR_GROUP_STATE_QUERIES id_err;
    uint8_t chat_id[TOX_GROUP_CHAT_ID_SIZE];
    tox_group_get_chat_id(toxes[0], state[0].group_number, chat_id, &id_err);

    ck_assert_msg(id_err == TOX_ERR_GROUP_STATE_QUERIES_OK, "Failed to get chat ID. error: %d", id_err);

    fprintf(stderr, "Peers attemping to join DHT group via the chat ID\n");

    for (size_t i = 1; i < NUM_GROUP_TOXES; ++i) {
        iterate_all_wait(NUM_GROUP_TOXES, toxes, state, ITERATION_INTERVAL);
        TOX_ERR_GROUP_JOIN join_err;
        state[i].group_number = tox_group_join(toxes[i], chat_id, (const uint8_t *)state[i].self_name,
                                               state[i].self_name_length,
                                               nullptr, 0, &join_err);
        ck_assert_msg(join_err == TOX_ERR_GROUP_JOIN_OK, "Peer %s (%zu) failed to join group. error %d",
                      state[i].self_name, i, join_err);

        c_sleep(100);
    }

    // make sure every peer sees every other peer before we continue
    do {
        iterate_all_wait(NUM_GROUP_TOXES, toxes, state, ITERATION_INTERVAL);
    } while (!all_peers_connected(toxes, state));

    /* manually tell the other peers the names of the peers that will be assigned new roles */
    for (size_t i = 0; i < NUM_GROUP_TOXES; ++i) {
        memcpy(state[i].mod_name1, state[0].peers[0].name, sizeof(state[i].mod_name1));
        memcpy(state[i].mod_name2, state[0].peers[2].name, sizeof(state[i].mod_name2));
        memcpy(state[i].observer_name1, state[0].peers[1].name, sizeof(state[i].observer_name1));
        memcpy(state[i].observer_name2, state[0].peers[2].name, sizeof(state[i].observer_name2));
    }

    /* founder checks his own role */
    TOX_ERR_GROUP_SELF_QUERY sq_err;
    TOX_GROUP_ROLE self_role = tox_group_self_get_role(toxes[0], state[0].group_number, &sq_err);
    ck_assert(sq_err == TOX_ERR_GROUP_SELF_QUERY_OK);
    ck_assert(self_role == TOX_GROUP_ROLE_FOUNDER);

    /* all peers should be user role except founder */
    for (size_t i = 1; i < NUM_GROUP_TOXES; ++i) {
        self_role = tox_group_self_get_role(toxes[i], state[i].group_number, &sq_err);
        ck_assert(sq_err == TOX_ERR_GROUP_SELF_QUERY_OK);
        ck_assert(self_role == TOX_GROUP_ROLE_USER);
    }

    /* founder sets first peer to moderator */
    fprintf(stderr, "Founder setting %s to moderator\n", state[0].peers[0].name);

    TOX_ERR_GROUP_MOD_SET_ROLE role_err;
    tox_group_mod_set_role(toxes[0], state[0].group_number, state[0].peers[0].peer_id, TOX_GROUP_ROLE_MODERATOR, &role_err);
    ck_assert_msg(role_err == TOX_ERR_GROUP_MOD_SET_ROLE_OK, "Failed to set moderator. error: %d", role_err);

    // manually flag the role setter because they don't get a callback
    state[0].mod_check = true;
    ++state[0].mod_event_count;
    check_mod_event(state, toxes, NUM_GROUP_TOXES, TOX_GROUP_MOD_EVENT_MODERATOR);

    check_self_role(state, toxes, state[0].peers[0].peer_id, TOX_GROUP_ROLE_MODERATOR);

    fprintf(stderr, "All peers successfully received mod event\n");

    /* founder sets second and third peer to observer */
    fprintf(stderr, "Founder setting %s to observer\n", state[0].peers[1].name);

    tox_group_mod_set_role(toxes[0], state[0].group_number, state[0].peers[1].peer_id, TOX_GROUP_ROLE_OBSERVER, &role_err);
    ck_assert_msg(role_err == TOX_ERR_GROUP_MOD_SET_ROLE_OK, "Failed to set observer. error: %d", role_err);

    state[0].observer_check = true;
    ++state[0].observer_event_count;
    check_mod_event(state, toxes, NUM_GROUP_TOXES, TOX_GROUP_MOD_EVENT_OBSERVER);

    fprintf(stderr, "All peers successfully received observer event 1\n");

    fprintf(stderr, "Founder setting %s to observer\n", state[0].peers[2].name);

    tox_group_mod_set_role(toxes[0], state[0].group_number, state[0].peers[2].peer_id, TOX_GROUP_ROLE_OBSERVER, &role_err);
    ck_assert_msg(role_err == TOX_ERR_GROUP_MOD_SET_ROLE_OK, "Failed to set observer. error: %d", role_err);

    state[0].observer_check = true;
    ++state[0].observer_event_count;
    check_mod_event(state, toxes, NUM_GROUP_TOXES, TOX_GROUP_MOD_EVENT_OBSERVER);

    check_self_role(state, toxes, state[0].peers[1].peer_id, TOX_GROUP_ROLE_OBSERVER);

    fprintf(stderr, "All peers successfully received observer event 2\n");

    /* New moderator promotes second peer back to user */
    uint32_t idx = get_state_index_by_nick(state, NUM_GROUP_TOXES, state[0].peers[0].name, state[0].peers[0].name_length);
    uint32_t obs_peer_id = get_peer_id_by_nick(state[idx].peers, NUM_GROUP_TOXES - 1, state[idx].observer_name1);

    fprintf(stderr, "%s is promoting %s back to user\n", state[idx].self_name, state[0].peers[1].name);

    tox_group_mod_set_role(toxes[idx], state[idx].group_number, obs_peer_id, TOX_GROUP_ROLE_USER, &role_err);
    ck_assert_msg(role_err == TOX_ERR_GROUP_MOD_SET_ROLE_OK, "Failed to promote observer back to user. error: %d",
                  role_err);

    state[idx].user_check = true;
    ++state[idx].user_event_count;
    check_mod_event(state, toxes, NUM_GROUP_TOXES, TOX_GROUP_MOD_EVENT_USER);

    fprintf(stderr, "All peers successfully received user event\n");

    /* founder assigns third peer to moderator (this triggers two events: user and moderator) */
    fprintf(stderr, "Founder setting %s to moderator\n", state[0].peers[2].name);

    tox_group_mod_set_role(toxes[0], state[0].group_number, state[0].peers[2].peer_id, TOX_GROUP_ROLE_MODERATOR, &role_err);
    ck_assert_msg(role_err == TOX_ERR_GROUP_MOD_SET_ROLE_OK, "Failed to set moderator. error: %d", role_err);

    state[0].mod_check = true;
    ++state[0].mod_event_count;
    check_mod_event(state, toxes, NUM_GROUP_TOXES, TOX_GROUP_MOD_EVENT_MODERATOR);

    check_self_role(state, toxes, state[0].peers[2].peer_id, TOX_GROUP_ROLE_MODERATOR);

    fprintf(stderr, "All peers successfully received moderator event\n");

    /* moderator attempts to demote and kick founder */
    uint32_t founder_peer_id = get_peer_id_by_nick(state[idx].peers, NUM_GROUP_TOXES - 1, state[0].self_name);
    tox_group_mod_set_role(toxes[idx], state[idx].group_number, founder_peer_id, TOX_GROUP_ROLE_OBSERVER, &role_err);
    ck_assert_msg(role_err != TOX_ERR_GROUP_MOD_SET_ROLE_OK, "Mod set founder to observer");

    TOX_ERR_GROUP_MOD_KICK_PEER k_err;
    tox_group_mod_kick_peer(toxes[idx], state[idx].group_number, founder_peer_id, &k_err);
    ck_assert_msg(k_err != TOX_ERR_GROUP_MOD_KICK_PEER_OK, "Mod kicked founder");

    /* founder kicks moderator (this triggers two events: user and kick) */
    fprintf(stderr, "Founder is kicking %s\n", state[0].peers[0].name);

    tox_group_mod_kick_peer(toxes[0], state[0].group_number, state[0].peers[0].peer_id, &k_err);
    ck_assert_msg(k_err == TOX_ERR_GROUP_MOD_KICK_PEER_OK, "Failed to kick peer. error: %d", k_err);

    state[0].kick_check = true;
    check_mod_event(state, toxes, NUM_GROUP_TOXES, TOX_GROUP_MOD_EVENT_KICK);

    fprintf(stderr, "All peers successfully received kick event\n");

    fprintf(stderr, "Founder is demoting moderator to user\n");

    tox_group_mod_set_role(toxes[0], state[0].group_number, state[0].peers[2].peer_id, TOX_GROUP_ROLE_USER, &role_err);
    ck_assert_msg(role_err == TOX_ERR_GROUP_MOD_SET_ROLE_OK, "Failed to demote peer 3 to User. error: %d", role_err);

    state[0].user_check = true;
    ++state[0].user_event_count;

    check_mod_event(state, toxes, NUM_GROUP_TOXES, TOX_GROUP_MOD_EVENT_USER);
    check_self_role(state, toxes, state[0].peers[2].peer_id, TOX_GROUP_ROLE_USER);

    for (size_t i = 0; i < NUM_GROUP_TOXES; i++) {
        TOX_ERR_GROUP_LEAVE err_exit;
        tox_group_leave(toxes[i], state[i].group_number, nullptr, 0, &err_exit);
        ck_assert(err_exit == TOX_ERR_GROUP_LEAVE_OK);
    }

    fprintf(stderr, "All tests passed!\n");
#endif  // VANILLA_NACL
}

int main(void)
{
    setvbuf(stdout, nullptr, _IONBF, 0);

    run_auto_test(nullptr, NUM_GROUP_TOXES, group_moderation_test, false);
    return 0;
}

#undef NUM_GROUP_TOXES
#undef GROUP_NAME
#undef GROUP_NAME_LEN
