#include "framework/framework.h"
#include "../../toxcore/tox_private.h"
#include <stdio.h>
#include <string.h>

#define GROUP_NAME "Restore Lab"
#define GROUP_NAME_LEN (sizeof(GROUP_NAME) - 1)
#define PEER_LIMIT 42
#define MAX_STATE_SIZE 4096

typedef struct State {
    uint32_t group_number;
    bool joined;
    uint8_t peer_pk[TOX_GROUP_PEER_PUBLIC_KEY_SIZE];
    uint32_t peer_id;
    bool peer_joined;
    bool restored;
} State;

typedef struct Kept_Group {
    uint8_t chat_id[TOX_GROUP_CHAT_ID_SIZE];
    uint8_t self_secret_key[TOX_GROUP_SECRET_KEY_SIZE];
    uint8_t chat_secret_key[TOX_GROUP_SECRET_KEY_SIZE];
    bool founder;
    uint8_t state[MAX_STATE_SIZE];
    uint32_t state_length;
} Kept_Group;

static void on_group_invite(const Tox_Event_Group_Invite *event, void *user_data)
{
    ToxNode *self = (ToxNode *)user_data;
    State *state = (State *)tox_node_get_script_ctx(self);
    Tox_Err_Group_Invite_Accept err;
    state->group_number = tox_group_invite_accept(tox_node_get_tox(self), tox_event_group_invite_get_friend_number(event),
                          tox_event_group_invite_get_invite_data(event),
                          tox_event_group_invite_get_invite_data_length(event),
                          (const uint8_t *)"Bob", 3, nullptr, 0, &err);
    ck_assert(err == TOX_ERR_GROUP_INVITE_ACCEPT_OK);
}

static void on_group_self_join(const Tox_Event_Group_Self_Join *event, void *user_data)
{
    ToxNode *self = (ToxNode *)user_data;
    State *state = (State *)tox_node_get_script_ctx(self);
    state->joined = true;
}

static void on_group_peer_join(const Tox_Event_Group_Peer_Join *event, void *user_data)
{
    ToxNode *self = (ToxNode *)user_data;
    State *state = (State *)tox_node_get_script_ctx(self);
    state->peer_id = tox_event_group_peer_join_get_peer_id(event);
    ck_assert(tox_group_peer_get_public_key(tox_node_get_tox(self), tox_event_group_peer_join_get_group_number(event),
                                            state->peer_id, state->peer_pk, nullptr));
    state->peer_joined = true;
}

static void keep_group(Tox *tox, uint32_t group_number, Kept_Group *kept)
{
    ck_assert(tox_group_get_chat_id(tox, group_number, kept->chat_id, nullptr));
    ck_assert(tox_group_self_get_secret_key(tox, group_number, kept->self_secret_key, nullptr));

    Tox_Err_Group_Get_Chat_Secret_Key key_err;
    kept->founder = tox_group_get_chat_secret_key(tox, group_number, kept->chat_secret_key, &key_err);
    ck_assert(kept->founder ? key_err == TOX_ERR_GROUP_GET_CHAT_SECRET_KEY_OK
              : key_err == TOX_ERR_GROUP_GET_CHAT_SECRET_KEY_NOT_FOUNDER);

    Tox_Group_State *state = tox_group_get_state(tox, group_number, nullptr);
    ck_assert(state != nullptr);
    kept->state_length = tox_group_state_bytes_size(state);
    ck_assert(kept->state_length > 0 && kept->state_length <= MAX_STATE_SIZE);
    ck_assert(tox_group_state_get_bytes(state, kept->state));
    tox_group_state_free(state);
}

static uint32_t restore_group(Tox *tox, const Kept_Group *kept, const char *name, bool with_state)
{
    Tox_Group_State *state = nullptr;

    if (with_state) {
        Tox_Err_Group_State_Load load_err;
        state = tox_group_state_load(tox_get_system(tox), kept->state, kept->state_length, &load_err);
        ck_assert(load_err == TOX_ERR_GROUP_STATE_LOAD_OK);
    }

    Tox_Err_Group_Join_As err;
    const uint32_t group_number = tox_group_join_as(tox, kept->chat_id, TOX_GROUP_PRIVACY_STATE_PRIVATE,
                                  kept->self_secret_key, kept->founder ? kept->chat_secret_key : nullptr,
                                  (const uint8_t *)name, strlen(name), nullptr, 0, state, &err);
    ck_assert(err == TOX_ERR_GROUP_JOIN_AS_OK);
    tox_group_state_free(state);
    return group_number;
}

static void alice_script(ToxNode *self, void *ctx)
{
    State *state = (State *)ctx;
    Tox *tox = tox_node_get_tox(self);
    tox_events_callback_group_peer_join(tox_node_get_dispatch(self), on_group_peer_join);

    tox_node_wait_for_self_connected(self);
    tox_node_wait_for_friend_connected(self, 0);

    Tox_Err_Group_New err_new;
    state->group_number = tox_group_new(tox, TOX_GROUP_PRIVACY_STATE_PRIVATE, (const uint8_t *)GROUP_NAME,
                                        GROUP_NAME_LEN, (const uint8_t *)"Alice", 5, &err_new);
    ck_assert(err_new == TOX_ERR_GROUP_NEW_OK);
    ck_assert(tox_group_invite_friend(tox, state->group_number, 0, nullptr));
    WAIT_UNTIL(state->peer_joined);

    const uint32_t bob_id = state->peer_id;
    uint8_t bob_pk[TOX_GROUP_PEER_PUBLIC_KEY_SIZE];
    memcpy(bob_pk, state->peer_pk, sizeof(bob_pk));
    Tox_Err_Group_Set_Role role_err;
    tox_group_set_role(tox, state->group_number, bob_id, TOX_GROUP_ROLE_MODERATOR, &role_err);
    ck_assert(role_err == TOX_ERR_GROUP_SET_ROLE_OK);

    // Bob rejoins with his old key, so he is still a moderator.
    state->peer_joined = false;
    ToxNode *bob = tox_scenario_get_node(tox_node_get_scenario(self), 1);
    const State *bob_state = (const State *)tox_node_get_script_ctx(bob);
    WAIT_UNTIL(bob_state->restored && state->peer_joined);
    ck_assert(memcmp(state->peer_pk, bob_pk, sizeof(bob_pk)) == 0);
    WAIT_UNTIL(tox_group_peer_get_role(tox, state->group_number, state->peer_id, nullptr) == TOX_GROUP_ROLE_MODERATOR);
    tox_node_log(self, "Bob is back as the moderator.");

    Kept_Group kept;
    keep_group(tox, state->group_number, &kept);
    ck_assert(kept.founder);
    uint8_t self_pk[TOX_GROUP_PEER_PUBLIC_KEY_SIZE];
    ck_assert(tox_group_self_get_public_key(tox, state->group_number, self_pk, nullptr));

    tox_node_reload_moved(self);
    tox = tox_node_get_tox(self);
    tox_events_callback_group_peer_join(tox_node_get_dispatch(self), on_group_peer_join);
    ck_assert(tox_group_get_group_list_size(tox) == 0);

    tox_node_wait_for_self_connected(self);
    state->peer_joined = false;
    state->group_number = restore_group(tox, &kept, "Alice", true);
    WAIT_UNTIL(state->peer_joined);
    ck_assert(tox_group_self_get_role(tox, state->group_number, nullptr) == TOX_GROUP_ROLE_FOUNDER);

    uint8_t restored_pk[TOX_GROUP_PEER_PUBLIC_KEY_SIZE];
    ck_assert(tox_group_self_get_public_key(tox, state->group_number, restored_pk, nullptr));
    ck_assert(memcmp(restored_pk, self_pk, sizeof(self_pk)) == 0);

    Tox_Err_Group_Set_Peer_Limit limit_err;
    tox_group_set_peer_limit(tox, state->group_number, PEER_LIMIT, &limit_err);
    ck_assert(limit_err == TOX_ERR_GROUP_SET_PEER_LIMIT_OK);
    tox_node_log(self, "Back as the founder.");
    state->restored = true;

    // Bob and Alice both restart on a different port, so no peer is left in the group.
    // They restart one at a time, so each can bootstrap from the other.
    tox_scenario_barrier_wait(self);
    keep_group(tox, state->group_number, &kept);
    tox_scenario_barrier_wait(self);
    tox_scenario_barrier_wait(self);
    tox_node_reload_moved(self);
    tox = tox_node_get_tox(self);
    tox_events_callback_group_peer_join(tox_node_get_dispatch(self), on_group_peer_join);
    tox_scenario_barrier_wait(self);

    tox_node_wait_for_self_connected(self);
    state->peer_joined = false;
    state->group_number = restore_group(tox, &kept, "Alice", true);
    WAIT_UNTIL(state->peer_joined);
    WAIT_UNTIL(tox_group_peer_get_role(tox, state->group_number, state->peer_id, nullptr) == TOX_GROUP_ROLE_MODERATOR);
    ck_assert(tox_group_get_peer_limit(tox, state->group_number, nullptr) == PEER_LIMIT);
    tox_node_log(self, "Both are back.");
    tox_scenario_barrier_wait(self);
}

static void bob_script(ToxNode *self, void *ctx)
{
    State *state = (State *)ctx;
    Tox *tox = tox_node_get_tox(self);
    tox_events_callback_group_invite(tox_node_get_dispatch(self), on_group_invite);
    tox_events_callback_group_self_join(tox_node_get_dispatch(self), on_group_self_join);

    tox_node_wait_for_self_connected(self);
    tox_node_wait_for_friend_connected(self, 0);
    WAIT_UNTIL(state->joined);
    WAIT_UNTIL(tox_group_self_get_role(tox, state->group_number, nullptr) == TOX_GROUP_ROLE_MODERATOR);

    Kept_Group kept;
    keep_group(tox, state->group_number, &kept);
    ck_assert(!kept.founder);

    // Alice only knows the old port of Bob, and private groups are not announced, so Bob finds her
    // through their friend connection. He rejoins without a state, because Alice sends him the settings.
    tox_node_reload_moved(self);
    tox = tox_node_get_tox(self);
    ck_assert(tox_group_get_group_list_size(tox) == 0);

    tox_node_wait_for_self_connected(self);
    state->group_number = restore_group(tox, &kept, "Bob", false);
    WAIT_UNTIL(tox_group_self_get_role(tox, state->group_number, nullptr) == TOX_GROUP_ROLE_MODERATOR);
    tox_node_log(self, "Back as the moderator.");
    state->restored = true;

    // Bob receives the new peer limit after Alice rejoins as the founder.
    WAIT_UNTIL(tox_group_get_peer_limit(tox, state->group_number, nullptr) == PEER_LIMIT);

    tox_scenario_barrier_wait(self);
    keep_group(tox, state->group_number, &kept);
    tox_scenario_barrier_wait(self);
    tox_node_reload_moved(self);
    tox = tox_node_get_tox(self);
    tox_scenario_barrier_wait(self);
    tox_scenario_barrier_wait(self);

    // No other peer is in the group, so the state is needed to restore it.
    tox_node_wait_for_self_connected(self);
    state->group_number = restore_group(tox, &kept, "Bob", true);
    ck_assert(tox_group_self_get_role(tox, state->group_number, nullptr) == TOX_GROUP_ROLE_MODERATOR);
    tox_scenario_barrier_wait(self);
}

int main(int argc, char *argv[])
{
    ToxScenario *s = tox_scenario_new(argc, argv, 300000);
    State states[2] = {{0}};

    ToxNode *alice = tox_scenario_add_node(s, "Alice", alice_script, &states[0], sizeof(State));
    ToxNode *bob = tox_scenario_add_node(s, "Bob", bob_script, &states[1], sizeof(State));

    tox_node_bootstrap(bob, alice);
    tox_node_friend_add(alice, bob);
    tox_node_friend_add(bob, alice);

    ToxScenarioStatus res = tox_scenario_run(s);
    if (res != TOX_SCENARIO_DONE) {
        return 1;
    }

    tox_scenario_free(s);
    return 0;
}

#undef MAX_STATE_SIZE
#undef PEER_LIMIT
#undef GROUP_NAME_LEN
#undef GROUP_NAME
