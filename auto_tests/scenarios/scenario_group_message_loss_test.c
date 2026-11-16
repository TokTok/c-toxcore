#include "framework/framework.h"
#include <stdio.h>
#include <string.h>

// Bob loses some of these messages, which come in bursts so that a lost one
// has others close behind it.
#define LOSSY_MESSAGES 600
#define BURST 6
// Bob takes in 1 waiting message per iteration, so Alice sends less than 1 per
// tick.
#define TICKS_BETWEEN_BURSTS 10
#define LOSS_PERCENT 5
// The rest come 1 at a time, so Bob looks at his receive array before each.
// They are more than a full ring of ids, so they reach the slots of the lossy
// ones again.
#define NUM_MESSAGES (LOSSY_MESSAGES + 2100)

typedef struct {
    uint32_t group_number;
    bool peer_joined;
    uint32_t sent;
    uint32_t received;
    // The first message that came out of order or twice.
    bool wrong;
    uint32_t wrong_got;
    uint32_t wrong_expected;
} LossState;

static void on_group_invite(const Tox_Event_Group_Invite *event, void *user_data)
{
    ToxNode *self = (ToxNode *)user_data;
    LossState *state = (LossState *)tox_node_get_script_ctx(self);
    Tox_Err_Group_Invite_Accept err;
    state->group_number = tox_group_invite_accept(tox_node_get_tox(self),
                          tox_event_group_invite_get_friend_number(event),
                          tox_event_group_invite_get_invite_data(event),
                          tox_event_group_invite_get_invite_data_length(event),
                          (const uint8_t *)"Bob", 3, nullptr, 0, &err);
    ck_assert(err == TOX_ERR_GROUP_INVITE_ACCEPT_OK);
}

static void on_group_peer_join(const Tox_Event_Group_Peer_Join *event, void *user_data)
{
    ToxNode *self = (ToxNode *)user_data;
    LossState *state = (LossState *)tox_node_get_script_ctx(self);
    state->peer_joined = true;
}

static void on_group_message(const Tox_Event_Group_Message *event, void *user_data)
{
    ToxNode *self = (ToxNode *)user_data;
    LossState *state = (LossState *)tox_node_get_script_ctx(self);

    char text[16] = {0};
    const size_t length = tox_event_group_message_get_message_length(event);
    ck_assert(length < sizeof(text));
    memcpy(text, tox_event_group_message_get_message(event), length);
    const uint32_t number = (uint32_t)strtoul(text, nullptr, 10);

    if (number != state->received && !state->wrong) {
        state->wrong = true;
        state->wrong_got = number;
        state->wrong_expected = state->received;
    }

    ++state->received;
}

static void send_messages(ToxNode *self, LossState *state, uint32_t until, uint32_t burst, uint32_t ticks)
{
    while (state->sent < until) {
        for (uint32_t i = 0; i < burst; ++i) {
            char text[16];
            const int length = snprintf(text, sizeof(text), "%u", state->sent);
            Tox_Err_Group_Send_Message err;
            tox_group_send_message(tox_node_get_tox(self), state->group_number, TOX_MESSAGE_TYPE_NORMAL,
                                   (const uint8_t *)text, (size_t)length, &err);
            ck_assert(err == TOX_ERR_GROUP_SEND_MESSAGE_OK);
            ++state->sent;
        }

        for (uint32_t i = 0; i < ticks; ++i) {
            tox_scenario_yield(self);
        }
    }
}

static void alice_script(ToxNode *self, void *ctx)
{
    LossState *state = (LossState *)ctx;
    Tox *tox = tox_node_get_tox(self);
    tox_events_callback_group_peer_join(tox_node_get_dispatch(self), on_group_peer_join);

    WAIT_UNTIL(tox_node_is_self_connected(self));
    WAIT_UNTIL(tox_node_is_friend_connected(self, 0));

    Tox_Err_Group_New err_new;
    state->group_number = tox_group_new(tox, TOX_GROUP_PRIVACY_STATE_PRIVATE, (const uint8_t *)"loss", 4,
                                        (const uint8_t *)"Alice", 5, &err_new);
    ck_assert(err_new == TOX_ERR_GROUP_NEW_OK);
    ck_assert(tox_group_invite_friend(tox, state->group_number, 0, nullptr));
    WAIT_UNTIL(state->peer_joined);

    ToxNode *bob = tox_scenario_get_node(tox_node_get_scenario(self), 1);
    const LossState *bob_state = (const LossState *)tox_node_get_peer_ctx(bob);

    // Only Alice's packets: lost acks would sometimes make her time Bob out.
    tox_scenario_set_send_loss(self, bob, LOSS_PERCENT);
    send_messages(self, state, LOSSY_MESSAGES, BURST, TICKS_BETWEEN_BURSTS);
    WAIT_UNTIL(bob_state->received >= LOSSY_MESSAGES);
    tox_scenario_set_send_loss(self, bob, 0);

    send_messages(self, state, NUM_MESSAGES, 1, 1);
    WAIT_UNTIL(bob_state->received >= NUM_MESSAGES);
}

static void bob_script(ToxNode *self, void *ctx)
{
    const LossState *state = (const LossState *)ctx;
    Tox_Dispatch *dispatch = tox_node_get_dispatch(self);
    tox_events_callback_group_invite(dispatch, on_group_invite);
    tox_events_callback_group_peer_join(dispatch, on_group_peer_join);
    tox_events_callback_group_message(dispatch, on_group_message);

    WAIT_UNTIL(tox_node_is_self_connected(self));
    WAIT_UNTIL(state->received >= NUM_MESSAGES);
}

int main(int argc, char *argv[])
{
    ToxScenario *s = tox_scenario_new(argc, argv, 600000);
    LossState alice_state = {0};
    LossState bob_state = {0};

    ToxNode *alice = tox_scenario_add_node(s, "Alice", alice_script, &alice_state, sizeof(LossState));
    ToxNode *bob = tox_scenario_add_node(s, "Bob", bob_script, &bob_state, sizeof(LossState));

    tox_node_friend_add(alice, bob);
    tox_node_friend_add(bob, alice);
    tox_node_bootstrap(alice, bob);
    tox_node_bootstrap(bob, alice);

    ck_assert(tox_scenario_run(s) == TOX_SCENARIO_DONE);
    tox_scenario_free(s);
    ck_assert_msg(!bob_state.wrong, "message %u came where %u was expected", bob_state.wrong_got,
                  bob_state.wrong_expected);
    return 0;
}

#undef LOSSY_MESSAGES
#undef BURST
#undef TICKS_BETWEEN_BURSTS
#undef LOSS_PERCENT
#undef NUM_MESSAGES
