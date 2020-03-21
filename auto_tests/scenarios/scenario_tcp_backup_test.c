/* Tests that a friend_connection properly switches to using TCP relays when
 * the direct UDP connection fails, and switches back to using the direct
 * connection if it recovers.
 */

#include "framework/framework.h"

#define RELAY_TCP_PORT 33449
#define NUM_PEERS 2

typedef struct {
    bool seen_udp;
    bool seen_tcp;
} State;

static void wait_for_friend_connection_status(ToxNode *self, Tox_Connection expected_status)
{
    while (tox_scenario_is_running(self)) {
        const Tox_Connection connection_status = tox_node_get_friend_connection_status(self, 0);

        if (connection_status == expected_status) {
            return;
        }

        ck_assert(connection_status != TOX_CONNECTION_NONE);
        tox_scenario_yield(self);
    }
}

static void peer_script(ToxNode *self, void *ctx)
{
    State *state = (State *)ctx;
    // The relay is node 0, the peers are nodes 1 and 2.
    ToxNode *peer = tox_scenario_get_node(tox_node_get_scenario(self), 3 - tox_node_get_index(self));
    const State *peer_state = (const State *)tox_node_get_peer_ctx(peer);

    tox_node_wait_for_self_connected(self);
    tox_node_wait_for_friend_connected(self, 0);

    wait_for_friend_connection_status(self, TOX_CONNECTION_UDP);
    state->seen_udp = true;
    WAIT_UNTIL(peer_state->seen_udp);

    tox_node_log(self, "Simulating failure of the direct connection");
    tox_scenario_set_send_loss(self, peer, 100);

    tox_node_log(self, "Waiting to switch to using TCP relay");
    wait_for_friend_connection_status(self, TOX_CONNECTION_TCP);
    state->seen_tcp = true;
    WAIT_UNTIL(peer_state->seen_tcp);

    tox_node_log(self, "Simulating recovery of the direct connection");
    tox_scenario_set_send_loss(self, peer, 50);

    tox_node_log(self, "Waiting to switch to using direct connection");
    wait_for_friend_connection_status(self, TOX_CONNECTION_UDP);
}

static void relay_script(ToxNode *self, void *ctx)
{
    ToxScenario *s = tox_node_get_scenario(self);

    while (tox_scenario_is_running(self)) {
        bool all_finished = true;

        for (uint32_t i = 0; i < NUM_PEERS; ++i) {
            if (!tox_node_is_finished(tox_scenario_get_node(s, i + 1))) {
                all_finished = false;
                break;
            }
        }

        if (all_finished) {
            break;
        }

        tox_scenario_yield(self);
    }
}

int main(int argc, char *argv[])
{
    ToxScenario *s = tox_scenario_new(argc, argv, 300000);

    struct Tox_Options *opts_relay = tox_options_new(nullptr);
    tox_options_set_tcp_port(opts_relay, RELAY_TCP_PORT);
    tox_options_set_ipv6_enabled(opts_relay, false);
    tox_options_set_local_discovery_enabled(opts_relay, false);
    ToxNode *relay = tox_scenario_add_node_ex(s, "Relay", relay_script, nullptr, 0, opts_relay);
    tox_options_free(opts_relay);

    uint8_t relay_dht_id[TOX_PUBLIC_KEY_SIZE];
    tox_self_get_dht_id(tox_node_get_tox(relay), relay_dht_id);

    const uint16_t relay_tcp_port = tox_self_get_tcp_port(tox_node_get_tox(relay), nullptr);

    State states[NUM_PEERS] = {{0}};
    ToxNode *peers[NUM_PEERS];
    const char *const aliases[NUM_PEERS] = {"Alice", "Bob"};

    for (uint32_t i = 0; i < NUM_PEERS; ++i) {
        peers[i] = tox_scenario_add_node(s, aliases[i], peer_script, &states[i], sizeof(State));

        ck_assert(tox_add_tcp_relay(tox_node_get_tox(peers[i]), "127.0.0.1", relay_tcp_port, relay_dht_id, nullptr));
        tox_node_bootstrap(peers[i], relay);
    }

    tox_node_friend_add(peers[0], peers[1]);
    tox_node_friend_add(peers[1], peers[0]);

    const ToxScenarioStatus res = tox_scenario_run(s);

    if (res != TOX_SCENARIO_DONE) {
        tox_scenario_log(s, "Test failed with status %u", res);
        return 1;
    }

    tox_scenario_free(s);
    return 0;
}

#undef RELAY_TCP_PORT
#undef NUM_PEERS
