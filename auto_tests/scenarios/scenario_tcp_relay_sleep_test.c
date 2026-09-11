/* A relay must not go to sleep under a connection that is still awake on it.
 *
 * `set_tcp_connection_to_status(tcp_c, n, false)` counts a connection's online
 * slots as sleepers on their relay; the wake path has to take them back, or
 * every sleep -> wake -> sleep cycle leaves a phantom sleeper behind and
 * `lock_count == sleep_count` holds while an awake connection is still online
 * on the relay -- which `do_tcp_conns` then puts to sleep under it, and the
 * peer that had no other route to us is gone.
 *
 * Four nodes. Relay: a TCP relay. Alice and Bob: UDP on, so their connection
 * goes direct and Alice's TCP connection for Bob sleeps. Carol: UDP off, so
 * Alice reaches her only through the relay and that connection stays awake.
 * Bob goes offline for twelve seconds: past UDP_DIRECT_TIMEOUT, so Alice's
 * connection for him wakes, and short of FRIEND_CONNECTION_TIMEOUT, so it is
 * not dropped. Bob comes back, goes direct again, and Alice's connection for
 * him sleeps a second time. Before the fix that left one phantom sleeper on
 * the relay: with Bob's slot and Carol's slot online, lock_count 2 == sleep_count
 * 2, the relay slept, Carol's slot went with it, and Alice lost Carol. After
 * the fix Carol stays connected over TCP for as long as we care to watch.
 */

#include "framework/framework.h"

#include <stdio.h>

#define RELAY_TCP_PORT 33451

// Longer than UDP_DIRECT_TIMEOUT (8 s), so Alice's connection for Bob wakes;
// shorter than FRIEND_CONNECTION_TIMEOUT (32 s), so it is not dropped.
#define BOB_OFFLINE_MS 12000

// Longer than FRIEND_CONNECTION_TIMEOUT: a relay put to sleep under Carol's
// connection loses her within it.
#define WATCH_MS 60000

enum {
    NODE_RELAY = 0,
    NODE_ALICE = 1,
    NODE_BOB = 2,
    NODE_CAROL = 3,
};

// Alice's friend numbers, in the order the friends are added below.
enum {
    ALICE_FRIEND_BOB = 0,
    ALICE_FRIEND_CAROL = 1,
};

static void wait_for_alice(ToxNode *self)
{
    ToxScenario *s = tox_node_get_scenario(self);
    ToxNode *alice = tox_scenario_get_node(s, NODE_ALICE);
    WAIT_UNTIL(tox_node_is_finished(alice));
}

static void relay_script(ToxNode *self, void *ctx)
{
    (void)ctx;
    tox_scenario_barrier_wait(self);  // Bob goes offline.
    tox_scenario_barrier_wait(self);  // Bob is back.
    wait_for_alice(self);
}

static void alice_script(ToxNode *self, void *ctx)
{
    (void)ctx;
    ToxScenario *s = tox_node_get_scenario(self);

    tox_node_wait_for_self_connected(self);
    tox_node_wait_for_friend_connected(self, ALICE_FRIEND_BOB);
    tox_node_wait_for_friend_connected(self, ALICE_FRIEND_CAROL);

    // Bob direct: Alice's TCP connection for him goes to sleep on the relay.
    WAIT_UNTIL(tox_node_get_friend_connection_status(self, ALICE_FRIEND_BOB) == TOX_CONNECTION_UDP);
    // Carol through the relay only: that connection stays awake.
    WAIT_UNTIL(tox_node_get_friend_connection_status(self, ALICE_FRIEND_CAROL) == TOX_CONNECTION_TCP);
    tox_node_log(self, "Bob is direct, Carol is on the relay.");

    tox_scenario_barrier_wait(self);  // Bob goes offline.

    // Past UDP_DIRECT_TIMEOUT Bob is no longer direct, and Alice's connection
    // for him wakes. The friend connection itself survives the outage.
    WAIT_UNTIL(tox_node_get_friend_connection_status(self, ALICE_FRIEND_BOB) != TOX_CONNECTION_UDP);
    ck_assert_msg(tox_node_get_friend_connection_status(self, ALICE_FRIEND_BOB) == TOX_CONNECTION_TCP,
                  "Bob should have gone from direct to relayed, not away");
    tox_node_log(self, "Bob is no longer direct.");

    tox_scenario_barrier_wait(self);  // Bob is back.

    // Direct again: the connection for Bob sleeps a second time. This is the
    // cycle that used to leave a phantom sleeper on the relay.
    WAIT_UNTIL(tox_node_get_friend_connection_status(self, ALICE_FRIEND_BOB) == TOX_CONNECTION_UDP);
    tox_node_log(self, "Bob is direct again; watching Carol for %d s.", WATCH_MS / 1000);

    // The relay must stay up for Carol: her connection is awake on it, so the
    // relay's sleepers cannot equal its locks -- unless a phantom made up the
    // difference.
    const uint64_t until = tox_scenario_get_time(s) + WATCH_MS;
    while (tox_scenario_get_time(s) < until && tox_scenario_is_running(self)) {
        const Tox_Connection carol = tox_node_get_friend_connection_status(self, ALICE_FRIEND_CAROL);
        ck_assert_msg(carol == TOX_CONNECTION_TCP,
                      "Carol, reachable only through the relay, was lost (status %d) after Bob's "
                      "connection slept, woke and slept again: the relay went to sleep under her",
                      (int)carol);
        tox_scenario_yield(self);
    }

    tox_node_log(self, "Carol stayed on the relay throughout.");
}

static void bob_script(ToxNode *self, void *ctx)
{
    (void)ctx;

    tox_node_wait_for_self_connected(self);
    tox_node_wait_for_friend_connected(self, 0);
    WAIT_UNTIL(tox_node_get_friend_connection_status(self, 0) == TOX_CONNECTION_UDP);

    tox_scenario_barrier_wait(self);  // Bob goes offline.

    tox_node_log(self, "Going offline for %d s.", BOB_OFFLINE_MS / 1000);
    tox_node_set_offline(self, true);

    for (int i = 0; i < BOB_OFFLINE_MS / TOX_SCENARIO_TICK_MS; ++i) {
        tox_scenario_yield(self);
    }

    tox_node_log(self, "Back online.");
    tox_node_set_offline(self, false);

    tox_scenario_barrier_wait(self);  // Bob is back.

    wait_for_alice(self);
}

static void carol_script(ToxNode *self, void *ctx)
{
    (void)ctx;

    tox_node_wait_for_self_connected(self);
    tox_node_wait_for_friend_connected(self, 0);

    tox_scenario_barrier_wait(self);  // Bob goes offline.
    tox_scenario_barrier_wait(self);  // Bob is back.

    wait_for_alice(self);
}

int main(int argc, char *argv[])
{
    ToxScenario *s = tox_scenario_new(argc, argv, 300000);

    struct Tox_Options *opts_relay = tox_options_new(nullptr);
    tox_options_set_tcp_port(opts_relay, RELAY_TCP_PORT);
    ToxNode *relay = tox_scenario_add_node_ex(s, "Relay", relay_script, nullptr, 0, opts_relay);
    tox_options_free(opts_relay);

    uint8_t relay_dht_id[TOX_PUBLIC_KEY_SIZE];
    tox_self_get_dht_id(tox_node_get_tox(relay), relay_dht_id);
    const uint16_t relay_tcp_port = tox_self_get_tcp_port(tox_node_get_tox(relay), nullptr);

    ToxNode *alice = tox_scenario_add_node(s, "Alice", alice_script, nullptr, 0);
    ToxNode *bob = tox_scenario_add_node(s, "Bob", bob_script, nullptr, 0);

    // Carol has no UDP: the relay is her only road to Alice.
    struct Tox_Options *opts_carol = tox_options_new(nullptr);
    tox_options_set_udp_enabled(opts_carol, false);
    tox_options_set_local_discovery_enabled(opts_carol, false);
    ToxNode *carol = tox_scenario_add_node_ex(s, "Carol", carol_script, nullptr, 0, opts_carol);
    tox_options_free(opts_carol);

    ToxNode *nodes[] = {alice, bob, carol};

    for (size_t i = 0; i < sizeof(nodes) / sizeof(nodes[0]); ++i) {
        tox_add_tcp_relay(tox_node_get_tox(nodes[i]), "127.0.0.1", relay_tcp_port, relay_dht_id, nullptr);
        tox_node_bootstrap(nodes[i], relay);
    }

    // Alice's friend 0 is Bob, friend 1 is Carol (ALICE_FRIEND_*).
    tox_node_friend_add(alice, bob);
    tox_node_friend_add(bob, alice);
    tox_node_friend_add(alice, carol);
    tox_node_friend_add(carol, alice);

    ToxScenarioStatus res = tox_scenario_run(s);
    if (res != TOX_SCENARIO_DONE) {
        tox_scenario_log(s, "Test failed with status %u", res);
        return 1;
    }

    tox_scenario_free(s);
    return 0;
}
