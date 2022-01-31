/**
 * This autotest creates a small local DHT and makes sure that each peer can crawl
 * the entire DHT using the DHT getnodes api functions.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "../toxcore/tox.h"
#include "../toxcore/tox_private.h"
#include "auto_test_support.h"
#include "check_compat.h"

#define NUM_TOXES 30

typedef struct Dht_Node {
    uint8_t  public_key[TOX_DHT_NODE_PUBLIC_KEY_SIZE];
    char     ip[TOX_DHT_NODE_IP_STRING_SIZE];
    uint16_t port;
} Dht_Node;

typedef struct State {
    Dht_Node **nodes;
    size_t num_nodes;
    uint8_t **public_key_list;
} State;

static void free_nodes(Dht_Node **nodes, size_t num_nodes)
{
    for (size_t i = 0; i < num_nodes; ++i) {
        free(nodes[i]);
    }

    free(nodes);
}

static bool all_nodes_crawled(AutoTox *autotoxes, uint32_t num_toxes)
{
    size_t count = 0;

    for (uint32_t i = 0; i < num_toxes; ++i) {
        const State *state = (const State *)autotoxes[i].state;

        if (state->num_nodes == NUM_TOXES) {
            ++count;
        }
    }

    return count == NUM_TOXES;
}

static bool node_crawled(Dht_Node **nodes, size_t num_nodes, const uint8_t *public_key)
{
    for (uint32_t i = 0; i < num_nodes; ++i) {
        if (memcmp(nodes[i]->public_key, public_key, TOX_DHT_NODE_PUBLIC_KEY_SIZE) == 0) {
            return true;
        }
    }

    return false;
}

static void getnodes_response_cb(Tox *tox, const uint8_t *public_key, const char *ip, uint16_t port, void *user_data)
{
    ck_assert(user_data != nullptr);

    AutoTox *autotoxes = (AutoTox *)user_data;
    State *state = (State *)autotoxes->state;

    if (node_crawled(state->nodes, state->num_nodes, public_key)) {
        return;
    }

    ck_assert(state->num_nodes < NUM_TOXES);

    Dht_Node *node = calloc(1, sizeof(Dht_Node));
    ck_assert(node != nullptr);

    memcpy(node->public_key, public_key, TOX_DHT_NODE_PUBLIC_KEY_SIZE);
    snprintf(node->ip, sizeof(node->ip), "%s", ip);
    node->port = port;

    state->nodes[state->num_nodes] = node;
    ++state->num_nodes;

    // ask every new node to give us their close nodes to every public key
    for (size_t i = 0; i < NUM_TOXES; ++i) {
        tox_dht_get_nodes(tox, public_key, ip, port, state->public_key_list[i], nullptr);
    }
}

static void test_dht_getnodes(AutoTox *autotoxes)
{
    ck_assert(NUM_TOXES >= 2);

    uint8_t **public_key_list = calloc(NUM_TOXES, sizeof(uint8_t *));
    ck_assert(public_key_list != nullptr);

    for (size_t i = 0; i < NUM_TOXES; ++i) {
        tox_callback_dht_get_nodes_response(autotoxes[i].tox, getnodes_response_cb);

        State *state = (State *)autotoxes[i].state;

        state->nodes = (Dht_Node **)calloc(NUM_TOXES, sizeof(Dht_Node *));
        ck_assert(state->nodes != nullptr);
        state->num_nodes = 0;
        state->public_key_list = public_key_list;

        public_key_list[i] = malloc(TOX_PUBLIC_KEY_SIZE);
        tox_self_get_dht_id(autotoxes[i].tox, public_key_list[i]);
    }

    while (!all_nodes_crawled(autotoxes, NUM_TOXES)) {
        iterate_all_wait(autotoxes, NUM_TOXES, ITERATION_INTERVAL);
    }

    for (size_t i = 0; i < NUM_TOXES; ++i) {
        State *state = (State *)autotoxes[i].state;
        free_nodes(state->nodes, state->num_nodes);
        free(public_key_list[i]);
    }

    free(public_key_list);
}

int main(void)
{
    setvbuf(stdout, nullptr, _IONBF, 0);

    Run_Auto_Options options = default_run_auto_options;
    options.graph = GRAPH_LINEAR;

    run_auto_test(nullptr, NUM_TOXES, test_dht_getnodes, sizeof(State), &options);

    return 0;
}

#undef NUM_TOXES
