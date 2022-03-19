#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <assert.h>
#include <stdint.h>
#include <string.h>

#include "../toxcore/announce_lookups.c"
#include "../toxcore/util.h"

#include "auto_test_support.h"
#include "check_compat.h"

static Lookup_Route random_dummy_route(uint16_t length)
{
    assert(length <= MAX_FORWARD_CHAIN_LENGTH);
    Lookup_Route route;
    route.chain_length = length;
    random_bytes(route.nodes[length].public_key, CRYPTO_PUBLIC_KEY_SIZE);
    return route;
}

static bool dummy_routes_eq(Lookup_Route route1, Lookup_Route route2)
{
    return (route1.chain_length == route2.chain_length
            && pk_equal(route_destination(&route1)->public_key,
                        route_destination(&route2)->public_key));
}

static void test_lookup_store_retrieve(void)
{
    uint8_t pk[CRYPTO_PUBLIC_KEY_SIZE];
    random_bytes(pk, CRYPTO_PUBLIC_KEY_SIZE);
    Lookup *const lookup = lookup_new(pk, 2, nullptr, nullptr);
    Lookup_Route route = random_dummy_route(2);

    lookup_add_node(lookup, &route, nullptr);
    Lookup_Node *node = lookup_find_node(lookup, route_destination(&route)->public_key);

    ck_assert(node != nullptr);
    ck_assert(dummy_routes_eq(route, node->route));

    delete_lookup_node(node);

    lookup_kill(lookup);
}

static void test_lookup_add_delete(void)
{
    uint8_t pk[CRYPTO_PUBLIC_KEY_SIZE];
    random_bytes(pk, CRYPTO_PUBLIC_KEY_SIZE);
    Lookup *const lookup = lookup_new(pk, 4, nullptr, nullptr);

    Lookup_Route route;

    for (uint32_t i = 0; i < 8; ++i) {
        ck_assert(num_lookup_nodes(lookup) == min_u16(4, i));
        route = random_dummy_route(2);
        lookup_add_node(lookup, &route, nullptr);
    }

    memcpy(route.nodes[route.chain_length].public_key, pk, CRYPTO_PUBLIC_KEY_SIZE);
    ck_assert(lookup_could_add_node(lookup, &route, nullptr));
    ck_assert(lookup_add_node(lookup, &route, nullptr));
    Lookup_Node *node = lookup_find_node(lookup, pk);
    ck_assert(node != nullptr);

    ck_assert(!lookup_could_add_node(lookup, &route, nullptr));
    ck_assert(!lookup_add_node(lookup, &route, nullptr));

    for (uint32_t i = 0; i < CRYPTO_PUBLIC_KEY_SIZE; ++i) {
        route.nodes[route.chain_length].public_key[i] = ~pk[i];
    }

    ck_assert(!lookup_could_add_node(lookup, &route, nullptr));
    ck_assert(!lookup_add_node(lookup, &route, nullptr));

    delete_lookup_node(node);
    ck_assert(num_lookup_nodes(lookup) == 3);
    ck_assert(lookup_find_node(lookup, pk) == nullptr);

    lookup_kill(lookup);
}

static void test_lookup_min(void)
{
    uint8_t pk[CRYPTO_PUBLIC_KEY_SIZE];
    random_bytes(pk, CRYPTO_PUBLIC_KEY_SIZE);
    Lookup *const lookup = lookup_new(pk, 8, nullptr, nullptr);

    Lookup_Route route;
    uint16_t num_shortest;
    Lookup_Route shortest_routes[8];

    for (uint32_t i = 0; i < 8; ++i) {
        uint16_t shortest = get_shortest_routes(lookup, shortest_routes, &num_shortest);
        ck_assert_msg(shortest == (i == 0 ? MAX_ROUTE_LENGTH + 1 : (i < 3 ? 3 : 2)),
                      "Shortest length %d after %d insertions", shortest, i);
        ck_assert_msg(num_shortest == (i < 2 ? i : (i < 3 ? 1 : i / 3)),
                      "Got %d shortest after %d insertions", num_shortest, i);
        route = random_dummy_route(1 + (i + 1) % 3);
        lookup_add_node(lookup, &route, nullptr);
    }

    route.chain_length = 0;
    memcpy(route.nodes[0].public_key, pk, CRYPTO_PUBLIC_KEY_SIZE);
    lookup_add_node(lookup, &route, nullptr);
    ck_assert(get_shortest_routes(lookup, shortest_routes, &num_shortest) == 1);
    ck_assert(num_shortest == 1);
    ck_assert(pk_equal(shortest_routes[0].nodes[0].public_key, pk));

    lookup_kill(lookup);
}

static uint64_t fake_time(Mono_Time *mono_time, void *user_data)
{
    return *((uint64_t *)user_data);
}

static void test_pending(void)
{
    uint8_t pk[CRYPTO_PUBLIC_KEY_SIZE], pk2[CRYPTO_PUBLIC_KEY_SIZE];
    random_bytes(pk, CRYPTO_PUBLIC_KEY_SIZE);
    Lookup *const lookup = lookup_new(pk, 4, nullptr, nullptr);
    Mono_Time *const mono_time = mono_time_new();
    uint64_t time = current_time_monotonic(mono_time);
    mono_time_set_current_time_callback(mono_time, fake_time, &time);

    for (uint32_t i = 0; i < 4; ++i) {
        random_bytes(pk2, CRYPTO_PUBLIC_KEY_SIZE);
        ck_assert_msg(add_pending(lookup, pk2, i, mono_time), "failed to add pending #%d", i + 1);
    }

    ck_assert_msg(!add_pending(lookup, pk2, 4, mono_time), "could re-add existing pending");
    ck_assert_msg(add_pending(lookup, pk, 4, mono_time), "failed to displace more distant pending");
    delete_pending(lookup, 4);
    random_bytes(pk2, CRYPTO_PUBLIC_KEY_SIZE);
    ck_assert_msg(add_pending(lookup, pk2, 5, mono_time), "failed to add pending after deletion");
    time += 1000 * PENDING_TIMEOUT;
    mono_time_update(mono_time);
    ck_assert_msg(add_pending(lookup, pk2, 6, mono_time), "failed to add pending after timeout");

    lookup_kill(lookup);
    mono_time_free(mono_time);
}

static void test_lookups(void)
{
    Lookups lookups = {0};
    uint8_t pk[CRYPTO_PUBLIC_KEY_SIZE], pk2[CRYPTO_PUBLIC_KEY_SIZE];
    random_bytes(pk, CRYPTO_PUBLIC_KEY_SIZE);
    random_bytes(pk2, CRYPTO_PUBLIC_KEY_SIZE);
    ck_assert(add_lookup(&lookups, pk, 8, nullptr, nullptr));
    ck_assert(add_lookup(&lookups, pk2, 8, nullptr, nullptr));
    Lookup *lookup = find_lookup(&lookups, pk);
    ck_assert(lookup != nullptr);
    ck_assert(pk_equal(pk, lookup->data_public_key));

    ck_assert(delete_lookup(&lookups, pk));
    ck_assert(find_lookup(&lookups, pk) == nullptr);

    ck_assert(add_lookup(&lookups, pk, 8, nullptr, nullptr));
    ck_assert(add_lookup(&lookups, pk, 4, nullptr, nullptr));
    lookup = find_lookup(&lookups, pk);
    ck_assert(lookup != nullptr);
    ck_assert(lookup->width == 4);
    ck_assert(delete_lookup(&lookups, pk));
    ck_assert(find_lookup(&lookups, pk) == nullptr);

    ck_assert(add_lookup(&lookups, pk, 4, nullptr, nullptr));
    free_lookups(&lookups);
}

int main(void)
{
    setvbuf(stdout, nullptr, _IONBF, 0);

    test_lookup_store_retrieve();
    test_lookup_add_delete();
    test_lookup_min();
    test_pending();
    test_lookups();

    return 0;
}
