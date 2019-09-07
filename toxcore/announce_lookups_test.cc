/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2026 The TokTok team.
 */

#include "announce_lookups.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <memory>

#include "../testing/support/public/simulation.hh"
#include "attributes.h"
#include "crypto_core.h"
#include "mono_time.h"

namespace {

using tox::test::SimulatedNode;
using tox::test::Simulation;

class AnnounceLookupsTest : public ::testing::Test {
protected:
    void SetUp() override
    {
        sim = std::make_unique<Simulation>(12345);
        node = sim->create_node();
        sim->advance_time(1000);

        mono_time = mono_time_new(
            &node->c_memory,
            [](void *_Nullable user_data) -> std::uint64_t {
                return static_cast<Simulation *>(user_data)->clock().current_time_ms();
            },
            sim.get());
        mono_time_update(mono_time);

        random_bytes(&node->c_random, data_pk, sizeof(data_pk));
    }

    void TearDown() override { mono_time_free(&node->c_memory, mono_time); }

    const Memory *_Nonnull mem() const { return &node->c_memory; }

    Lookup_Route random_route(std::uint16_t chain_length)
    {
        Lookup_Route route{};
        route.chain_length = chain_length;
        random_bytes(&node->c_random, route.nodes[chain_length].public_key, CRYPTO_PUBLIC_KEY_SIZE);
        return route;
    }

    std::unique_ptr<Simulation> sim;
    std::unique_ptr<SimulatedNode> node;
    Mono_Time *_Nullable mono_time = nullptr;
    std::uint8_t data_pk[CRYPTO_PUBLIC_KEY_SIZE];
};

TEST_F(AnnounceLookupsTest, FindsAnAddedNodeWithItsRoute)
{
    Lookup *const lookup = lookup_new(mem(), data_pk, 2, nullptr, nullptr);
    ASSERT_NE(lookup, nullptr);
    const Lookup_Route route = random_route(2);

    ASSERT_TRUE(lookup_add_node(lookup, &route, nullptr));
    Lookup_Node *const found = lookup_find_node(lookup, route_destination_pk(&route));

    ASSERT_NE(found, nullptr);
    EXPECT_EQ(found->route.chain_length, route.chain_length);
    EXPECT_TRUE(pk_equal(route_destination_pk(&found->route), route_destination_pk(&route)));

    delete_lookup_node(found);
    EXPECT_EQ(lookup_find_node(lookup, route_destination_pk(&route)), nullptr);

    lookup_kill(mem(), lookup);
}

TEST_F(AnnounceLookupsTest, KeepsTheClosestNodesWhenFull)
{
    Lookup *const lookup = lookup_new(mem(), data_pk, 4, nullptr, nullptr);
    ASSERT_NE(lookup, nullptr);

    Lookup_Route route{};

    for (std::uint16_t i = 0; i < 8; ++i) {
        EXPECT_EQ(num_lookup_nodes(lookup), std::min<std::uint16_t>(4, i));
        route = random_route(2);
        lookup_add_node(lookup, &route, nullptr);
    }

    std::memcpy(route.nodes[route.chain_length].public_key, data_pk, CRYPTO_PUBLIC_KEY_SIZE);
    EXPECT_TRUE(lookup_could_add_node(lookup, &route, nullptr));
    ASSERT_TRUE(lookup_add_node(lookup, &route, nullptr));
    Lookup_Node *const closest = lookup_find_node(lookup, data_pk);
    ASSERT_NE(closest, nullptr);

    EXPECT_FALSE(lookup_could_add_node(lookup, &route, nullptr));
    EXPECT_FALSE(lookup_add_node(lookup, &route, nullptr));

    for (std::uint32_t i = 0; i < CRYPTO_PUBLIC_KEY_SIZE; ++i) {
        route.nodes[route.chain_length].public_key[i] = ~data_pk[i];
    }

    EXPECT_FALSE(lookup_could_add_node(lookup, &route, nullptr));
    EXPECT_FALSE(lookup_add_node(lookup, &route, nullptr));

    delete_lookup_node(closest);
    EXPECT_EQ(num_lookup_nodes(lookup), 3);
    EXPECT_EQ(lookup_find_node(lookup, data_pk), nullptr);

    lookup_kill(mem(), lookup);
}

TEST_F(AnnounceLookupsTest, RefusesOurOwnKey)
{
    Lookup *const lookup = lookup_new(mem(), data_pk, 4, nullptr, nullptr);
    ASSERT_NE(lookup, nullptr);
    const Lookup_Route route = random_route(1);

    EXPECT_FALSE(lookup_could_add_node(lookup, &route, route_destination_pk(&route)));
    EXPECT_FALSE(lookup_add_node(lookup, &route, route_destination_pk(&route)));
    EXPECT_EQ(num_lookup_nodes(lookup), 0);

    lookup_kill(mem(), lookup);
}

TEST_F(AnnounceLookupsTest, FindsTheShortestRoutes)
{
    Lookup *const lookup = lookup_new(mem(), data_pk, 8, nullptr, nullptr);
    ASSERT_NE(lookup, nullptr);

    Lookup_Route route{};
    std::uint16_t num_shortest = 0;
    Lookup_Route shortest_routes[8];

    for (std::uint16_t i = 0; i < 8; ++i) {
        const std::uint16_t shortest = get_shortest_routes(lookup, shortest_routes, &num_shortest);
        EXPECT_EQ(shortest, i == 0 ? MAX_ROUTE_LENGTH + 1 : (i < 3 ? 3 : 2)) << "after " << i;
        EXPECT_EQ(num_shortest, i < 2 ? i : (i < 3 ? 1 : i / 3)) << "after " << i;
        route = random_route(1 + (i + 1) % 3);
        lookup_add_node(lookup, &route, nullptr);
    }

    route.chain_length = 0;
    std::memcpy(route.nodes[0].public_key, data_pk, CRYPTO_PUBLIC_KEY_SIZE);
    lookup_add_node(lookup, &route, nullptr);
    EXPECT_EQ(get_shortest_routes(lookup, shortest_routes, &num_shortest), 1);
    ASSERT_EQ(num_shortest, 1);
    EXPECT_TRUE(pk_equal(shortest_routes[0].nodes[0].public_key, data_pk));

    lookup_kill(mem(), lookup);
}

TEST_F(AnnounceLookupsTest, ShortensRoutesThroughANodeWithAValidRoute)
{
    Lookup *const lookup = lookup_new(mem(), data_pk, 4, nullptr, nullptr);
    ASSERT_NE(lookup, nullptr);

    const Lookup_Route distant = random_route(2);
    ASSERT_TRUE(lookup_add_node(lookup, &distant, nullptr));

    Lookup_Route valid = random_route(1);
    valid.nodes[0] = *route_destination(&distant);
    lookup_route_valid(lookup, &valid);

    const Lookup_Node *const found = lookup_find_node(lookup, route_destination_pk(&distant));
    ASSERT_NE(found, nullptr);
    EXPECT_EQ(found->route.chain_length, 0);

    lookup_kill(mem(), lookup);
}

TEST_F(AnnounceLookupsTest, PendingResponsesMakeRoomByDistanceAndTimeout)
{
    Lookup *const lookup = lookup_new(mem(), data_pk, 4, nullptr, nullptr);
    ASSERT_NE(lookup, nullptr);
    std::uint8_t pk[CRYPTO_PUBLIC_KEY_SIZE];

    for (std::uint64_t i = 1; i <= 4; ++i) {
        random_bytes(&node->c_random, pk, sizeof(pk));
        EXPECT_TRUE(add_pending(lookup, pk, i, mono_time)) << "pending #" << i;
    }

    EXPECT_FALSE(add_pending(lookup, pk, 5, mono_time)) << "added the same key twice";
    EXPECT_TRUE(add_pending(lookup, data_pk, 5, mono_time)) << "didn't displace a more distant one";

    delete_pending(lookup, 5);
    random_bytes(&node->c_random, pk, sizeof(pk));
    EXPECT_TRUE(add_pending(lookup, pk, 6, mono_time)) << "no room after a deletion";

    sim->advance_time(1000 * (PENDING_TIMEOUT + 1));
    mono_time_update(mono_time);
    random_bytes(&node->c_random, pk, sizeof(pk));
    EXPECT_TRUE(add_pending(lookup, pk, 7, mono_time)) << "no room after the timeout";

    lookup_kill(mem(), lookup);
}

TEST_F(AnnounceLookupsTest, AddingAKeyAgainReplacesItsLookup)
{
    Lookups lookups{};
    std::uint8_t other_pk[CRYPTO_PUBLIC_KEY_SIZE];
    random_bytes(&node->c_random, other_pk, sizeof(other_pk));

    ASSERT_TRUE(add_lookup(&lookups, mem(), data_pk, 8, nullptr, nullptr));
    ASSERT_TRUE(add_lookup(&lookups, mem(), other_pk, 8, nullptr, nullptr));
    const Lookup *lookup = find_lookup(&lookups, data_pk);
    ASSERT_NE(lookup, nullptr);
    EXPECT_TRUE(pk_equal(lookup->data_public_key, data_pk));

    EXPECT_TRUE(delete_lookup(&lookups, mem(), data_pk));
    EXPECT_EQ(find_lookup(&lookups, data_pk), nullptr);
    EXPECT_FALSE(delete_lookup(&lookups, mem(), data_pk));

    ASSERT_TRUE(add_lookup(&lookups, mem(), data_pk, 8, nullptr, nullptr));
    ASSERT_TRUE(add_lookup(&lookups, mem(), data_pk, 4, nullptr, nullptr));
    EXPECT_EQ(lookups.num_lookups, 2);
    lookup = find_lookup(&lookups, data_pk);
    ASSERT_NE(lookup, nullptr);
    EXPECT_EQ(lookup->width, 4);

    free_lookups(&lookups, mem());
    EXPECT_EQ(lookups.num_lookups, 0);
}

}  // namespace
