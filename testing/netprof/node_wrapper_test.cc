#include "node_wrapper.hh"

#include <gtest/gtest.h>

#include "../support/public/simulation.hh"

namespace tox::netprof {

class NodeWrapperTest : public ::testing::Test {
protected:
    ~NodeWrapperTest() override;
    tox::test::Simulation sim_{12345};
};

NodeWrapperTest::~NodeWrapperTest() = default;

TEST_F(NodeWrapperTest, Identity)
{
    NodeWrapper alice(sim_, 1, "Alice", false, 10.0f, 20.0f);
    EXPECT_EQ(alice.id(), 1u);
    EXPECT_EQ(alice.name(), "Alice");
    EXPECT_FLOAT_EQ(alice.x(), 10.0f);
    EXPECT_FLOAT_EQ(alice.y(), 20.0f);
}

TEST_F(NodeWrapperTest, Movement)
{
    NodeWrapper alice(sim_, 1, "Alice", false);
    alice.set_pos(30.0f, 40.0f);
    EXPECT_FLOAT_EQ(alice.x(), 30.0f);
    EXPECT_FLOAT_EQ(alice.y(), 40.0f);
}

TEST_F(NodeWrapperTest, OnlineStatus)
{
    NodeWrapper alice(sim_, 1, "Alice", false);
    EXPECT_TRUE(alice.is_online());

    alice.set_online(false);
    EXPECT_FALSE(alice.is_online());

    alice.set_online(true);
    EXPECT_TRUE(alice.is_online());
}

TEST_F(NodeWrapperTest, InitialStats)
{
    NodeWrapper alice(sim_, 1, "Alice", false);
    auto stats = alice.get_stats();

    EXPECT_EQ(stats.total_udp.count_sent, 0u);
    EXPECT_EQ(stats.total_udp.count_recv, 0u);
    EXPECT_EQ(stats.total_tcp.count_sent, 0u);
    EXPECT_EQ(stats.total_tcp.count_recv, 0u);
    EXPECT_EQ(stats.dht.num_closelist, 0u);
    EXPECT_EQ(stats.dht.connection_status, TOX_CONNECTION_NONE);
}

TEST_F(NodeWrapperTest, DHTId)
{
    NodeWrapper alice(sim_, 1, "Alice", false);
    auto dht_id = alice.get_dht_id();
    EXPECT_EQ(dht_id.size(), TOX_PUBLIC_KEY_SIZE);
}

}  // namespace tox::netprof
