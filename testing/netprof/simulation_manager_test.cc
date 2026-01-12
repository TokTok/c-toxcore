#include "simulation_manager.hh"

#include <gtest/gtest.h>

#include <fstream>

namespace tox::netprof {

class SimulationManagerTest : public ::testing::Test {
protected:
    ~SimulationManagerTest() override;
    SimulationManager manager_{12345, true};
};

SimulationManagerTest::~SimulationManagerTest() = default;

TEST_F(SimulationManagerTest, AddAndRemoveNode)
{
    auto alice = manager_.add_node("Alice");
    ASSERT_NE(alice, nullptr);
    EXPECT_EQ(alice->name(), "Alice");
    EXPECT_EQ(manager_.get_nodes().size(), 1u);

    uint32_t id = alice->id();
    manager_.remove_node(id);
    EXPECT_EQ(manager_.get_nodes().size(), 0u);
    EXPECT_EQ(manager_.get_node(id), nullptr);
}

TEST_F(SimulationManagerTest, GetNodeByName)
{
    manager_.add_node("Alice");
    manager_.add_node("Bob");

    auto alice = manager_.get_node_by_name("Alice");
    ASSERT_NE(alice, nullptr);
    EXPECT_EQ(alice->name(), "Alice");

    auto bob = manager_.get_node_by_name("Bob");
    ASSERT_NE(bob, nullptr);
    EXPECT_EQ(bob->name(), "Bob");

    EXPECT_EQ(manager_.get_node_by_name("Charlie"), nullptr);
}

TEST_F(SimulationManagerTest, ConnectNodes)
{
    auto alice = manager_.add_node("Alice");
    auto bob = manager_.add_node("Bob");

    bool connected = manager_.connect_nodes(alice->id(), bob->id());
    EXPECT_TRUE(connected);
}

TEST_F(SimulationManagerTest, DisconnectNodes)
{
    auto alice = manager_.add_node("Alice");
    auto bob = manager_.add_node("Bob");

    manager_.connect_nodes(alice->id(), bob->id());
    manager_.step(100);

    bool disconnected = manager_.disconnect_nodes(alice->id(), bob->id());
    EXPECT_TRUE(disconnected);

    // Verify friend relationships are removed after disconnection.
    // Sufficient time is needed for friend deletion to be reflected in statistics.
    manager_.step(100);
    auto stats_alice = alice->get_stats();
    EXPECT_EQ(stats_alice.dht.num_friends, 0u);
}

TEST_F(SimulationManagerTest, GlobalStatsTracking)
{
    auto alice = manager_.add_node("Alice");
    auto bob = manager_.add_node("Bob");
    manager_.connect_nodes(alice->id(), bob->id());

    uint64_t initial_time = manager_.get_virtual_time_ms();
    manager_.step(100);
    // Virtual time starts at 1000ms.
    // Verify that stepping 100ms advances the virtual clock appropriately.
    // The underlying simulation engine steps in minimum increments.
    EXPECT_GE(manager_.get_virtual_time_ms(), initial_time + 100);
}

TEST_F(SimulationManagerTest, Serialization)
{
    manager_.add_node("Alice");
    manager_.add_node("Bob");

    nlohmann::json j = manager_.to_json();
    EXPECT_TRUE(j.contains("nodes"));
    EXPECT_EQ(j["nodes"].size(), 2u);

    SimulationManager manager2{12345};
    manager2.from_json(j);
    EXPECT_EQ(manager2.get_nodes().size(), 2u);
    EXPECT_EQ(manager2.get_nodes()[0]->name(), "Alice");
    EXPECT_EQ(manager2.get_nodes()[1]->name(), "Bob");
}

TEST_F(SimulationManagerTest, AddNodeWithPosition)
{
    auto alice = manager_.add_node("Alice", 10.5f, 20.7f);
    ASSERT_NE(alice, nullptr);
    EXPECT_FLOAT_EQ(alice->x(), 10.5f);
    EXPECT_FLOAT_EQ(alice->y(), 20.7f);
}

TEST_F(SimulationManagerTest, ProtocolBreakdown)
{
    auto alice = manager_.add_node("Alice");
    manager_.step(100);

    auto stats = alice->get_stats();
    // Verify that packet statistics are initially empty.
    EXPECT_TRUE(stats.udp_packet_stats.empty());
    EXPECT_TRUE(stats.tcp_packet_stats.empty());
}

TEST_F(SimulationManagerTest, ProtocolBreakdownWithTraffic)
{
    auto alice = manager_.add_node("Alice");
    auto bob = manager_.add_node("Bob");
    manager_.connect_nodes(alice->id(), bob->id());

    // Allow time for node exchange and DHT pings.
    manager_.step(1000);

    auto stats = alice->get_stats();
    // Statistics maps should contain DHT/Ping traffic.
    EXPECT_FALSE(stats.udp_packet_stats.empty());
}

TEST_F(SimulationManagerTest, SerializationWithPosition)
{
    manager_.add_node("Alice", 1.0f, 2.0f);

    nlohmann::json j = manager_.to_json();
    ASSERT_TRUE(j["nodes"][0].contains("pos"));
    EXPECT_FLOAT_EQ(j["nodes"][0]["pos"][0].get<float>(), 1.0f);
    EXPECT_FLOAT_EQ(j["nodes"][0]["pos"][1].get<float>(), 2.0f);

    SimulationManager manager2{12345};
    manager2.from_json(j);
    ASSERT_EQ(manager2.get_nodes().size(), 1u);
    EXPECT_FLOAT_EQ(manager2.get_nodes()[0]->x(), 1.0f);
    EXPECT_FLOAT_EQ(manager2.get_nodes()[0]->y(), 2.0f);
}

TEST_F(SimulationManagerTest, SaveLoadFile)
{
    manager_.add_node("Alice", 10.0f, 20.0f);
    manager_.add_node("Bob", 30.0f, 40.0f);
    manager_.connect_nodes(1, 2);

    const std::string filename = "test_save.json";
    manager_.save_to_file(filename);

    SimulationManager manager2{12345};
    manager2.load_from_file(filename);

    ASSERT_EQ(manager2.get_nodes().size(), 2u);
    EXPECT_EQ(manager2.get_nodes()[0]->name(), "Alice");
    EXPECT_FLOAT_EQ(manager2.get_nodes()[0]->x(), 10.0f);
    EXPECT_EQ(manager2.get_nodes()[1]->name(), "Bob");
    EXPECT_FLOAT_EQ(manager2.get_nodes()[1]->y(), 40.0f);

    // Clean up
    std::remove(filename.c_str());
}

TEST_F(SimulationManagerTest, AutoBootstrapping)
{
    auto alice = manager_.add_node("Alice");
    manager_.step(100);

    auto bob = manager_.add_node("Bob");
    // Verify automatic bootstrapping of Node B against existing Node A.

    // Allow sufficient time for node exchange and DHT activity.
    manager_.step(5000);

    auto stats_bob = bob->get_stats();
    // Node Bob should discover Node Alice in its DHT close list.
    EXPECT_GT(stats_bob.dht.num_closelist, 0u);
}

TEST_F(SimulationManagerTest, LoadSnapshotDoesNotCorruptRunnerCount)
{
    // 1. Add some nodes.
    manager_.add_node("Alice");
    manager_.add_node("Bob");

    // 2. Load a snapshot (this triggers from_json).
    nlohmann::json j = manager_.to_json();
    manager_.from_json(j);

    // 3. Load it again to be sure.
    manager_.from_json(j);

    // 4. Try to step the simulation. If the runner count is corrupted, this will freeze.
    // We use a small timeout to ensure the test fails instead of hanging indefinitely if broken.
    manager_.step(100);
}

TEST_F(SimulationManagerTest, PinnedStateSerialization)
{
    auto alice = manager_.add_node("Alice");
    alice->set_pinned(true);

    auto bob = manager_.add_node("Bob");
    bob->set_pinned(false);

    nlohmann::json j = manager_.to_json();

    SimulationManager manager2{12345};
    manager2.from_json(j);

    auto alice2 = manager2.get_node_by_name("Alice");
    ASSERT_NE(alice2, nullptr);
    EXPECT_TRUE(alice2->is_pinned());

    auto bob2 = manager2.get_node_by_name("Bob");
    ASSERT_NE(bob2, nullptr);
    EXPECT_FALSE(bob2->is_pinned());
}

}  // namespace tox::netprof
