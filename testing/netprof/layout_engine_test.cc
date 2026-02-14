#include "layout_engine.hh"

#include <gtest/gtest.h>

#include <cmath>

namespace tox::netprof {

TEST(LayoutEngineTest, AddAndRemoveNode)
{
    LayoutEngine engine(100, 100);
    engine.add_node(1, 50, 50);
    EXPECT_EQ(engine.nodes().size(), 1u);
    EXPECT_FLOAT_EQ(engine.nodes().at(1).x, 50.0f);
    EXPECT_FLOAT_EQ(engine.nodes().at(1).y, 50.0f);

    engine.remove_node(1);
    EXPECT_EQ(engine.nodes().size(), 0u);
}

TEST(LayoutEngineTest, RepulsionForce)
{
    LayoutEngine engine(100, 100);
    // Place two nodes close to each other in the center
    engine.add_node(1, 50, 50);
    engine.add_node(2, 51, 50);

    float initial_dist = 1.0f;

    // Step the simulation
    engine.step(0.1f);

    auto &n1 = engine.nodes().at(1);
    auto &n2 = engine.nodes().at(2);

    float dx = n2.x - n1.x;
    float dy = n2.y - n1.y;
    float final_dist = std::sqrt(dx * dx + dy * dy);

    // Nodes must move apart due to repulsion.
    EXPECT_GT(final_dist, initial_dist);
}

TEST(LayoutEngineTest, AttractionForce)
{
    LayoutEngine engine(100, 100);
    // Place two nodes far apart and connect them
    engine.add_node(1, 10, 10);
    engine.add_node(2, 90, 90);
    engine.add_link(1, 2);

    float dx_init = 80.0f;
    float dy_init = 80.0f;
    float initial_dist = std::sqrt(dx_init * dx_init + dy_init * dy_init);

    // Step the simulation multiple times to see the pull
    for (int i = 0; i < 10; ++i)
        engine.step(0.1f);

    auto &n1 = engine.nodes().at(1);
    auto &n2 = engine.nodes().at(2);

    float dx = n2.x - n1.x;
    float dy = n2.y - n1.y;
    float final_dist = std::sqrt(dx * dx + dy * dy);

    // Nodes must move closer due to attraction.
    EXPECT_LT(final_dist, initial_dist);
}

TEST(LayoutEngineTest, PinningNodes)
{
    LayoutEngine engine(100, 100);
    // Add a fixed node and a free node
    engine.add_node(1, 50, 50, true);  // fixed
    engine.add_node(2, 51, 50, false);  // free

    engine.step(0.1f);

    auto &n1 = engine.nodes().at(1);
    auto &n2 = engine.nodes().at(2);

    // Verify node 1 remains fixed.
    EXPECT_FLOAT_EQ(n1.x, 50.0f);
    EXPECT_FLOAT_EQ(n1.y, 50.0f);

    // Verify node 2 has moved.
    EXPECT_NE(n2.x, 51.0f);
}

TEST(LayoutEngineTest, Boundaries)
{
    LayoutEngine engine(100, 100);
    // Place node near the edge with velocity towards the edge
    engine.add_node(1, 2, 50);
    engine.update_node(1, 2, 50, false);  // Not fixed

    // Step multiple times with a lot of repulsion (simulated by adding another node)
    engine.add_node(2, 10, 50);  // Will push node 1 to the left

    for (int i = 0; i < 100; ++i)
        engine.step(0.5f);

    auto &n1 = engine.nodes().at(1);
    // Verify clamping to boundary (min 5.0 as per implementation).
    EXPECT_GE(n1.x, 5.0f);
}

TEST(LayoutEngineTest, TriangleNonCollinear)
{
    LayoutEngine engine(100, 100);
    // Create a triangle: 1-2, 2-3, 3-1
    // Start them perfectly collinear
    engine.add_node(1, 40, 40);
    engine.add_node(2, 60, 40);
    engine.add_node(3, 50, 40);  // Exactly on the line 1-2

    engine.add_link(1, 2);
    engine.add_link(2, 3);
    engine.add_link(3, 1);

    // Run for many steps to let it stabilize
    for (int i = 0; i < 500; ++i) {
        engine.step(0.1f);
    }

    auto &n1 = engine.nodes().at(1);
    auto &n2 = engine.nodes().at(2);
    auto &n3 = engine.nodes().at(3);

    // Calculate area of triangle (should be non-zero)
    float area
        = 0.5f * std::abs(n1.x * (n2.y - n3.y) + n2.x * (n3.y - n1.y) + n3.x * (n1.y - n2.y));

    // Ensure non-zero area, confirming collinearity was broken.
    EXPECT_GT(area, 10.0f);
}

TEST(LayoutEngineTest, ChainNonCollinear)
{
    LayoutEngine engine(100, 100);
    // Create a chain: 1-2, 2-3
    engine.add_node(1, 40, 40);
    engine.add_node(2, 50, 40);
    engine.add_node(3, 60, 40);

    engine.add_link(1, 2);
    engine.add_link(2, 3);

    // Run for steps
    for (int i = 0; i < 500; ++i) {
        engine.step(0.1f);
    }

    auto &n1 = engine.nodes().at(1);
    auto &n2 = engine.nodes().at(2);
    auto &n3 = engine.nodes().at(3);

    float area
        = 0.5f * std::abs(n1.x * (n2.y - n3.y) + n2.x * (n3.y - n1.y) + n3.x * (n1.y - n2.y));

    // Chain might remain nearly collinear, but jitter should prevent exactly zero area.
    EXPECT_GT(area, 0.01f);
}

TEST(LayoutEngineTest, ManyNodesStayInBounds)
{
    const float width = 100.0f;
    const float height = 100.0f;
    LayoutEngine engine(width, height);

    // Add 100 nodes in the same spot to create massive repulsion
    for (uint32_t i = 0; i < 100; ++i) {
        engine.add_node(i, 50, 50);
    }

    // Run for many steps
    for (int i = 0; i < 200; ++i) {
        engine.step(0.5f);
    }

    for (const auto &kv : engine.nodes()) {
        EXPECT_GE(kv.second.x, 0.0f);
        EXPECT_LE(kv.second.x, width);
        EXPECT_GE(kv.second.y, 0.0f);
        EXPECT_LE(kv.second.y, height);
    }
}

TEST(LayoutEngineTest, Stabilization)
{
    LayoutEngine engine(100, 100);
    engine.add_node(1, 40, 40);
    engine.add_node(2, 60, 60);
    engine.add_link(1, 2);

    EXPECT_FALSE(engine.is_stabilized());

    // Run until it stabilizes or we reach a timeout (many steps)
    bool stabilized = false;
    for (int i = 0; i < 2000; ++i) {
        engine.step(0.1f);
        if (engine.is_stabilized()) {
            stabilized = true;
            break;
        }
    }

    EXPECT_TRUE(stabilized);
    EXPECT_TRUE(engine.is_stabilized());

    // Verify that adding a node de-stabilizes the layout.
    engine.add_node(3, 10, 10);
    EXPECT_FALSE(engine.is_stabilized());
}

}  // namespace tox::netprof
