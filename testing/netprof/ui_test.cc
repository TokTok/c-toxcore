#include "ui_test_support.hh"

namespace tox::netprof {

TEST_F(NetProfUITest, AddNodeUpdatesModel)
{
    ui_.emit(MsgNodeAdded{1, "Alice"});
    ui_.process_messages();

    const auto &model = ui_.get_model();
    ASSERT_EQ(model.nodes.size(), 1u);
    EXPECT_EQ(model.nodes.at(1).name, "Alice");
    EXPECT_EQ(model.selected_node_id, 1u);
}

TEST_F(NetProfUITest, UpdateStatsAddsToHistory)
{
    ui_.emit(MsgNodeAdded{1, "Alice"});
    ui_.emit(MsgNodeStats{1, 100, 200, 10, 5, 3, 2, TOX_CONNECTION_UDP, true, false, 1});
    ui_.process_messages();

    const auto &model = ui_.get_model();
    const auto &node = model.nodes.at(1);

    ASSERT_EQ(node.dht_neighbors_history.size(), kHistoryBufferSize);
    EXPECT_EQ(node.dht_neighbors_history.back(), 10);
    EXPECT_GT(node.bw_in_history.back(), 0);
    EXPECT_EQ(node.bw_in_history.back(), 30);
}

TEST_F(NetProfUITest, NodeMovedUpdatesModel)
{
    ui_.emit(MsgNodeAdded{1, "Alice", 10.0f, 10.0f});
    ui_.emit(MsgNodeMoved{1, 20.0f, 30.0f});
    ui_.process_messages();

    const auto &model = ui_.get_model();
    EXPECT_FLOAT_EQ(model.nodes.at(1).x, 20.0f);
    EXPECT_FLOAT_EQ(model.nodes.at(1).y, 30.0f);
}

TEST_F(NetProfUITest, EmitDuringInitializationRace)
{
    std::thread ui_thread([&]() { ui_.run(); });

    for (int i = 0; i < 1000; ++i) {
        ui_.emit(MsgLog{"Race test"});
        if (i == 500) {
            ui_.execute_command("quit");
        }
        std::this_thread::yield();
    }

    ui_thread.join();
}

TEST_F(NetProfUITest, TabPaneFocusTest)
{
    auto is_topo_focused = [&]() { return ui_.get_topology_comp()->Focused(); };
    auto is_dht_filters_focused = [&]() { return ui_.get_dht_filter_controls()->Focused(); };

    auto screen = ftxui::Screen::Create(ftxui::Dimension::Fixed(150), ftxui::Dimension::Fixed(50));
    ftxui::Render(screen, ui_.get_main_container()->Render());

    EXPECT_TRUE(is_topo_focused());
    EXPECT_FALSE(is_dht_filters_focused());

    EXPECT_TRUE(ui_.get_main_container()->OnEvent(ftxui::Event::Tab));  // Command Log
    EXPECT_FALSE(is_topo_focused());

    EXPECT_TRUE(ui_.get_main_container()->OnEvent(ftxui::Event::Tab));  // DHT Topology
    EXPECT_TRUE(ui_.get_main_container()->OnEvent(ftxui::Event::Tab));  // DHT Filters

    EXPECT_TRUE(is_dht_filters_focused());
}

TEST_F(NetProfUITest, SimulationSpeedConsistency)
{
    NetProfUI ui1([](auto) {});
    ui1.emit(MsgNodeAdded{1, "Alice"});
    for (int i = 0; i < 4; ++i) {
        ui1.emit(MsgNodeStats{1, 100, 200, 10, 5, 3, 2, TOX_CONNECTION_UDP, true, false, 1});
    }
    ui1.process_messages();

    NetProfUI ui4([](auto) {});
    ui4.emit(MsgNodeAdded{1, "Alice"});
    ui4.emit(MsgNodeStats{1, 100, 200, 10, 5, 3, 2, TOX_CONNECTION_UDP, true, false, 4});
    ui4.process_messages();

    NetProfUI ui05([](auto) {});
    ui05.emit(MsgNodeAdded{1, "Alice"});
    for (int i = 0; i < 4; ++i) {
        ui05.emit(MsgNodeStats{1, 100, 200, 10, 5, 3, 2, TOX_CONNECTION_UDP, true, false, 0});
        ui05.emit(MsgNodeStats{1, 100, 200, 10, 5, 3, 2, TOX_CONNECTION_UDP, true, false, 1});
    }
    ui05.process_messages();

    EXPECT_EQ(ui1.get_model().nodes.at(1).bw_in_history, ui4.get_model().nodes.at(1).bw_in_history);
    EXPECT_EQ(
        ui1.get_model().nodes.at(1).bw_in_history, ui05.get_model().nodes.at(1).bw_in_history);
    EXPECT_EQ(ui1.get_model().nodes.at(1).dht_neighbors_history,
        ui4.get_model().nodes.at(1).dht_neighbors_history);
    EXPECT_EQ(ui1.get_model().nodes.at(1).dht_neighbors_history,
        ui05.get_model().nodes.at(1).dht_neighbors_history);
    EXPECT_EQ(ui1.get_model().nodes.at(1).dht_response_history,
        ui4.get_model().nodes.at(1).dht_response_history);
    EXPECT_EQ(ui1.get_model().nodes.at(1).dht_response_history,
        ui05.get_model().nodes.at(1).dht_response_history);
}

TEST_F(NetProfUITest, SimulationSpeedConsistencyLarge)
{
    const uint32_t kLargeTicks = 500;

    // ui1: 500 messages, each with 1 response and 1 tick.
    NetProfUI ui1([](auto) {});
    ui1.emit(MsgNodeAdded{1, "Alice"});
    for (uint32_t i = 0; i < kLargeTicks; ++i) {
        ui1.emit(MsgDHTResponse{1, 2, 3});
        ui1.emit(MsgNodeStats{1, 100, 200, 10, 5, 3, 2, TOX_CONNECTION_UDP, true, false, 1});
    }
    ui1.process_messages();

    // uiLarge: 1 message with 500 ticks, after 500 responses.
    NetProfUI uiLarge([](auto) {});
    uiLarge.emit(MsgNodeAdded{1, "Alice"});
    for (uint32_t i = 0; i < kLargeTicks; ++i) {
        uiLarge.emit(MsgDHTResponse{1, 2, 3});
    }
    uiLarge.emit(
        MsgNodeStats{1, 100, 200, 10, 5, 3, 2, TOX_CONNECTION_UDP, true, false, kLargeTicks});
    uiLarge.process_messages();

    // Both should reach the target bandwidth.
    EXPECT_EQ(ui1.get_model().nodes.at(1).bw_in_history.back(), 100);
    EXPECT_EQ(uiLarge.get_model().nodes.at(1).bw_in_history.back(), 100);

    // Verify all 500 responses are preserved in the compressed history.
    const auto &h = uiLarge.get_model().nodes.at(1).dht_response_history;
    int total_responses = 0;
    for (int r : h) {
        total_responses += r;
    }
    EXPECT_EQ(total_responses, 500);

    // The compressed history should only have the last 40 samples modified.
    // (Actually 200 samples total, but the first 160 are 0s).
    EXPECT_EQ(h[159], 0);
    EXPECT_GT(h[160], 0);
}

}  // namespace tox::netprof
