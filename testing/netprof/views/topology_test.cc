#include "topology.hh"

#include "../ui_test_support.hh"

namespace tox::netprof {

TEST_F(NetProfUITest, CursorModeToggle)
{
    ui_.get_topology_comp()->TakeFocus();
    EXPECT_TRUE(ui_.get_topology_comp()->Focused());

    EXPECT_FALSE(ui_.get_model().cursor_mode);
    ui_.handle_event(ftxui::Event::Character('c'));
    EXPECT_TRUE(ui_.get_model().cursor_mode);
    ui_.handle_event(ftxui::Event::Character('c'));
    EXPECT_FALSE(ui_.get_model().cursor_mode);
}

TEST_F(NetProfUITest, LayerToggleShortcut)
{
    ui_.get_topology_comp()->TakeFocus();
    EXPECT_EQ(ui_.get_model().layer_mode, LayerMode::Normal);
    ui_.handle_event(ftxui::Event::Character('l'));
    EXPECT_EQ(ui_.get_model().layer_mode, LayerMode::TrafficType);
    ui_.handle_event(ftxui::Event::Character('l'));
    EXPECT_EQ(ui_.get_model().layer_mode, LayerMode::Normal);
}

TEST_F(NetProfUITest, LayerCommandExecution)
{
    EXPECT_EQ(ui_.get_model().layer_mode, LayerMode::Normal);

    ui_.execute_command("layer traffic");
    EXPECT_EQ(ui_.get_model().layer_mode, LayerMode::TrafficType);

    ui_.execute_command("  layer normal  ");
    EXPECT_EQ(ui_.get_model().layer_mode, LayerMode::Normal);
}

TEST_F(NetProfUITest, PinnedNodeVisualIndicator)
{
    ui_.emit(MsgNodeAdded{1, "Alice", 50, 50});
    ui_.emit(MsgNodeStats{1, 0, 0, 0, 0, 0, 0, TOX_CONNECTION_NONE, true, true, 1, {}});
    ui_.process_messages();

    auto element = views::topology(ui_.get_model())->Render();
    auto screen = ftxui::Screen::Create(ftxui::Dimension::Fixed(200), ftxui::Dimension::Fixed(60));
    ftxui::Render(screen, element);

    std::string output = screen.ToString();
    EXPECT_NE(output.find("Alice [P]"), std::string::npos);
}

TEST_F(NetProfUITest, GrabAndDragNode)
{
    ui_.get_topology_comp()->TakeFocus();
    ui_.emit(MsgNodeAdded{1, "Alice", 20.0f, 20.0f});
    ui_.process_messages();

    ui_.handle_event(ftxui::Event::Character('c'));
    ui_.handle_event(ftxui::Event::Character('g'));

    ui_.handle_event(ftxui::Event::ArrowDown);
    ui_.process_messages();

    EXPECT_EQ(last_command_.type, CmdType::MoveNode);
    ASSERT_EQ(last_command_.args.size(), 3u);
    EXPECT_EQ(last_command_.args[0], "1");

    ui_.handle_event(ftxui::Event::Character('g'));
    EXPECT_FALSE(ui_.get_model().grab_mode);
}

TEST_F(NetProfUITest, DirectionalNavigation)
{
    ui_.emit(MsgNodeAdded{1, "Center", 50, 50});
    ui_.emit(MsgNodeAdded{2, "Left", 20, 50});
    ui_.emit(MsgNodeAdded{3, "Right", 80, 50});
    ui_.emit(MsgNodeAdded{4, "Up", 50, 20});
    ui_.emit(MsgNodeAdded{5, "Down", 50, 80});
    ui_.process_messages();

    ui_.select_node_in_direction(0, 0);
    EXPECT_EQ(ui_.get_model().selected_node_id, 1u);

    ui_.select_node_in_direction(1, 0);
    EXPECT_EQ(ui_.get_model().selected_node_id, 3u);

    ui_.select_node_in_direction(-1, 0);
    EXPECT_EQ(ui_.get_model().selected_node_id, 1u);
}

TEST_F(NetProfUITest, DHTInteractionBidirectionalDedupeTest)
{
    ui_.emit(MsgNodeAdded{1, "Alice", 10, 10});
    ui_.emit(MsgNodeAdded{2, "Bob", 90, 90});
    ui_.process_messages();

    ui_.emit(MsgDHTResponse{1, 2});
    ui_.process_messages();
    UIModel::InteractionKey key{1, 2, false};
    ASSERT_TRUE(ui_.get_model().dht_interactions.count(key));

    GlobalStats stats;
    stats.virtual_time_ms = 500;
    ui_.emit(MsgTick{stats});
    ui_.process_messages();

    ui_.emit(MsgDHTResponse{2, 1});
    ui_.process_messages();

    EXPECT_EQ(ui_.get_model().dht_interactions.size(), 1u);
    EXPECT_EQ(ui_.get_model().dht_interactions.at(key), 500u);
}

TEST_F(NetProfUITest, DHTInteractionRenderingTest)
{
    ui_.emit(MsgNodeAdded{1, "Alice", 10, 10});
    ui_.emit(MsgNodeAdded{2, "Bob", 90, 90});
    ui_.emit(MsgDHTResponse{1, 2});
    ui_.process_messages();

    UIModel model = ui_.get_model();
    model.show_dht_interactions_physical = true;
    model.screen_width = 200;
    model.screen_height = 100;

    auto element = views::topology(model)->Render();
    auto screen = ftxui::Screen::Create(ftxui::Dimension::Fixed(200), ftxui::Dimension::Fixed(100));
    ftxui::Render(screen, element);

    bool found_interaction_line = false;
    for (int y = 20; y < 80; ++y) {
        for (int x = 20; x < 180; ++x) {
            if (screen.at(x, y) != " " && screen.at(x, y) != "·") {
                found_interaction_line = true;
                break;
            }
        }
    }
    EXPECT_TRUE(found_interaction_line);
}

TEST_F(NetProfUITest, DeleteNodeSelectsNearest)
{
    ui_.emit(MsgNodeAdded{1, "Alice", 20.0f, 50.0f});
    ui_.emit(MsgNodeAdded{2, "Bob", 50.0f, 50.0f});
    ui_.emit(MsgNodeAdded{3, "Charlie", 80.0f, 50.0f});
    ui_.process_messages();

    ui_.select_node_in_direction(1, 0);
    EXPECT_EQ(ui_.get_model().selected_node_id, 2u);

    ui_.emit(MsgNodeRemoved{2});
    ui_.process_messages();

    EXPECT_NE(ui_.get_model().selected_node_id, 0u);
    EXPECT_TRUE(ui_.get_model().selected_node_id == 1u || ui_.get_model().selected_node_id == 3u);
}

TEST_F(NetProfUITest, DeleteMarkedNodeClearsMark)
{
    ui_.emit(MsgNodeAdded{1, "Alice"});
    ui_.emit(MsgNodeAdded{2, "Bob"});
    ui_.process_messages();

    ui_.select_node_in_direction(0, 0);
    ui_.handle_event(ftxui::Event::Character('f'));
    EXPECT_EQ(ui_.get_model().marked_node_id, 1u);

    ui_.emit(MsgNodeRemoved{1});
    ui_.process_messages();

    EXPECT_EQ(ui_.get_model().marked_node_id, 0u);
}

TEST_F(NetProfUITest, DisconnectNodesRemovesLink)
{
    ui_.emit(MsgNodeAdded{1, "Alice"});
    ui_.emit(MsgNodeAdded{2, "Bob"});
    ui_.emit(MsgLinkUpdated{1, 2, true, 20, 0.0});
    ui_.process_messages();

    EXPECT_EQ(ui_.get_model().links.size(), 1u);

    ui_.emit(MsgLinkUpdated{1, 2, false, 0, 0.0});
    ui_.process_messages();

    EXPECT_EQ(ui_.get_model().links.size(), 0u);
}

TEST_F(NetProfUITest, DeleteNodeRemovesLinks)
{
    ui_.emit(MsgNodeAdded{1, "Alice"});
    ui_.emit(MsgNodeAdded{2, "Bob"});
    ui_.emit(MsgLinkUpdated{1, 2, true, 20, 0.0});
    ui_.process_messages();

    ASSERT_EQ(ui_.get_model().links.size(), 1u);

    ui_.emit(MsgNodeRemoved{1});
    ui_.process_messages();

    EXPECT_EQ(ui_.get_model().links.size(), 0u);
}

TEST_F(NetProfUITest, NavigationToNodeZero)
{
    ui_.emit(MsgNodeAdded{1, "Alice", 20, 50});
    ui_.emit(MsgNodeAdded{2, "Bob", 80, 50});
    ui_.process_messages();

    EXPECT_EQ(ui_.get_model().selected_node_id, 1u);

    ui_.select_node_in_direction(1, 0);
    EXPECT_EQ(ui_.get_model().selected_node_id, 2u);

    ui_.select_node_in_direction(-1, 0);
    EXPECT_EQ(ui_.get_model().selected_node_id, 1u);
}

}  // namespace tox::netprof
