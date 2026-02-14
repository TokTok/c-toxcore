#include "dht_filter.hh"

#include "../ui_test_support.hh"

namespace tox::netprof {

TEST_F(NetProfUITest, DHTFilterInteractions)
{
    auto is_dht_filters_focused = [&]() { return ui_.get_dht_filter_controls()->Focused(); };

    auto screen = ftxui::Screen::Create(ftxui::Dimension::Fixed(150), ftxui::Dimension::Fixed(50));
    ftxui::Render(screen, ui_.get_main_container()->Render());

    EXPECT_TRUE(ui_.get_model().show_dht_responder_lines);
    EXPECT_TRUE(ui_.get_model().show_dht_discovery_lines);

    ui_.get_main_container()->OnEvent(ftxui::Event::Tab);  // Command Log
    ui_.get_main_container()->OnEvent(ftxui::Event::Tab);  // DHT Topology
    ui_.get_main_container()->OnEvent(ftxui::Event::Tab);  // DHT Filters
    EXPECT_TRUE(is_dht_filters_focused());
}

}  // namespace tox::netprof
