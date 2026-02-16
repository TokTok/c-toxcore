#include "dht_topology.hh"

#include "../ui_test_support.hh"

namespace tox::netprof {

TEST_F(NetProfUITest, DHTTopologyRenderTest)
{
    std::vector<uint8_t> dht_id(32, 0);
    dht_id[0] = 0x80;
    ui_.emit(MsgNodeAdded{1, "Alice", 10, 10, dht_id});
    ui_.process_messages();

    auto element = views::dht_topology(ui_.get_model())->Render();
    auto screen = ftxui::Screen::Create(ftxui::Dimension::Fixed(100), ftxui::Dimension::Fixed(50));
    ftxui::Render(screen, element);

    std::string output = screen.ToString();
    EXPECT_NE(output.find("Alice"), std::string::npos);
}

TEST_F(NetProfUITest, DHTRadialStackingTest)
{
    std::vector<uint8_t> dht_id(32, 0);
    dht_id[0] = 0x40;
    ui_.emit(MsgNodeAdded{1, "Alice", 10, 10, dht_id});
    ui_.emit(MsgNodeAdded{2, "Bob", 10, 10, dht_id});
    ui_.emit(MsgResize{306, 100});
    ui_.process_messages();

    auto element = views::dht_topology(ui_.get_model())->Render();
    auto screen = ftxui::Screen::Create(ftxui::Dimension::Fixed(306), ftxui::Dimension::Fixed(100));
    ftxui::Render(screen, element);

    auto find_node_y = [&](const std::string &name) {
        for (int y = 0; y < 100; ++y) {
            std::string line;
            for (int x = 0; x < 200; ++x)
                line += screen.at(x, y);
            if (line.find(name) != std::string::npos)
                return y;
        }
        return -1;
    };

    int alice_y = find_node_y("Alice");
    int bob_y = find_node_y("Bob");

    ASSERT_NE(alice_y, -1);
    ASSERT_NE(bob_y, -1);
    EXPECT_NE(alice_y, bob_y);
}

}  // namespace tox::netprof
