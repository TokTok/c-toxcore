#include "inspector.hh"

#include "../../../toxcore/tox_private.h"
#include "../ui_test_support.hh"

namespace tox::netprof {

TEST_F(NetProfUITest, RenderInspectorDoesNotCrashOnEmptyHistory)
{
    ui_.emit(MsgNodeAdded{1, "Alice"});
    ui_.process_messages();

    auto element = views::inspector(ui_.get_model())->Render();
    auto screen = ftxui::Screen::Create(ftxui::Dimension::Fixed(40), ftxui::Dimension::Fixed(20));
    ftxui::Render(screen, element);
}

TEST_F(NetProfUITest, InspectorShowsNodeInfo)
{
    ui_.emit(MsgNodeAdded{42, "BobtheBuilder"});
    ui_.process_messages();

    auto element = views::inspector(ui_.get_model())->Render();
    auto screen = ftxui::Screen::Create(ftxui::Dimension::Fixed(100), ftxui::Dimension::Fixed(50));
    ftxui::Render(screen, element);

    std::string output = screen.ToString();
    EXPECT_NE(output.find("BobtheBuilder"), std::string::npos);
    EXPECT_NE(output.find("ID:   42"), std::string::npos);
}

TEST_F(NetProfUITest, InspectorResponsiveDHTActivity)
{
    ui_.emit(MsgNodeAdded{1, "Alice"});
    std::map<NodeInfo::ProtocolKey, NodeInfo::Traffic> breakdown;
    for (int i = 0; i < 20; ++i) {
        breakdown[{TOX_NETPROF_PACKET_TYPE_UDP, static_cast<uint8_t>(200 + i)}]
            = {static_cast<uint64_t>(1000 - i), 100};
    }
    ui_.emit(MsgNodeStats{1, 0, 0, 0, 0, 0, 0, TOX_CONNECTION_UDP, true, false, 1, breakdown});
    ui_.process_messages();

    {
        ui_.emit(MsgResize{120, 100});
        ui_.process_messages();
        auto element = views::inspector(ui_.get_model())->Render();
        auto screen
            = ftxui::Screen::Create(ftxui::Dimension::Fixed(120), ftxui::Dimension::Fixed(100));
        ftxui::Render(screen, element);
        std::string out = screen.ToString();
        EXPECT_NE(out.find("DHT Activity"), std::string::npos);
        EXPECT_NE(out.find("UDP 219"), std::string::npos);
    }

    {
        ui_.emit(MsgResize{120, 60});
        ui_.process_messages();
        auto element = views::inspector(ui_.get_model())->Render();
        auto screen
            = ftxui::Screen::Create(ftxui::Dimension::Fixed(120), ftxui::Dimension::Fixed(46));
        ftxui::Render(screen, element);
        std::string out = screen.ToString();
        EXPECT_NE(out.find("DHT Activity"), std::string::npos);
        EXPECT_NE(out.find("UDP 209"), std::string::npos);
        EXPECT_EQ(out.find("UDP 210"), std::string::npos);
        EXPECT_NE(out.find("... and 10 more"), std::string::npos);
    }
}

TEST_F(NetProfUITest, ProtocolBreakdownInInspector)
{
    std::map<NodeInfo::ProtocolKey, NodeInfo::Traffic> breakdown
        = {{{TOX_NETPROF_PACKET_TYPE_UDP, TOX_NETPROF_PACKET_ID_CRYPTO}, {400, 600}},
            {{TOX_NETPROF_PACKET_TYPE_UDP, TOX_NETPROF_PACKET_ID_ZERO}, {200, 300}}};
    ui_.emit(MsgNodeAdded{1, "Alice"});
    ui_.emit(MsgNodeStats{1, 0, 0, 0, 0, 0, 0, TOX_CONNECTION_NONE, true, false, 1, breakdown});
    ui_.emit(MsgResize{100, 50});
    ui_.process_messages();

    auto element = views::inspector(ui_.get_model())->Render();
    auto screen = ftxui::Screen::Create(ftxui::Dimension::Fixed(100), ftxui::Dimension::Fixed(50));
    ftxui::Render(screen, element);
    std::string output = screen.ToString();

    EXPECT_NE(output.find("PROTOCOL BREAKDOWN"), std::string::npos);
    EXPECT_NE(output.find("Encrypted Data"), std::string::npos);
    EXPECT_NE(output.find("400"), std::string::npos);
    EXPECT_NE(output.find("600"), std::string::npos);
    EXPECT_NE(output.find("Ping Req"), std::string::npos);
}

}  // namespace tox::netprof
