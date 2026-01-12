#include "command_log.hh"

#include "../ui_test_support.hh"
#include "event_log.hh"

namespace tox::netprof {

TEST_F(NetProfUITest, LogSeparation)
{
    ui_.emit(MsgLog{"This is a command", LogLevel::Command});
    ui_.emit(MsgLog{"This is an event", LogLevel::Info});
    ui_.process_messages();

    auto event_view = views::event_log(ui_.get_model())->Render();
    auto screen = ftxui::Screen::Create(ftxui::Dimension::Fixed(100), ftxui::Dimension::Fixed(10));
    ftxui::Render(screen, event_view);
    std::string event_out = screen.ToString();
    EXPECT_NE(event_out.find("This is an event"), std::string::npos);
    EXPECT_EQ(event_out.find("This is a command"), std::string::npos);

    auto command_view = views::command_log(ui_.get_model())->Render();
    screen = ftxui::Screen::Create(ftxui::Dimension::Fixed(100), ftxui::Dimension::Fixed(10));
    ftxui::Render(screen, command_view);
    std::string command_out = screen.ToString();
    EXPECT_NE(command_out.find("This is a command"), std::string::npos);
    EXPECT_EQ(command_out.find("This is an event"), std::string::npos);
}

TEST_F(NetProfUITest, CommandLogLatestVisible)
{
    for (int i = 1; i <= 10; ++i) {
        ui_.emit(MsgLog{"Command " + std::to_string(i), LogLevel::Command});
    }
    ui_.process_messages();

    auto element = views::command_log(ui_.get_model())->Render();
    element |= ftxui::size(ftxui::HEIGHT, ftxui::EQUAL, 6);

    auto screen = ftxui::Screen::Create(ftxui::Dimension::Fixed(100), ftxui::Dimension::Fixed(6));
    ftxui::Render(screen, element);
    std::string out = screen.ToString();

    EXPECT_NE(out.find("Command 10"), std::string::npos);
    EXPECT_NE(out.find("Command 5"), std::string::npos);
    EXPECT_EQ(out.find("Command 4"), std::string::npos);
}

}  // namespace tox::netprof
