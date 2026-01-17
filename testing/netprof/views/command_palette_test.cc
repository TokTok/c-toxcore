#include "../ui_test_support.hh"

namespace tox::netprof {

TEST_F(NetProfUITest, CommandPaletteToggle)
{
    ui_.get_main_container()->TakeFocus();
    EXPECT_FALSE(ui_.get_model().show_command_palette);
    ui_.handle_event(ftxui::Event::Character(':'));
    EXPECT_TRUE(ui_.get_model().show_command_palette);
    ui_.handle_event(ftxui::Event::Escape);
    EXPECT_FALSE(ui_.get_model().show_command_palette);
}

TEST_F(NetProfUITest, CommandPaletteVisualAndInputTest)
{
    ui_.get_main_container()->TakeFocus();
    auto screen = ftxui::Screen::Create(ftxui::Dimension::Fixed(100), ftxui::Dimension::Fixed(50));
    ftxui::Render(screen, ui_.get_main_container()->Render());
    EXPECT_EQ(screen.ToString().find("COMMAND PALETTE"), std::string::npos);

    ui_.get_main_container()->OnEvent(ftxui::Event::Character(':'));
    screen = ftxui::Screen::Create(ftxui::Dimension::Fixed(100), ftxui::Dimension::Fixed(50));
    ftxui::Render(screen, ui_.get_main_container()->Render());
    EXPECT_NE(screen.ToString().find("COMMAND PALETTE"), std::string::npos);

    ui_.emit(MsgReset{});
    ui_.process_messages();
    last_command_ = {CmdType::Step, {}};

    ui_.get_main_container()->OnEvent(ftxui::Event::Character('a'));
    EXPECT_EQ(ui_.get_model().command_input, "a");
    EXPECT_NE(last_command_.type, CmdType::AddNode);
}

TEST_F(NetProfUITest, CommandPaletteCompletionAndNavigation)
{
    ui_.get_main_container()->TakeFocus();
    ui_.handle_event(ftxui::Event::Character(':'));
    ui_.get_main_container()->OnEvent(ftxui::Event::Character('p'));

    bool found_pause = false;
    for (const auto &s : ui_.get_model().command_suggestions) {
        if (s.name == "pause")
            found_pause = true;
    }
    EXPECT_TRUE(found_pause);

    ASSERT_GT(ui_.get_model().command_suggestions.size(), 1u);
    int initial_index = ui_.get_model().command_selected_index;
    ui_.handle_event(ftxui::Event::ArrowDown);
    EXPECT_NE(ui_.get_model().command_selected_index, initial_index);

    ui_.get_main_container()->OnEvent(ftxui::Event::Return);
    EXPECT_FALSE(ui_.get_model().show_command_palette);
}

TEST_F(NetProfUITest, CommandPaletteRenderingAndScrolling)
{
    ui_.emit(MsgResize{150, 60});
    ui_.process_messages();
    ui_.get_main_container()->TakeFocus();
    ui_.handle_event(ftxui::Event::Special({16}));

    auto screen = ftxui::Screen::Create(ftxui::Dimension::Fixed(150), ftxui::Dimension::Fixed(60));
    ftxui::Render(screen, ui_.get_main_container()->Render());
    std::string output = screen.ToString();

    EXPECT_NE(output.find("add node"), std::string::npos);

    ui_.handle_event(ftxui::Event::ArrowUp);
    screen = ftxui::Screen::Create(ftxui::Dimension::Fixed(120), ftxui::Dimension::Fixed(60));
    ftxui::Render(screen, ui_.get_main_container()->Render());
    output = screen.ToString();

    EXPECT_NE(output.find("step"), std::string::npos);
}

}  // namespace tox::netprof
