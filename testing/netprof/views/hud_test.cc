#include "hud.hh"

#include "../ui_test_support.hh"

namespace tox::netprof {

TEST_F(NetProfUITest, HUDGraphEvolutionTest)
{
    {
        ui_.emit(MsgTick{{1000, 1.0, 0, 0, true}});
        ui_.process_messages();
        auto screen
            = ftxui::Screen::Create(ftxui::Dimension::Fixed(100), ftxui::Dimension::Fixed(50));
        ftxui::Render(screen, views::hud(ui_.get_model())->Render());
        std::string out = screen.ToString();
        EXPECT_NE(out.find("T+00:00:01.000"), std::string::npos);
        EXPECT_NE(out.find("PAUSED"), std::string::npos);
    }

    {
        ui_.emit(MsgTick{{5000, 1.0, 100, 1000, false}});
        ui_.process_messages();
        auto screen
            = ftxui::Screen::Create(ftxui::Dimension::Fixed(150), ftxui::Dimension::Fixed(50));
        ftxui::Render(screen, views::hud(ui_.get_model())->Render());
        std::string out = screen.ToString();
        EXPECT_NE(out.find("T+00:00:05.000"), std::string::npos);
        EXPECT_NE(out.find("RUNNING"), std::string::npos);
    }
}

TEST_F(NetProfUITest, SimulationSpeedCycle)
{
    ui_.emit(MsgTick{{0, 1.0, 0, 0, true}});
    ui_.process_messages();

    for (int i = 0; i < 19; ++i) {
        ui_.handle_event(ftxui::Event::Character('+'));
        ui_.emit(MsgTick{{0, std::stod(last_command_.args[0]), 0, 0, true}});
        ui_.process_messages();
    }

    EXPECT_DOUBLE_EQ(ui_.get_model().stats.real_time_factor, 0.0);

    ui_.handle_event(ftxui::Event::Character('='));
    EXPECT_EQ(last_command_.type, CmdType::SetSpeed);
    EXPECT_EQ(last_command_.args[0], "1.0");
}

}  // namespace tox::netprof
