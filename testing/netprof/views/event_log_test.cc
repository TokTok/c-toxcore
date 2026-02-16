#include "event_log.hh"

#include "../ui_test_support.hh"

namespace tox::netprof {

TEST_F(NetProfUITest, LogFiltering)
{
    ui_.emit(MsgLog{"Important event", LogLevel::Info});
    ui_.emit(MsgLog{"Spammy event", LogLevel::Info});
    ui_.process_messages();

    auto get_rendered_logs = [&]() {
        auto element = views::event_log(ui_.get_model())->Render();
        auto screen
            = ftxui::Screen::Create(ftxui::Dimension::Fixed(100), ftxui::Dimension::Fixed(10));
        ftxui::Render(screen, element);
        return screen.ToString();
    };

    std::string out = get_rendered_logs();
    EXPECT_NE(out.find("Important event"), std::string::npos);
    EXPECT_NE(out.find("Spammy event"), std::string::npos);

    ui_.execute_command("filter Important");
    out = get_rendered_logs();
    EXPECT_NE(out.find("Important event"), std::string::npos);
    EXPECT_EQ(out.find("Spammy event"), std::string::npos);
}

}  // namespace tox::netprof
