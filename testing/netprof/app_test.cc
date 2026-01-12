#include "app.hh"

#include <gtest/gtest.h>

namespace tox::netprof {

class AppTest : public ::testing::Test {
protected:
    ~AppTest() override;
    NetProfApp app_{12345, false};
};

AppTest::~AppTest() = default;

TEST_F(AppTest, ConnectByName)
{
    // NetProfApp starts with Alice (1) and Bob (2) connected.
    // Let's add Charlie and Dave.
    app_.handle_command({CmdType::AddNode, {}});  // Adds Charlie (3)
    app_.handle_command({CmdType::AddNode, {}});  // Adds Dave (4)

    // Verify they are not connected initially.
    EXPECT_EQ(app_.manager().get_node_by_name("Charlie")->id(), 3u);
    EXPECT_EQ(app_.manager().get_node_by_name("Dave")->id(), 4u);

    // Connect them by name.
    app_.handle_command({CmdType::ConnectNodes, {"Charlie", "Dave"}});
    app_.ui().process_messages();

    // Verify connection intent exists.
    bool found = false;
    app_.manager().for_each_connection([&](const SimulationManager::ConnectionIntent &c) {
        if ((c.node_a == 3 && c.node_b == 4) || (c.node_a == 4 && c.node_b == 3)) {
            found = true;
        }
    });
    EXPECT_TRUE(found);

    // Verify UI model has the link.
    const auto &links = app_.ui().get_model().links;
    bool ui_found = false;
    for (const auto &l : links) {
        if ((l.from == 3 && l.to == 4) || (l.from == 4 && l.to == 3)) {
            ui_found = true;
            break;
        }
    }
    EXPECT_TRUE(ui_found);
}

TEST_F(AppTest, ConnectInitialAndAddedNode)
{
    // Alice (1) exists. Add Charlie (3).
    app_.handle_command({CmdType::AddNode, {}});
    app_.ui().process_messages();

    // Connect Alice and Charlie.
    app_.handle_command({CmdType::ConnectNodes, {"Alice", "Charlie"}});
    app_.ui().process_messages();

    // Verify UI model has the link.
    const auto &links = app_.ui().get_model().links;
    bool ui_found = false;
    for (const auto &l : links) {
        if ((l.from == 1 && l.to == 3) || (l.from == 3 && l.to == 1)) {
            ui_found = true;
            break;
        }
    }
    EXPECT_TRUE(ui_found);
}

TEST_F(AppTest, ConnectCaseInsensitive)
{
    // Add Charlie.
    app_.handle_command({CmdType::AddNode, {}});
    app_.ui().process_messages();

    // Try connecting with lowercase names.
    app_.handle_command({CmdType::ConnectNodes, {"alice", "charlie"}});
    app_.ui().process_messages();

    const auto &links = app_.ui().get_model().links;
    bool ui_found = false;
    for (const auto &l : links) {
        if ((l.from == 1 && l.to == 3) || (l.from == 3 && l.to == 1)) {
            ui_found = true;
            break;
        }
    }
    EXPECT_TRUE(ui_found) << "Connection by lowercase name should work";
}

TEST_F(AppTest, ConnectMixedCase)
{
    // Add Charlie.
    app_.handle_command({CmdType::AddNode, {}});
    app_.ui().process_messages();

    // Try connecting with mixed case names.
    app_.handle_command({CmdType::ConnectNodes, {"aLiCe", "CHarLIE"}});
    app_.ui().process_messages();

    const auto &links = app_.ui().get_model().links;
    bool ui_found = false;
    for (const auto &l : links) {
        if ((l.from == 1 && l.to == 3) || (l.from == 3 && l.to == 1)) {
            ui_found = true;
            break;
        }
    }
    EXPECT_TRUE(ui_found) << "Connection by mixed-case name should work";

    // Verify log message.
    const auto &logs = app_.ui().get_model().logs;
    bool log_found = false;
    for (const auto &entry : logs) {
        if (entry.message.find("Connected node") != std::string::npos) {
            log_found = true;
            break;
        }
    }
    EXPECT_TRUE(log_found);
}

TEST_F(AppTest, RemoveByName)
{
    EXPECT_NE(app_.manager().get_node_by_name("Alice"), nullptr);
    app_.handle_command({CmdType::RemoveNode, {"Alice"}});
    EXPECT_EQ(app_.manager().get_node_by_name("Alice"), nullptr);
}

TEST_F(AppTest, MoveByName)
{
    auto bob = app_.manager().get_node_by_name("Bob");
    EXPECT_FALSE(bob->is_pinned());
    app_.handle_command({CmdType::MoveNode, {"Bob", "10.0", "20.0"}});
    EXPECT_FLOAT_EQ(bob->x(), 10.0f);
    EXPECT_FLOAT_EQ(bob->y(), 20.0f);
    // Manual move should automatically pin the node.
    EXPECT_TRUE(bob->is_pinned());
}

TEST_F(AppTest, TogglePin)
{
    auto alice = app_.manager().get_node_by_name("Alice");
    EXPECT_FALSE(alice->is_pinned());

    // Pin it.
    app_.handle_command({CmdType::TogglePin, {"Alice"}});
    EXPECT_TRUE(alice->is_pinned());

    // Unpin it.
    app_.handle_command({CmdType::TogglePin, {"Alice"}});
    EXPECT_FALSE(alice->is_pinned());
}

TEST_F(AppTest, InvalidNumericInputDoesNotCrash)
{
    // This would have crashed before if it used std::stod directly.
    // "not_a_number" will fail safe_stod/safe_stoul and then fail name lookup.
    app_.handle_command({CmdType::SetSpeed, {"not_a_number"}});
    app_.handle_command({CmdType::ConnectNodes, {"NonExistent1", "NonExistent2"}});
}

TEST_F(AppTest, CommandEmitsCorrectLogLevel)
{
    app_.handle_command({CmdType::TogglePause, {}});
    app_.ui().process_messages();

    const auto &logs = app_.ui().get_model().logs;
    bool found = false;
    for (const auto &log : logs) {
        if (log.level == LogLevel::Command
            && (log.message.find("PAUSED") != std::string::npos
                || log.message.find("RESUMED") != std::string::npos)) {
            found = true;
            break;
        }
    }
    EXPECT_TRUE(found);
}

}  // namespace tox::netprof
