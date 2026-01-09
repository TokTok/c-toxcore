/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2026 The TokTok team.
 */

#include "public/tox_network.hh"

#include <gtest/gtest.h>

namespace tox::test {
namespace {

    TEST(ToxNetworkTest, SetupConnectedFriends)
    {
        Simulation sim;
        sim.net().set_latency(5);
        auto main_node = sim.create_node();
        auto main_tox = main_node->create_tox();
        ASSERT_NE(main_tox, nullptr);

        const int num_friends = 3;
        auto friends = setup_connected_friends(sim, main_tox.get(), *main_node, num_friends);

        ASSERT_EQ(friends.size(), num_friends);

        for (const auto &f : friends) {
            EXPECT_NE(tox_friend_get_connection_status(main_tox.get(), f.friend_number, nullptr),
                TOX_CONNECTION_NONE);
        }

        // Verify they can actually communicate
        struct Context {
            int count = 0;
        } ctx;

        tox_callback_friend_message(main_tox.get(),
            [](Tox *, uint32_t, Tox_Message_Type, const uint8_t *, size_t, void *user_data) {
                static_cast<Context *>(user_data)->count++;
            });

        for (const auto &f : friends) {
            const uint8_t msg[] = "hello";
            tox_friend_send_message(
                f.tox.get(), 0, TOX_MESSAGE_TYPE_NORMAL, msg, sizeof(msg), nullptr);
        }

        sim.run_until([&]() {
            tox_iterate(main_tox.get(), &ctx);
            for (auto &f : friends) {
                tox_iterate(f.tox.get(), nullptr);
            }
            return ctx.count == num_friends;
        });

        EXPECT_EQ(ctx.count, num_friends);
    }

    TEST(ToxNetworkTest, Setup50ConnectedFriends)
    {
        Simulation sim;
        sim.net().set_latency(5);
        auto main_node = sim.create_node();
        auto main_tox = main_node->create_tox();
        ASSERT_NE(main_tox, nullptr);

        const int num_friends = 50;
        auto friends = setup_connected_friends(sim, main_tox.get(), *main_node, num_friends);

        ASSERT_EQ(friends.size(), num_friends);

        struct Context {
            int count = 0;
        } ctx;

        tox_callback_friend_message(main_tox.get(),
            [](Tox *, uint32_t, Tox_Message_Type, const uint8_t *, size_t, void *user_data) {
                static_cast<Context *>(user_data)->count++;
            });

        for (const auto &f : friends) {
            const uint8_t msg[] = "hello";
            tox_friend_send_message(
                f.tox.get(), 0, TOX_MESSAGE_TYPE_NORMAL, msg, sizeof(msg), nullptr);
        }

        sim.run_until(
            [&]() {
                tox_iterate(main_tox.get(), &ctx);
                for (auto &f : friends) {
                    tox_iterate(f.tox.get(), nullptr);
                }
                return ctx.count == num_friends;
            },
            60000);

        EXPECT_EQ(ctx.count, num_friends);
    }

    TEST(ToxNetworkTest, ConnectFriends)
    {
        Simulation sim;
        sim.net().set_latency(5);
        auto node1 = sim.create_node();
        auto tox1 = node1->create_tox();
        auto node2 = sim.create_node();
        auto tox2 = node2->create_tox();

        ASSERT_NE(tox1, nullptr);
        ASSERT_NE(tox2, nullptr);

        ASSERT_TRUE(connect_friends(sim, *node1, tox1.get(), *node2, tox2.get()));

        EXPECT_NE(tox_friend_get_connection_status(tox1.get(), 0, nullptr), TOX_CONNECTION_NONE);
        EXPECT_NE(tox_friend_get_connection_status(tox2.get(), 0, nullptr), TOX_CONNECTION_NONE);

        // Verify communication
        bool received = false;
        tox_callback_friend_message(tox2.get(),
            [](Tox *, uint32_t, Tox_Message_Type, const uint8_t *, size_t, void *user_data) {
                *static_cast<bool *>(user_data) = true;
            });

        const uint8_t msg[] = "hello";
        tox_friend_send_message(tox1.get(), 0, TOX_MESSAGE_TYPE_NORMAL, msg, sizeof(msg), nullptr);

        sim.run_until([&]() {
            tox_iterate(tox1.get(), nullptr);
            tox_iterate(tox2.get(), &received);
            return received;
        });

        EXPECT_TRUE(received);
    }

    TEST(ToxNetworkTest, SetupConnectedGroup)
    {
        Simulation sim;
        sim.net().set_latency(5);
        auto main_node = sim.create_node();
        auto main_tox = main_node->create_tox();
        ASSERT_NE(main_tox, nullptr);

        const int num_friends = 15;
        auto friends = setup_connected_friends(sim, main_tox.get(), *main_node, num_friends);
        ASSERT_EQ(friends.size(), num_friends);

        uint32_t group_number = setup_connected_group(sim, main_tox.get(), friends);
        EXPECT_NE(group_number, UINT32_MAX);

        // Verify we can send a group message
        struct Context {
            int count = 0;
        } ctx;

        tox_callback_group_message(main_tox.get(),
            [](Tox *, uint32_t, uint32_t, Tox_Message_Type, const uint8_t *, size_t, uint32_t,
                void *user_data) { static_cast<Context *>(user_data)->count++; });

        for (const auto &f : friends) {
            const uint8_t msg[] = "hello";
            uint32_t f_gn = 0;  // It should be 0 since it's the first group.
            Tox_Err_Group_Send_Message err_send;
            tox_group_send_message(
                f.tox.get(), f_gn, TOX_MESSAGE_TYPE_NORMAL, msg, sizeof(msg), &err_send);
            EXPECT_EQ(err_send, TOX_ERR_GROUP_SEND_MESSAGE_OK);
        }

        sim.run_until(
            [&]() {
                tox_iterate(main_tox.get(), &ctx);
                for (auto &f : friends) {
                    tox_iterate(f.tox.get(), nullptr);
                }
                return ctx.count == num_friends;
            },
            10000);

        EXPECT_EQ(ctx.count, num_friends);
    }

    TEST(ToxNetworkTest, Setup50ConnectedGroup)
    {
        Simulation sim;
        sim.net().set_latency(5);
        auto main_node = sim.create_node();
        auto main_tox = main_node->create_tox();
        ASSERT_NE(main_tox, nullptr);

        const int num_friends = 50;
        auto friends = setup_connected_friends(sim, main_tox.get(), *main_node, num_friends);
        ASSERT_EQ(friends.size(), num_friends);

        uint32_t group_number = setup_connected_group(sim, main_tox.get(), friends);
        EXPECT_NE(group_number, UINT32_MAX);

        struct Context {
            int count = 0;
        } ctx;

        tox_callback_group_message(main_tox.get(),
            [](Tox *, uint32_t, uint32_t, Tox_Message_Type, const uint8_t *, size_t, uint32_t,
                void *user_data) { static_cast<Context *>(user_data)->count++; });

        for (const auto &f : friends) {
            const uint8_t msg[] = "hello";
            uint32_t f_gn = 0;
            Tox_Err_Group_Send_Message err_send;
            tox_group_send_message(
                f.tox.get(), f_gn, TOX_MESSAGE_TYPE_NORMAL, msg, sizeof(msg), &err_send);
            EXPECT_EQ(err_send, TOX_ERR_GROUP_SEND_MESSAGE_OK);
        }

        sim.run_until(
            [&]() {
                tox_iterate(main_tox.get(), &ctx);
                for (auto &f : friends) {
                    tox_iterate(f.tox.get(), nullptr);
                }
                return ctx.count == num_friends;
            },
            120000);

        EXPECT_EQ(ctx.count, num_friends);
    }

}  // namespace
}  // namespace tox::test
