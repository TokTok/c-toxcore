// clang-format off
#include "group_connection.h"
// clang-format on

#include <gtest/gtest.h>

#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "../testing/support/public/simulation.hh"
#include "../testing/support/public/tox_network.hh"
#include "Messenger.h"
#include "group_chats.h"
#include "group_common.h"
#include "logger.h"
#include "mem.h"
#include "mono_time.h"
#include "network.h"
#include "os_memory.h"
#include "os_random.h"
#include "tox.h"
#include "tox_struct.h"

namespace {

using tox::test::SimulatedNode;

// Alice and Bob share a private group on a simulated network that can drop
// packets between them.
class GroupLossless : public ::testing::Test {
protected:
    void SetUp() override
    {
        ASSERT_NE(alice_, nullptr);
        ASSERT_NE(bob_, nullptr);
        ASSERT_TRUE(
            tox::test::connect_friends(sim_, *alice_node_, alice_.get(), *bob_node_, bob_.get()));

        tox_callback_group_invite(bob_.get(),
            [](Tox *tox, uint32_t friend_number, const uint8_t *data, size_t length,
                const uint8_t *, size_t, void *user_data) {
                const uint8_t name[] = "bob";
                static_cast<GroupLossless *>(user_data)->bob_group_ = tox_group_invite_accept(
                    tox, friend_number, data, length, name, sizeof(name) - 1, nullptr, 0, nullptr);
            });
        tox_callback_group_self_join(bob_.get(), [](Tox *, uint32_t, void *user_data) {
            static_cast<GroupLossless *>(user_data)->joined_ = true;
        });

        const uint8_t group_name[] = "lossless";
        const uint8_t name[] = "alice";
        Tox_Err_Group_New err;
        alice_group_ = tox_group_new(alice_.get(), TOX_GROUP_PRIVACY_STATE_PRIVATE, group_name,
            sizeof(group_name) - 1, name, sizeof(name) - 1, &err);
        ASSERT_EQ(err, TOX_ERR_GROUP_NEW_OK);
        ASSERT_TRUE(tox_group_invite_friend(alice_.get(), alice_group_, 0, nullptr));

        run_until([&]() { return joined_; }, 30000);
        ASSERT_TRUE(joined_);
        run_for(5000);
        const GC_Connection *alice_conn = conn(alice_.get(), alice_group_);
        const GC_Connection *bob_conn = conn(bob_.get(), bob_group_);
        ASSERT_NE(alice_conn, nullptr);
        ASSERT_NE(bob_conn, nullptr);
        ASSERT_TRUE(alice_conn->confirmed);
        ASSERT_TRUE(bob_conn->confirmed);

        sim_.net().add_filter([this](tox::test::Packet &p) { return !(drop_ && drop_(p)); });
    }

    // The filter outlives the test's locals.
    void TearDown() override { drop_ = nullptr; }

    static bool is_group_packet(const tox::test::Packet &p, uint8_t type, const SimulatedNode &to)
    {
        return !p.data.empty() && p.data[0] == type && ip_equal(&p.to.ip, &to.ip);
    }

    // Peer 0 is us, so peer 1 is the other one.
    static GC_Connection *conn(const Tox *tox, uint32_t group_number)
    {
        GC_Chat *chat = gc_get_group(tox->m->group_handler, group_number);
        return chat == nullptr ? nullptr : get_gc_connection(chat, 1);
    }

    void send(const std::string &message)
    {
        Tox_Err_Group_Send_Message err;
        tox_group_send_message(alice_.get(), alice_group_, TOX_MESSAGE_TYPE_NORMAL,
            reinterpret_cast<const uint8_t *>(message.data()), message.size(), &err);
        EXPECT_EQ(err, TOX_ERR_GROUP_SEND_MESSAGE_OK);
    }

    void run_until(std::function<bool()> condition, uint64_t timeout_ms)
    {
        sim_.run_until(
            [&]() {
                tox_iterate(alice_.get(), this);
                tox_iterate(bob_.get(), this);
                return condition();
            },
            timeout_ms);
    }

    void run_for(uint64_t ms)
    {
        run_until([]() { return false; }, ms);
    }

    std::function<bool(const tox::test::Packet &)> drop_;

    tox::test::Simulation sim_{12345};
    std::unique_ptr<SimulatedNode> alice_node_ = sim_.create_node();
    std::unique_ptr<SimulatedNode> bob_node_ = sim_.create_node();
    SimulatedNode::ToxPtr alice_ = alice_node_->create_tox();
    SimulatedNode::ToxPtr bob_ = bob_node_->create_tox();
    uint32_t alice_group_ = 0;
    uint32_t bob_group_ = 0;
    bool joined_ = false;
};

// Bob gets the second message first and keeps it until the first comes. His
// ack then stops Alice from sending it again.
TEST_F(GroupLossless, AcknowledgesAMessageHeldForAnEarlierOne)
{
    const std::string first(1, 'a');
    const std::string second(400, 'b');
    constexpr size_t kLarge = 200;

    // The first send of the first message is lost.
    bool lost_first = false;
    int sends_of_second = 0;
    drop_ = [&](const tox::test::Packet &p) {
        if (!is_group_packet(p, NET_PACKET_GC_LOSSLESS, *bob_node_)) {
            return false;
        }
        if (p.data.size() < kLarge) {
            return !std::exchange(lost_first, true);
        }
        ++sends_of_second;
        return false;
    };

    // Send them 1 s apart, so Bob acks the second message before Alice would send it
    // again.
    send(first);
    run_for(1000);
    send(second);
    run_for(10000);

    EXPECT_TRUE(lost_first);
    EXPECT_EQ(sends_of_second, 1);
}

class GroupConnection : public ::testing::Test {
protected:
    void SetUp() override
    {
        ASSERT_NE(log_, nullptr);
        ASSERT_NE(mono_time_, nullptr);

        chat_->log = log_;
        chat_->mem = mem_;
        chat_->secure_mem = mem_;
        chat_->rng = os_random();
        chat_->mono_time = mono_time_;

        gconn_.send_array = static_cast<GC_Message_Array_Entry *>(
            mem_valloc(mem_, GCC_BUFFER_SIZE, sizeof(GC_Message_Array_Entry)));
        gconn_.recv_array = static_cast<GC_Message_Array_Entry *>(
            mem_valloc(mem_, GCC_BUFFER_SIZE, sizeof(GC_Message_Array_Entry)));
        ASSERT_NE(gconn_.send_array, nullptr);
        ASSERT_NE(gconn_.recv_array, nullptr);

        gconn_.session_keys
            = static_cast<GC_Session_Keys *>(mem_alloc(mem_, sizeof(GC_Session_Keys)));
        ASSERT_NE(gconn_.session_keys, nullptr);
    }

    void TearDown() override
    {
        gcc_peer_cleanup(mem_, mem_, &gconn_);
        mono_time_free(mem_, mono_time_);
        logger_kill(log_);
    }

    int send(const std::uint8_t *data, std::uint16_t length)
    {
        return gcc_send_lossless_packet(chat_.get(), &gconn_, data, length, GP_BROADCAST);
    }

    const Memory *mem_ = os_memory();
    Logger *log_ = logger_new(mem_);
    Mono_Time *mono_time_ = mono_time_new(mem_, nullptr, nullptr);
    std::unique_ptr<GC_Chat> chat_ = std::make_unique<GC_Chat>();
    GC_Connection gconn_{};
};

// The send array keeps one slot free to tell a full array from an empty one,
// also when its oldest entry is in the first slot.
TEST_F(GroupConnection, SendArrayIsFullWhenOldestEntryIsInFirstSlot)
{
    gcc_set_send_message_id(&gconn_, 0);

    const std::uint8_t data[1] = {0};
    for (int i = 0; i < GCC_BUFFER_SIZE - 1; ++i) {
        ASSERT_EQ(send(data, sizeof(data)), 0);
    }
    EXPECT_EQ(send(data, sizeof(data)), -1);
}

// A message whose fragments don't all fit gives their ids back, also once the
// ids no longer fit in 16 bits.
TEST_F(GroupConnection, FragmentsThatDontFitGiveBackTheirIds)
{
    gcc_set_send_message_id(&gconn_, UINT16_MAX + 10);

    // Two slots stay free, for the first two fragments.
    const std::uint8_t data[1] = {0};
    for (int i = 0; i < GCC_BUFFER_SIZE - 3; ++i) {
        ASSERT_EQ(send(data, sizeof(data)), 0);
    }
    const std::uint64_t next_id = gconn_.send_message_id;

    const std::vector<std::uint8_t> message(3 * MAX_GC_PACKET_CHUNK_SIZE);
    EXPECT_FALSE(gcc_send_lossless_packet_fragments(
        chat_.get(), &gconn_, message.data(), message.size(), GP_BROADCAST));
    EXPECT_EQ(gconn_.send_message_id, next_id);
}

}  // namespace
