// clang-format off
#include "group_connection.h"
// clang-format on

#include <gtest/gtest.h>

#include <cstdint>
#include <memory>
#include <vector>

#include "group_chats.h"
#include "group_common.h"
#include "logger.h"
#include "mem.h"
#include "mono_time.h"
#include "os_memory.h"
#include "os_random.h"

namespace {

class GroupConnection : public ::testing::Test {
protected:
    void SetUp() override
    {
        ASSERT_NE(log_, nullptr);
        ASSERT_NE(mono_time_, nullptr);

        chat_->log = log_;
        chat_->mem = mem_;
        chat_->rng = os_random();
        chat_->mono_time = mono_time_;

        gconn_.send_array = static_cast<GC_Message_Array_Entry *>(
            mem_valloc(mem_, GCC_BUFFER_SIZE, sizeof(GC_Message_Array_Entry)));
        gconn_.recv_array = static_cast<GC_Message_Array_Entry *>(
            mem_valloc(mem_, GCC_BUFFER_SIZE, sizeof(GC_Message_Array_Entry)));
        ASSERT_NE(gconn_.send_array, nullptr);
        ASSERT_NE(gconn_.recv_array, nullptr);
    }

    void TearDown() override
    {
        gcc_peer_cleanup(mem_, &gconn_);
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
