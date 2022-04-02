#include <gtest/gtest.h>

#include "group_announce.h"
#include "mono_time.h"

namespace {

struct Announces : ::testing::Test {
protected:
    uint64_t clock_ = 0;
    Mono_Time *mono_time_ = nullptr;
    GC_Announces_List *gca_ = nullptr;

    void SetUp() override
    {
        mono_time_ = mono_time_new();
        ASSERT_NE(mono_time_, nullptr);
        mono_time_set_current_time_callback(
            mono_time_,
            [](Mono_Time *mono_time, void *user_data) {
                return *static_cast<uint64_t *>(user_data);
            },
            &clock_);
        gca_ = new_gca_list();
        ASSERT_NE(gca_, nullptr);
    }

    ~Announces() override
    {
        kill_gca(gca_);
        mono_time_free(mono_time_);
    }
};

TEST_F(Announces, CanBeCreatedAndDeleted)
{
    // Just create one and kill it immediately.
}

TEST_F(Announces, AnnouncesCanTimeOut)
{
    clock_ = 100;
    ASSERT_EQ(gca_->root_announces, nullptr);
    GC_Public_Announce ann{};
    ann.chat_public_key[0] = 0xae;
    ASSERT_NE(gca_add_announce(mono_time_, gca_, &ann), nullptr);
    ASSERT_NE(gca_->root_announces, nullptr);
    ASSERT_EQ(gca_->root_announces->chat_id[0], 0xae);

    // One iteration without having any time passed => announce is still here.
    do_gca(mono_time_, gca_);
    ASSERT_NE(gca_->root_announces, nullptr);

    // 29 seconds later, still there
    clock_ += 29000;
    do_gca(mono_time_, gca_);
    ASSERT_NE(gca_->root_announces, nullptr);

    // Another second later, it's still there, but will disappear on the next
    // iteration.
    clock_ += 1000;
    do_gca(mono_time_, gca_);
    ASSERT_NE(gca_->root_announces, nullptr);

    // One more iteration and it's gone.
    do_gca(mono_time_, gca_);
    ASSERT_NE(gca_->root_announces, nullptr);
}

struct AnnouncesPack : ::testing::Test {
protected:
    Logger *logger_ = nullptr;

    void SetUp() override
    {
        logger_ = logger_new();
        ASSERT_NE(logger_, nullptr);
    }

    ~AnnouncesPack() override { logger_kill(logger_); }
};

TEST_F(AnnouncesPack, UnpackAnnouncesList)
{
    const uint8_t data[] = {0x00, 0x24, 0x3d, 0x00, 0x3d, 0xff, 0xff, 0x5b, 0x04, 0x20, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00};

    GC_Announce announce;
    gca_unpack_announces_list(logger_, data, sizeof(data), &announce, 1);
}

}  // namespace
