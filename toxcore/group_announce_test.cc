#include "group_announce.h"

#include <gtest/gtest.h>

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

TEST_F(Announces, KillGcaOnNullptrIsNoop)
{
    // All kill functions should be nullable.
    kill_gca(nullptr);
}

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
    std::vector<GC_Announce> announces_;
    Logger *logger_ = nullptr;

    void SetUp() override
    {
        logger_ = logger_new();
        ASSERT_NE(logger_, nullptr);

        // Add an announce without TCP relay.
        announces_.emplace_back();
        auto &ann1 = announces_.back();

        ann1.peer_public_key[0] = 0xae;
        ann1.ip_port.ip.family = net_family_ipv4;
        ann1.ip_port.ip.ip.v4.uint8[0] = 0x7f;  // 127.0.0.1
        ann1.ip_port.ip.ip.v4.uint8[3] = 0x1;
        ann1.ip_port_is_set = 1;

        // Add an announce with TCP relay.
        announces_.emplace_back();
        auto &ann2 = announces_.back();

        ann2.peer_public_key[0] = 0xaf;  // different key
        ann2.ip_port.ip.family = net_family_ipv4;
        ann2.ip_port.ip.ip.v4.uint8[0] = 0x7f;  // 127.0.0.2
        ann2.ip_port.ip.ip.v4.uint8[3] = 0x2;
        ann2.ip_port_is_set = 1;
        ann2.tcp_relays_count = 1;
        ann2.tcp_relays[0].ip_port.ip.family = net_family_ipv4;
        ann2.tcp_relays[0].ip_port.ip.ip.v4 = ip4_broadcast;
        ann2.tcp_relays[0].public_key[0] = 0xea;
    }

    ~AnnouncesPack() override { logger_kill(logger_); }
};

TEST_F(AnnouncesPack, UnpackIncompleteAnnouncesList)
{
    const uint8_t data[] = {0x00, 0x24, 0x3d, 0x00, 0x3d, 0xff, 0xff, 0x5b, 0x04, 0x20, 0x00, 0x01,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00};

    GC_Announce announce;
    gca_unpack_announces_list(logger_, data, sizeof(data), &announce, 1);
}

TEST_F(AnnouncesPack, PackedAnnouncesListCanBeUnpacked)
{
    const uint16_t size = gca_pack_announces_list_size(announces_.size());
    std::vector<uint8_t> packed(size);

    size_t processed = 0;

    EXPECT_GT(gca_pack_announces_list(logger_, packed.data(), packed.size(), announces_.data(),
              announces_.size(), &processed), 0);
    ASSERT_GE(processed, ENC_PUBLIC_KEY_SIZE + 2);
    ASSERT_LE(processed, size);

    std::vector<GC_Announce> announces_unpacked(announces_.size());
    ASSERT_EQ(gca_unpack_announces_list(logger_, packed.data(), packed.size(),
                  announces_unpacked.data(), announces_unpacked.size()),
        announces_unpacked.size());
}

TEST_F(AnnouncesPack, PackingEmptyAnnounceFails)
{
    GC_Announce announce{};  // all zeroes
    std::vector<uint8_t> packed(gca_pack_announces_list_size(1));
    EXPECT_EQ(
        gca_pack_announces_list(logger_, packed.data(), packed.size(), &announce, 1, nullptr), -1);
}

}  // namespace
