#include "group_moderation.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <vector>

#include "crypto_core.h"

namespace {

using ModerationHash = std::array<uint8_t, MOD_MODERATION_HASH_SIZE>;

TEST(ModList, PackedSizeOfEmptyModListIsZero)
{
    Moderation mods{};
    EXPECT_EQ(mod_list_packed_size(&mods), 0);

    uint8_t byte = 1;
    mod_list_pack(&mods, &byte);
    EXPECT_EQ(byte, 1);
}

TEST(ModList, UnpackingZeroSizeArrayIsNoop)
{
    Moderation mods{};
    const uint8_t byte = 1;
    EXPECT_EQ(mod_list_unpack(&mods, &byte, 0, 0), 0);
}

TEST(ModList, PackingAndUnpackingList)
{
    using ModListEntry = std::array<uint8_t, MOD_LIST_ENTRY_SIZE>;
    Moderation mods{};
    EXPECT_TRUE(mod_list_add_entry(&mods, ModListEntry{}.data()));

    std::vector<uint8_t> packed(mod_list_packed_size(&mods));
    mod_list_pack(&mods, packed.data());

    Moderation mods2{};
    EXPECT_EQ(mod_list_unpack(&mods2, packed.data(), packed.size(), 1), packed.size());
}

TEST(ModList, UnpackingTooManyModsFails)
{
    using ModListEntry = std::array<uint8_t, MOD_LIST_ENTRY_SIZE>;
    Moderation mods{};
    EXPECT_TRUE(mod_list_add_entry(&mods, ModListEntry{}.data()));

    std::vector<uint8_t> packed(mod_list_packed_size(&mods));
    mod_list_pack(&mods, packed.data());

    Moderation mods2{};
    EXPECT_EQ(mod_list_unpack(&mods2, packed.data(), packed.size(), 2), -1);
}

TEST(ModList, UnpackingFromEmptyBufferFails)
{
    std::vector<uint8_t> packed(1);

    Moderation mods{};
    EXPECT_EQ(mod_list_unpack(&mods, packed.end().base(), 0, 1), -1);
}

TEST(ModList, HashOfEmptyModListZeroesOutBuffer)
{
    Moderation mods{};

    // Fill with random data, check that it's zeroed.
    ModerationHash hash;
    random_bytes(hash.data(), hash.size());
    EXPECT_TRUE(mod_list_make_hash(&mods, hash.data()));
    EXPECT_EQ(hash, ModerationHash{});
}

TEST(ModList, RemoveIndexFromEmptyModListFails)
{
    Moderation mods{};
    EXPECT_FALSE(mod_list_remove_index(&mods, 0));
    EXPECT_FALSE(mod_list_remove_index(&mods, UINT16_MAX));
}

TEST(ModList, RemoveEntryFromEmptyModListFails)
{
    Moderation mods{};
    uint8_t sig_pk[32] = {0};
    EXPECT_FALSE(mod_list_remove_entry(&mods, sig_pk));
}

TEST(ModList, CleanupOnEmptyModsIsNoop)
{
    Moderation mods{};
    mod_list_cleanup(&mods);
}

TEST(ModList, EmptyModListCannotVerifyAnySigPk)
{
    Moderation mods{};
    uint8_t sig_pk[32] = {0};
    EXPECT_FALSE(mod_list_verify_sig_pk(&mods, sig_pk));
}

TEST(SanctionsList, PackingEmptyListsIsNoop)
{
    std::array<uint8_t, 1> packed{0x7f};
    EXPECT_EQ(sanctions_list_pack(packed.data(), packed.size(), nullptr, nullptr, 0), 0);
    EXPECT_EQ(packed[0], 0x7f);
}

TEST(SanctionsList, PackingIntoUndersizedBufferFails)
{
    Mod_Sanction sanctions[1];
    std::array<uint8_t, 1> packed;
    EXPECT_EQ(sanctions_list_pack(packed.data(), packed.size(), sanctions, nullptr, 1), -1);
}

}  // namespace
