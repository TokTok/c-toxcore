#include "group_moderation.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <vector>

#include "crypto_core.h"
#include "logger.h"
#include "util.h"

namespace {

using ExtPublicKey = std::array<uint8_t, EXT_PUBLIC_KEY_SIZE>;
using ExtSecretKey = std::array<uint8_t, EXT_SECRET_KEY_SIZE>;
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

TEST(ModList, ModListRemoveIndex)
{
    Moderation mods{};
    uint8_t sig_pk[32] = {1};
    EXPECT_TRUE(mod_list_add_entry(&mods, sig_pk));
    EXPECT_TRUE(mod_list_remove_index(&mods, 0));
}

TEST(ModList, CleanupOnEmptyModsIsNoop)
{
    Moderation mods{};
    mod_list_cleanup(&mods);
}

TEST(ModList, EmptyModListCannotVerifyAnySigPk)
{
    Moderation mods{};
    uint8_t sig_pk[32] = {1};
    EXPECT_FALSE(mod_list_verify_sig_pk(&mods, sig_pk));
}

TEST(ModList, ModListAddVerifyRemoveSigPK)
{
    Moderation mods{};
    uint8_t sig_pk[32] = {1};
    EXPECT_TRUE(mod_list_add_entry(&mods, sig_pk));
    EXPECT_TRUE(mod_list_verify_sig_pk(&mods, sig_pk));
    EXPECT_TRUE(mod_list_remove_entry(&mods, sig_pk));
    EXPECT_FALSE(mod_list_verify_sig_pk(&mods, sig_pk));
}

TEST(SanctionsList, PackingIntoUndersizedBufferFails)
{
    Mod_Sanction sanctions[1];
    std::array<uint8_t, 1> packed;
    EXPECT_EQ(sanctions_list_pack(packed.data(), packed.size(), sanctions, 1, nullptr), -1);

    uint16_t length = sanctions_list_packed_size(1) - 1;
    std::vector<uint8_t> packed2(length);
    EXPECT_EQ(sanctions_list_pack(packed2.data(), packed2.size(), sanctions, 1, nullptr), -1);
}

TEST(SanctionsList, CreatePackUnpackSanction)
{
    ExtPublicKey pk;
    ExtSecretKey sk;
    EXPECT_TRUE(create_extended_keypair(pk.data(), sk.data()));

    Moderation mod{};
    Logger *log = logger_new();
    mod.log = log;

    memcpy(mod.self_public_sig_key, get_sig_pk(pk.data()), SIG_PUBLIC_KEY_SIZE);
    memcpy(mod.self_secret_sig_key, get_sig_sk(sk.data()), SIG_SECRET_KEY_SIZE);

    EXPECT_TRUE(mod_list_add_entry(&mod, get_sig_pk(pk.data())));

    Mod_Sanction sanction;
    EXPECT_FALSE(sanctions_list_check_integrity(&mod, &mod.sanctions_creds, &sanction, 1));

    uint8_t sanctioned_pk[32] = {1};
    EXPECT_TRUE(sanctions_list_make_entry(&mod, sanctioned_pk, &sanction, SA_OBSERVER));
    EXPECT_TRUE(sanctions_list_check_integrity(&mod, &mod.sanctions_creds, &sanction, 1));

    uint16_t packed_length = sanctions_list_packed_size(1);
    std::vector<uint8_t> packed(packed_length);
    EXPECT_EQ(
        sanctions_list_pack(packed.data(), packed.size(), &sanction, 1, nullptr), packed_length);

    Mod_Sanction unpacked_sanction;
    uint16_t processed_data_len = 0;

    EXPECT_EQ(sanctions_list_unpack(&unpacked_sanction, &mod.sanctions_creds, 1, packed.data(),
                  packed.size(), &processed_data_len),
        1);
    EXPECT_EQ(processed_data_len, packed_length + MOD_SANCTIONS_CREDS_SIZE);
    EXPECT_TRUE(sanctions_list_entry_exists(&mod, &sanction));
    EXPECT_TRUE(sanctions_list_entry_exists(&mod, &unpacked_sanction));
    EXPECT_TRUE(sanctions_list_remove_observer(&mod, sanctioned_pk, nullptr));
    EXPECT_FALSE(sanctions_list_entry_exists(&mod, &sanction));
    EXPECT_FALSE(sanctions_list_entry_exists(&mod, &unpacked_sanction));

    logger_kill(log);
}

}  // namespace
