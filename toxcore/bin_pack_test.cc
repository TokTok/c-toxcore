#include "bin_pack.h"

#include <gtest/gtest.h>

#include <array>
#include <memory>
#include <vector>

#include "bin_unpack.h"

namespace {

struct Bin_Unpack_Deleter {
    void operator()(Bin_Unpack *bu) const { bin_unpack_free(bu); }
};

using Bin_Unpack_Ptr = std::unique_ptr<Bin_Unpack, Bin_Unpack_Deleter>;

TEST(BinPack, TooSmallBufferIsNotExceeded)
{
    const uint64_t orig = 1234567812345678LL;
    std::array<uint8_t, sizeof(orig) - 1> buf;
    EXPECT_FALSE(bin_pack_obj([](Bin_Pack *bp, const Logger *logger, const void *obj) {
        return bin_pack_u64_b(bp, *static_cast<const uint64_t *>(obj));
    }, nullptr, &orig, buf.data(), buf.size()));
}

TEST(BinPack, PackedUint64CanBeUnpacked)
{
    const uint64_t orig = 1234567812345678LL;
    std::array<uint8_t, 8> buf;
    EXPECT_TRUE(bin_pack_obj([](Bin_Pack *bp, const Logger *logger, const void *obj) {
        return bin_pack_u64_b(bp, *static_cast<const uint64_t *>(obj));
    }, nullptr, &orig, buf.data(), buf.size()));

    Bin_Unpack_Ptr bu(bin_unpack_new(buf.data(), buf.size()));
    ASSERT_NE(bu, nullptr);
    uint64_t unpacked;
    ASSERT_TRUE(bin_unpack_u64_b(bu.get(), &unpacked));
    EXPECT_EQ(unpacked, 1234567812345678LL);
}

TEST(BinPack, MsgPackedUint8CanBeUnpackedAsUint32)
{
    const uint8_t orig = 123;
    std::array<uint8_t, 2> buf;
    EXPECT_TRUE(bin_pack_obj([](Bin_Pack *bp, const Logger *logger, const void *obj) {
        return bin_pack_u08(bp, *static_cast<const uint8_t *>(obj));
    }, nullptr, &orig, buf.data(), buf.size()));

    Bin_Unpack_Ptr bu(bin_unpack_new(buf.data(), buf.size()));
    ASSERT_NE(bu, nullptr);
    uint32_t val;
    ASSERT_TRUE(bin_unpack_u32(bu.get(), &val));
    EXPECT_EQ(val, 123);
}

TEST(BinPack, MsgPackedUint32CanBeUnpackedAsUint8IfSmallEnough)
{
    const uint32_t orig = 123;
    std::array<uint8_t, 2> buf;
    EXPECT_TRUE(bin_pack_obj([](Bin_Pack *bp, const Logger *logger, const void *obj) {
        return bin_pack_u32(bp, *static_cast<const uint32_t *>(obj));
    }, nullptr, &orig, buf.data(), buf.size()));

    Bin_Unpack_Ptr bu(bin_unpack_new(buf.data(), buf.size()));
    ASSERT_NE(bu, nullptr);
    uint8_t val;
    ASSERT_TRUE(bin_unpack_u08(bu.get(), &val));
    EXPECT_EQ(val, 123);
}

TEST(BinPack, LargeMsgPackedUint32CannotBeUnpackedAsUint8)
{
    const uint32_t orig = 1234567;
    std::array<uint8_t, 5> buf;
    EXPECT_TRUE(bin_pack_obj([](Bin_Pack *bp, const Logger *logger, const void *obj) {
        return bin_pack_u32(bp, *static_cast<const uint32_t *>(obj));
    }, nullptr, &orig, buf.data(), buf.size()));

    Bin_Unpack_Ptr bu(bin_unpack_new(buf.data(), buf.size()));
    ASSERT_NE(bu, nullptr);
    uint8_t val;
    EXPECT_FALSE(bin_unpack_u08(bu.get(), &val));
}

TEST(BinPack, BinCanHoldPackedInts)
{
    struct Stuff {
        uint64_t u64;
        uint16_t u16;
    };
    const Stuff orig = {1234567812345678LL, 54321};
    static const uint32_t packed_size = sizeof(uint64_t) + sizeof(uint16_t);

    std::array<uint8_t, 12> buf;
    EXPECT_TRUE(bin_pack_obj(
        [](Bin_Pack *bp, const Logger *logger, const void *obj) {
            const Stuff *self = static_cast<const Stuff *>(obj);
            return bin_pack_bin_marker(bp, packed_size)  //
                && bin_pack_u64_b(bp, self->u64)  //
                && bin_pack_u16_b(bp, self->u16);
        },
        nullptr, &orig, buf.data(), buf.size()));

    Bin_Unpack_Ptr bu(bin_unpack_new(buf.data(), buf.size()));
    ASSERT_NE(bu, nullptr);
    uint32_t size;
    EXPECT_TRUE(bin_unpack_bin_size(bu.get(), &size));
    EXPECT_EQ(size, 10);
    uint64_t val1;
    EXPECT_TRUE(bin_unpack_u64_b(bu.get(), &val1));
    EXPECT_EQ(val1, 1234567812345678LL);
    uint16_t val2;
    EXPECT_TRUE(bin_unpack_u16_b(bu.get(), &val2));
    EXPECT_EQ(val2, 54321);
}

TEST(BinPack, BinCanHoldArbitraryData)
{
    std::array<uint8_t, 7> buf;
    EXPECT_TRUE(bin_pack_obj(
        [](Bin_Pack *bp, const Logger *logger, const void *obj) {
            return bin_pack_bin_marker(bp, 5)  //
                && bin_pack_bin_b(bp, reinterpret_cast<const uint8_t *>("hello"), 5);
        },
        nullptr, nullptr, buf.data(), buf.size()));

    Bin_Unpack_Ptr bu(bin_unpack_new(buf.data(), buf.size()));
    ASSERT_NE(bu, nullptr);
    std::array<uint8_t, 5> str;
    EXPECT_TRUE(bin_unpack_bin_fixed(bu.get(), str.data(), str.size()));
    EXPECT_EQ(str, (std::array<uint8_t, 5>{'h', 'e', 'l', 'l', 'o'}));
}

TEST(BinPack, OversizedArrayFailsUnpack)
{
    std::array<uint8_t, 1> buf = {0x91};

    Bin_Unpack_Ptr bu(bin_unpack_new(buf.data(), buf.size()));
    uint32_t size;
    EXPECT_FALSE(bin_unpack_array(bu.get(), &size));
}

}  // namespace
