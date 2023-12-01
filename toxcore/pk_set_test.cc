#include "pk_set.h"

#include <gtest/gtest.h>

#include "crypto_core.h"

namespace {

struct PkSet : ::testing::Test {
protected:
    PkSet()
        : set_(pk_set_new(mem_, 1))
    {
    }
    ~PkSet() override { pk_set_free(set_); }

    void SetUp() override { ASSERT_NE(set_, nullptr); }

    const Memory *mem_ = system_memory();
    Pk_Set *set_;
};

TEST_F(PkSet, DoesntAddTheSameKeyTwice)
{
    const uint8_t pk[CRYPTO_PUBLIC_KEY_SIZE]{};
    ASSERT_TRUE(pk_set_add(set_, pk));
    ASSERT_FALSE(pk_set_add(set_, pk));
}

TEST_F(PkSet, ZeroCapacityCanGrow)
{
    pk_set_free(set_);
    set_ = pk_set_new(mem_, 0);

    const uint8_t pk[CRYPTO_PUBLIC_KEY_SIZE]{};
    ASSERT_TRUE(pk_set_add(set_, pk));
    ASSERT_FALSE(pk_set_add(set_, pk));
}

TEST_F(PkSet, GrowsWhenNeeded)
{
    const uint8_t pk1[CRYPTO_PUBLIC_KEY_SIZE]{0};
    ASSERT_TRUE(pk_set_add(set_, pk1));
    const uint8_t pk2[CRYPTO_PUBLIC_KEY_SIZE]{1};
    ASSERT_TRUE(pk_set_add(set_, pk2));
}

TEST_F(PkSet, ContainsKeyAfterAdd)
{
    const uint8_t pk[CRYPTO_PUBLIC_KEY_SIZE]{0};
    ASSERT_FALSE(pk_set_contains(set_, pk));
    ASSERT_TRUE(pk_set_add(set_, pk));
    ASSERT_TRUE(pk_set_contains(set_, pk));
}

TEST_F(PkSet, CanAdd256Keys)
{
    std::vector<std::array<uint8_t, CRYPTO_PUBLIC_KEY_SIZE>> pks(UINT8_MAX);
    for (uint8_t i = 0; i < UINT8_MAX; ++i) {
        auto &pk = pks[i];
        pk[0] = i & 0xff;
        pk[1] = i >> 8;
        ASSERT_FALSE(pk_set_contains(set_, pk.data()))
            << i << " -> {" << uint32_t(pk[0]) << "," << uint32_t(pk[1]) << "}";
        ASSERT_TRUE(pk_set_add(set_, pk.data()));
        ASSERT_TRUE(pk_set_contains(set_, pk.data()));
    }

    // Can't add the 257th key.
    const uint8_t pk[CRYPTO_PUBLIC_KEY_SIZE]{0xff, 0xff, 0xff};
    ASSERT_FALSE(pk_set_contains(set_, pk));
    ASSERT_FALSE(pk_set_add(set_, pk));
    ASSERT_FALSE(pk_set_contains(set_, pk));
}

}  // namespace
