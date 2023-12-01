#include "pk_set.h"

#include <gtest/gtest.h>

#include "crypto_core.h"

namespace {

struct PkSet : ::testing::Test {
protected:
    PkSet() : set_(pk_set_new(mem_, 1)) {}
    ~PkSet() override { pk_set_free(set_); }

    void SetUp() override {
        ASSERT_NE(set_, nullptr);
    }

    const Memory *mem_ = system_memory();
    Pk_Set *set_;
};

TEST_F(PkSet, DoesntAddTheSameKeyTwice)
{
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

}  // namespace
