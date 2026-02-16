#include "model_utils.hh"

#include <gtest/gtest.h>

namespace tox::netprof {

TEST(ModelUtilsTest, SafeSTOD)
{
    double val;
    EXPECT_TRUE(safe_stod("123.456", val));
    EXPECT_DOUBLE_EQ(val, 123.456);

    EXPECT_TRUE(safe_stod("-0.5", val));
    EXPECT_DOUBLE_EQ(val, -0.5);

    EXPECT_FALSE(safe_stod("abc", val));
    EXPECT_FALSE(safe_stod("123a", val));
    EXPECT_FALSE(safe_stod("", val));
}

TEST(ModelUtilsTest, SafeSTOF)
{
    float val;
    EXPECT_TRUE(safe_stof("12.5", val));
    EXPECT_FLOAT_EQ(val, 12.5f);

    EXPECT_FALSE(safe_stof("xyz", val));
}

TEST(ModelUtilsTest, SafeSTOUL)
{
    uint32_t val;
    EXPECT_TRUE(safe_stoul("42", val));
    EXPECT_EQ(val, 42u);

    EXPECT_TRUE(safe_stoul("0", val));
    EXPECT_EQ(val, 0u);

    // Verify that negative numbers are rejected.
    EXPECT_FALSE(safe_stoul("-1", val));

    EXPECT_FALSE(safe_stoul("abc", val));
}

}  // namespace tox::netprof
