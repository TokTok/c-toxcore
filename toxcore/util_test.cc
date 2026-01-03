/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2025 The TokTok team.
 */
#include "util.h"

#include <gtest/gtest.h>

#include <climits>

namespace {

TEST(Cmp, OrdersNumbersCorrectly)
{
    EXPECT_EQ(cmp_uint(1, 2), -1);
    EXPECT_EQ(cmp_uint(0, UINT32_MAX), -1);
    EXPECT_EQ(cmp_uint(UINT32_MAX, 0), 1);
    EXPECT_EQ(cmp_uint(UINT32_MAX, UINT32_MAX), 0);
    EXPECT_EQ(cmp_uint(0, UINT64_MAX), -1);
    EXPECT_EQ(cmp_uint(UINT64_MAX, 0), 1);
    EXPECT_EQ(cmp_uint(UINT64_MAX, UINT64_MAX), 0);
}

TEST(BytesToString, FormatsCorrectly)
{
    uint8_t bytes[] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE};
    char str[32];

    // Case 1: Full string fits
    // Length needed: 5*2 + 1 = 11. Buffer: 12.
    bytes_to_string(bytes, 5, str, 12);
    EXPECT_STREQ(str, "AABBCCDDEE");

    // Case 2: Exact fit
    // Length needed: 11. Buffer: 11.
    bytes_to_string(bytes, 5, str, 11);
    EXPECT_STREQ(str, "AABBCCDDEE");

    // Case 3: Truncation needed (1 byte less than full)
    // Buffer: 10. Available hex: 10 - 6 = 4. Start bytes: 2. End bytes: 1.
    // Result: AABB...EE
    bytes_to_string(bytes, 5, str, 10);
    EXPECT_STREQ(str, "AABB...EE");

    // Case 4: Truncation needed (more severe)
    // Buffer: 8. Available hex: 8 - 6 = 2. Start bytes: 1. End bytes: 1.
    // Result: AA...EE
    bytes_to_string(bytes, 5, str, 8);
    EXPECT_STREQ(str, "AA...EE");

    // Case 5: Just enough for "...", 1 start byte, 1 end byte
    // Buffer: 8. Same as above.

    // Case 6: Small buffer (< 6)
    // Buffer: 5.
    // Result: ...
    bytes_to_string(bytes, 5, str, 5);
    EXPECT_STREQ(str, "...");

    // Case 7: Zero length
    str[0] = 'X';
    bytes_to_string(bytes, 5, str, 0);
    EXPECT_EQ(str[0], 'X'); // Should not touch buffer
}

TEST(BytesToString, HandlesShortInputs)
{
    uint8_t bytes[] = {0x11, 0x22};
    char str[32];

    // Fits easily
    bytes_to_string(bytes, 2, str, 10);
    EXPECT_STREQ(str, "1122");

    // Exact fit
    bytes_to_string(bytes, 2, str, 5);
    EXPECT_STREQ(str, "1122");

    // Force truncation even on short input if buffer is tiny
    // Buffer: 4. Full need: 5.
    // Truncation path: Buffer 4 < 6. Result: ...
    bytes_to_string(bytes, 2, str, 4);
    EXPECT_STREQ(str, "...");
}

}  // namespace
