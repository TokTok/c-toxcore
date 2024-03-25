#include "mono_time.h"

#include <gtest/gtest.h>

#include <chrono>
#include <thread>

#include "mem_test_util.hh"
#include "tox_time_impl.h"

namespace {

TEST(MonoTime, UnixTimeIncreasesOverTime)
{
    Test_Memory mem;
    Mono_Time *mono_time = mono_time_new(mem, nullptr);
    ASSERT_NE(mono_time, nullptr);

    mono_time_update(mono_time);
    uint64_t const start = mono_time_get(mono_time);

    while (start == mono_time_get(mono_time)) {
        mono_time_update(mono_time);
    }

    uint64_t const end = mono_time_get(mono_time);
    EXPECT_GT(end, start);

    mono_time_free(mem, mono_time);
}

TEST(MonoTime, IsTimeout)
{
    Test_Memory mem;
    Mono_Time *mono_time = mono_time_new(mem, nullptr);
    ASSERT_NE(mono_time, nullptr);

    uint64_t const start = mono_time_get(mono_time);
    EXPECT_FALSE(mono_time_is_timeout(mono_time, start, 1));

    while (start == mono_time_get(mono_time)) {
        mono_time_update(mono_time);
    }

    EXPECT_TRUE(mono_time_is_timeout(mono_time, start, 1));

    mono_time_free(mem, mono_time);
}

TEST(MonoTime, IsTimeoutReal)
{
    Test_Memory mem;
    Mono_Time *mono_time = mono_time_new(mem, nullptr);
    ASSERT_NE(mono_time, nullptr);

    uint64_t const start = mono_time_get(mono_time);
    EXPECT_FALSE(mono_time_is_timeout(mono_time, start, 5));

    const uint64_t before_sleep = mono_time_get(mono_time);
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    mono_time_update(mono_time);
    const uint64_t after_sleep = mono_time_get(mono_time);

    // should still not have timed out (5sec) after sleeping ~100ms
    EXPECT_FALSE(mono_time_is_timeout(mono_time, start, 5))
        << "before sleep: " << before_sleep << ", after sleep: " << after_sleep;

    mono_time_free(mem, mono_time);
}

TEST(MonoTime, CustomTime)
{
    Test_Memory mem;
    Mono_Time *mono_time = mono_time_new(mem, nullptr);
    ASSERT_NE(mono_time, nullptr);

    uint64_t test_time = current_time_monotonic(mono_time) + 42137;

    constexpr Tox_Time_Funcs mock_time_funcs = {
        [](void *user_data) { return *static_cast<uint64_t *>(user_data); },
    };
    Tox_Time *tm = tox_time_new(&mock_time_funcs, &test_time, mem);
    ASSERT_NE(tm, nullptr);
    mono_time_set_current_time_callback(mono_time, tm);
    mono_time_update(mono_time);

    EXPECT_EQ(current_time_monotonic(mono_time), test_time);

    uint64_t const start = mono_time_get(mono_time);

    test_time += 7000;

    mono_time_update(mono_time);
    EXPECT_EQ(mono_time_get(mono_time) - start, 7);

    EXPECT_EQ(current_time_monotonic(mono_time), test_time);

    mono_time_free(mem, mono_time);
    tox_time_free(tm);
}

}  // namespace
