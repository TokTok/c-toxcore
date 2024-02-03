#include "util.h"

#include <gtest/gtest.h>

#include <limits>
#include <random>

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

template <typename T>
Sort_Funcs sort_funcs()
{
    return {
        [](const void *object, const void *va, const void *vb) {
            const T *a = static_cast<const T *>(va);
            const T *b = static_cast<const T *>(vb);

            // Just check that *something* is passed. Don't care what.
            EXPECT_NE(object, nullptr);

            return *a < *b;
        },
        [](const void *arr, uint32_t index) -> const void * {
            const T *vec = static_cast<const T *>(arr);
            return &vec[index];
        },
        [](void *arr, uint32_t index, const void *val) {
            T *vec = static_cast<T *>(arr);
            const T *value = static_cast<const T *>(val);
            vec[index] = *value;
        },
        [](void *arr, uint32_t index, uint32_t size) -> void * {
            T *vec = static_cast<T *>(arr);
            return &vec[index];
        },
        [](const void *object, uint32_t size) -> void * { return new T[size]; },
        [](const void *object, void *arr, uint32_t size) {
            T *vec = static_cast<T *>(arr);
            delete[] vec;
        },
    };
}

TEST(MergeSort, BehavesLikeStdSort)
{
    std::mt19937 rng;
    // INT_MAX-1 so later we have room to add 1 larger element if needed.
    std::uniform_int_distribution<int> dist{
        std::numeric_limits<int>::min(), std::numeric_limits<int>::max() - 1};

    const auto int_funcs = sort_funcs<int>();

    // Test with int arrays.
    for (uint32_t i = 1; i < 1000; ++i) {
        std::vector<int> vec(i);
        std::generate(std::begin(vec), std::end(vec), [&]() { return dist(rng); });

        auto sorted = vec;
        std::sort(sorted.begin(), sorted.end(), std::less<int>());

        // If vec was accidentally sorted, add another larger element that almost definitely makes
        // it not sorted.
        if (vec == sorted) {
            int const largest = *std::prev(sorted.end()) + 1;
            sorted.push_back(largest);
            vec.insert(vec.begin(), largest);
        }
        ASSERT_NE(vec, sorted);

        // Just pass some arbitrary "self" to make sure the callbacks pass it through.
        ASSERT_TRUE(merge_sort(vec.data(), vec.size(), &i, &int_funcs));
        ASSERT_EQ(vec, sorted);
    }
}

TEST(MergeSort, WorksWithNonTrivialTypes)
{
    std::mt19937 rng;
    std::uniform_int_distribution<int> dist{
        std::numeric_limits<int>::min(), std::numeric_limits<int>::max()};

    const auto string_funcs = sort_funcs<std::string>();

    // Test with std::string arrays.
    for (uint32_t i = 1; i < 500; ++i) {
        std::vector<std::string> vec(i);
        std::generate(std::begin(vec), std::end(vec), [&]() { return std::to_string(dist(rng)); });

        auto sorted = vec;
        std::sort(sorted.begin(), sorted.end(), std::less<std::string>());

        // If vec was accidentally sorted, add another larger element that almost definitely makes
        // it not sorted.
        if (vec == sorted) {
            std::string const largest = "larger than largest int";
            sorted.push_back(largest);
            vec.insert(vec.begin(), largest);
        }
        ASSERT_NE(vec, sorted);

        // Just pass some arbitrary "self" to make sure the callbacks pass it through.
        ASSERT_TRUE(merge_sort(vec.data(), vec.size(), &i, &string_funcs));
        ASSERT_EQ(vec, sorted);
    }
}

}  // namespace
