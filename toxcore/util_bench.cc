#include <benchmark/benchmark.h>

#include <cstdint>
#include <random>

#include "util.h"
#include "util_test_util.hh"

namespace {

static void BM_merge_sort(benchmark::State &state)
{
    std::mt19937 rng;
    // INT_MAX-1 so later we have room to add 1 larger element if needed.
    std::uniform_int_distribution<uint32_t> dist{
        std::numeric_limits<uint32_t>::min(), std::numeric_limits<uint32_t>::max() - 1};

    std::vector<uint32_t> vec(state.range(0) + 1);
    std::generate(std::begin(vec), std::end(vec), [&]() { return dist(rng); });

    constexpr auto int_funcs = sort_funcs<uint32_t>();

    for (auto _ : state) {
        std::vector<uint32_t> unsorted = vec;
        merge_sort(unsorted.data(), unsorted.size(), &state, &int_funcs);
    }
}

BENCHMARK(BM_merge_sort)->RangeMultiplier(2)->Range(8, 8 << 8);

static void BM_qsort(benchmark::State &state)
{
    std::mt19937 rng;
    // INT_MAX-1 so later we have room to add 1 larger element if needed.
    std::uniform_int_distribution<uint32_t> dist{
        std::numeric_limits<uint32_t>::min(), std::numeric_limits<uint32_t>::max() - 1};

    std::vector<uint32_t> vec(state.range(0) + 1);
    std::generate(std::begin(vec), std::end(vec), [&]() { return dist(rng); });

    for (auto _ : state) {
        std::vector<uint32_t> unsorted = vec;
        qsort(unsorted.data(), unsorted.size(), sizeof(unsorted[0]),
            [](const void *va, const void *vb) {
                const uint32_t *a = static_cast<const uint32_t *>(va);
                const uint32_t *b = static_cast<const uint32_t *>(vb);
                return cmp_uint(*a, *b);
            });
    }
}

BENCHMARK(BM_qsort)->RangeMultiplier(2)->Range(8, 8 << 8);

static void BM_std_sort(benchmark::State &state)
{
    std::mt19937 rng;
    // INT_MAX-1 so later we have room to add 1 larger element if needed.
    std::uniform_int_distribution<uint32_t> dist{
        std::numeric_limits<uint32_t>::min(), std::numeric_limits<uint32_t>::max() - 1};

    std::vector<uint32_t> vec(state.range(0) + 1);
    std::generate(std::begin(vec), std::end(vec), [&]() { return dist(rng); });

    for (auto _ : state) {
        std::vector<uint32_t> unsorted = vec;
        std::sort(unsorted.begin(), unsorted.end(), std::less<uint32_t>());
    }
}

BENCHMARK(BM_std_sort)->RangeMultiplier(2)->Range(8, 8 << 8);

}

BENCHMARK_MAIN();
