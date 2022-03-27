/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2021 The TokTok team.
 */

#ifndef C_TOXCORE_TESTING_FUZZING_FUZZ_SUPPORT_H
#define C_TOXCORE_TESTING_FUZZING_FUZZ_SUPPORT_H

#include <cstdint>
#include <cstdlib>

struct Fuzz_Data {
    const uint8_t *data;
    std::size_t size;

    uint8_t consume1() {
        const uint8_t val = data[0];
        ++data;
        --size;
        return val;
    }

    const uint8_t *consume(std::size_t count) {
        const uint8_t *val = data;
        data += count;
        size -= count;
        return val;
    }
};

#define CONSUME1(DECL, INPUT) \
    if (INPUT.size < 1) {     \
        return;               \
    }                         \
    DECL = INPUT.consume1()

#define CONSUME(DECL, INPUT, SIZE) \
    if (INPUT.size < SIZE) {       \
        return;                    \
    }                              \
    DECL = INPUT.consume(SIZE)

inline void fuzz_select_target(uint8_t selector, Fuzz_Data input)
{
    // The selector selected no function, so we do nothing and rely on the
    // fuzzer to come up with a better selector.
}

template<typename Arg, typename ...Args>
void fuzz_select_target(uint8_t selector, Fuzz_Data input, Arg fn, Args ...args)
{
    if (selector == sizeof...(Args)) {
        return fn(input);
    }
    return fuzz_select_target(selector - 1, input, args...);
}

template<typename ...Args>
void fuzz_select_target(const uint8_t *data, std::size_t size, Args ...args)
{
    Fuzz_Data input{data, size};

    CONSUME1(uint8_t selector, input);
    return fuzz_select_target(selector, input, args...);
}

#endif // C_TOXCORE_TESTING_FUZZING_FUZZ_SUPPORT_H
