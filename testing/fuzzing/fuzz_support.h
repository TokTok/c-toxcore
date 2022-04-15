/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2021-2022 The TokTok team.
 */

#ifndef C_TOXCORE_TESTING_FUZZING_FUZZ_SUPPORT_H
#define C_TOXCORE_TESTING_FUZZING_FUZZ_SUPPORT_H

#include <cstdint>
#include <cstdlib>
#include <deque>
#include <memory>
#include <vector>
#include <unordered_map>
#include <utility>

#include "../../toxcore/tox.h"

struct Fuzz_Data {
    const uint8_t *data;
    std::size_t size;

    Fuzz_Data(const uint8_t *input_data, std::size_t input_size)
        : data(input_data), size(input_size)
    {}

    Fuzz_Data &operator=(const Fuzz_Data &rhs) = delete;
    Fuzz_Data(const Fuzz_Data &rhs) = delete;

    uint8_t consume1()
    {
        const uint8_t val = data[0];
        ++data;
        --size;
        return val;
    }

    const uint8_t *consume(std::size_t count)
    {
        const uint8_t *val = data;
        data += count;
        size -= count;
        return val;
    }
};

/** @brief Consumes 1 byte of the fuzzer input or returns if no data available.
 *
 * This advances the fuzzer input data by 1 byte and consumes that byte in the
 * declaration.
 *
 * @example
 * @code
 * CONSUME1_OR_RETURN(const uint8_t one_byte, input);
 * @endcode
 */
#define CONSUME1_OR_RETURN(DECL, INPUT) \
    if (INPUT.size < 1) {               \
        return;                         \
    }                                   \
    DECL = INPUT.consume1()

/** @brief Consumes SIZE bytes of the fuzzer input or returns if not enough data available.
 *
 * This advances the fuzzer input data by SIZE byte and consumes those bytes in
 * the declaration. If less than SIZE bytes are available in the fuzzer input,
 * this macro returns from the enclosing function.
 *
 * @example
 * @code
 * CONSUME_OR_RETURN(const uint8_t *ten_bytes, input, 10);
 * @endcode
 */
#define CONSUME_OR_RETURN(DECL, INPUT, SIZE) \
    if (INPUT.size < SIZE) {                 \
        return;                              \
    }                                        \
    DECL = INPUT.consume(SIZE)

inline void fuzz_select_target(uint8_t selector, Fuzz_Data &input)
{
    // The selector selected no function, so we do nothing and rely on the
    // fuzzer to come up with a better selector.
}

template <typename Arg, typename... Args>
void fuzz_select_target(uint8_t selector, Fuzz_Data &input, Arg &&fn, Args &&... args)
{
    if (selector == sizeof...(Args)) {
        return fn(input);
    }
    return fuzz_select_target(selector - 1, input, std::forward<Args>(args)...);
}

template <typename... Args>
void fuzz_select_target(const uint8_t *data, std::size_t size, Args &&... args)
{
    Fuzz_Data input{data, size};

    CONSUME1_OR_RETURN(uint8_t selector, input);
    return fuzz_select_target(selector, input, std::forward<Args>(args)...);
}

struct Network;
struct Random;

struct System {
    std::unique_ptr<Tox_System> sys;
    std::unique_ptr<Network> ns;
    std::unique_ptr<Random> rng;

    // Not inline because sizeof of the above 2 structs is not known everywhere.
    ~System();

    /** @brief Deterministic system clock for this instance.
     *
     * Different instances can evolve independently. The time is initialised
     * with a large number, because otherwise many zero-initialised "empty"
     * friends inside toxcore will be "not timed out" for a long time, messing
     * up some logic. Tox moderately depends on the clock being fairly high up
     * (not close to 0).
     */
    uint64_t clock = UINT32_MAX;
};

/**
 * A Tox_System implementation that consumes fuzzer input to produce network
 * inputs and random numbers. Once it runs out of fuzzer input, network receive
 * functions return no more data and the random numbers are always zero.
 */
struct Fuzz_System : System {
    Fuzz_Data &data;

    explicit Fuzz_System(Fuzz_Data &input);
};

/**
 * A Tox_System implementation that consumes no fuzzer input but still has a
 * working and deterministic RNG. Network receive functions always fail, send
 * always succeeds.
 */
struct Null_System : System {
    uint64_t seed = 4;  // chosen by fair dice roll. guaranteed to be random.

    Null_System();
};

/**
 * A Tox_System implementation that records all I/O but does not actually
 * perform any real I/O. Everything inside this system is hermetic in-process
 * and fully deterministic.
 *
 * Note: take care not to initialise two systems with the same seed, since
 * that's the only thing distinguishing the system's behaviour. Two toxes
 * initialised with the same seed will be identical (same keys, etc.).
 */
struct Record_System : System {
    /** @brief State shared between all tox instances. */
    struct Global {
        /** @brief Bound UDP ports and their system instance.
         *
         * This implements an in-process network where instances can send
         * packets to other instances by inserting them into the receiver's
         * recvq using the receive function.
         *
         * We need to keep track of ports associated with recv queues because
         * toxcore sends packets to itself sometimes when doing onion routing
         * with only 2 nodes in the network.
         */
        std::unordered_map<uint16_t, Record_System *> bound;
    };

    Global &global_;
    uint64_t seed_;  //!< Current PRNG state.
    const char *name_;  //!< Tox system name ("tox1"/"tox2") for logging.

    std::deque<std::pair<uint16_t, std::vector<uint8_t>>> recvq;
    uint16_t port = 0;  //!< Sending port for this system instance.
    std::vector<uint8_t> recording;

    explicit Record_System(Global &global, uint64_t seed, const char *name);

    /** @brief Deposit a network packet in this instance's recvq.
     */
    void receive(uint16_t send_port, const uint8_t *buf, size_t len);
};

/** @brief Enable debug logging.
 *
 * This should not be enabled in fuzzer code while fuzzing, as console I/O slows
 * everything down drastically. It's useful while developing the fuzzer and the
 * protodump program.
 */
extern const bool DEBUG;

#endif  // C_TOXCORE_TESTING_FUZZING_FUZZ_SUPPORT_H
