#ifndef C_TOXCORE_TESTING_SUPPORT_RANDOM_H
#define C_TOXCORE_TESTING_SUPPORT_RANDOM_H

#include <cstdint>
#include <vector>

namespace tox::test {

/**
 * @brief Abstraction over the random number generator.
 */
class RandomSystem {
public:
    virtual ~RandomSystem();

    virtual uint32_t uniform(uint32_t upper_bound) = 0;
    virtual void bytes(uint8_t *out, size_t count) = 0;
};

}  // namespace tox::test

#endif  // C_TOXCORE_TESTING_SUPPORT_RANDOM_H
