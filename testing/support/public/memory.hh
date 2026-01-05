#ifndef C_TOXCORE_TESTING_SUPPORT_PUBLIC_MEMORY_H
#define C_TOXCORE_TESTING_SUPPORT_PUBLIC_MEMORY_H

#include <cstddef>
#include <cstdint>

namespace tox::test {

/**
 * @brief Abstraction over the memory allocator.
 */
class MemorySystem {
public:
    virtual ~MemorySystem();

    virtual void *malloc(size_t size) = 0;
    virtual void *realloc(void *ptr, size_t size) = 0;
    virtual void free(void *ptr) = 0;
};

}  // namespace tox::test

#endif  // C_TOXCORE_TESTING_SUPPORT_PUBLIC_MEMORY_H
