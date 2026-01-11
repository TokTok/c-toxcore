#ifndef C_TOXCORE_TESTING_SUPPORT_DOUBLES_FAKE_MEMORY_H
#define C_TOXCORE_TESTING_SUPPORT_DOUBLES_FAKE_MEMORY_H

#include <functional>

#include "../public/memory.hh"

// Forward declaration
struct Tox_Memory;

namespace tox::test {

class FakeMemory : public MemorySystem {
public:
    using FailureInjector = std::function<bool(size_t size)>;  // Return true to fail
    using Observer = std::function<void(bool success)>;

    FakeMemory();
    ~FakeMemory() override;

    void *malloc(size_t size) override;
    void *realloc(void *ptr, size_t size) override;
    void free(void *ptr) override;

    // Configure failure injection
    void set_failure_injector(FailureInjector injector);

    // Configure observer
    void set_observer(Observer observer);

    // Get the C-compatible struct
    struct Tox_Memory get_c_memory();

private:
    struct Header {
        size_t size;
        size_t magic;
    };
    static constexpr size_t kMagic = 0xDEADC0DE;
    static constexpr size_t kFreeMagic = 0xBAADF00D;

    size_t current_allocation_ = 0;
    size_t max_allocation_ = 0;

    FailureInjector failure_injector_;
    Observer observer_;
};

}  // namespace tox::test

#endif  // C_TOXCORE_TESTING_SUPPORT_DOUBLES_FAKE_MEMORY_H
