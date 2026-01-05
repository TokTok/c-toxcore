#include "../doubles/fake_memory.hh"

#include <cstdlib>
#include <new>

#include "../../../toxcore/tox_memory_impl.h"

namespace tox::test {

// --- Trampolines ---

static const Tox_Memory_Funcs kFakeMemoryVtable = {
    .malloc_callback
    = [](void *obj, uint32_t size) { return static_cast<FakeMemory *>(obj)->malloc(size); },
    .realloc_callback
    = [](void *obj, void *ptr,
          uint32_t size) { return static_cast<FakeMemory *>(obj)->realloc(ptr, size); },
    .dealloc_callback = [](void *obj, void *ptr) { static_cast<FakeMemory *>(obj)->free(ptr); },
};

// --- Implementation ---

FakeMemory::FakeMemory() = default;
FakeMemory::~FakeMemory() = default;

void *FakeMemory::malloc(size_t size)
{
    bool fail = failure_injector_ && failure_injector_(size);

    if (observer_) {
        observer_(!fail);
    }

    if (fail) {
        return nullptr;
    }
    return std::malloc(size);
}

void *FakeMemory::realloc(void *ptr, size_t size)
{
    bool fail = failure_injector_ && failure_injector_(size);

    if (observer_) {
        observer_(!fail);
    }

    if (fail) {
        // If realloc fails, original block is left untouched.
        return nullptr;
    }
    return std::realloc(ptr, size);
}

void FakeMemory::free(void *ptr) { std::free(ptr); }

void FakeMemory::set_failure_injector(FailureInjector injector)
{
    failure_injector_ = std::move(injector);
}

void FakeMemory::set_observer(Observer observer) { observer_ = std::move(observer); }

struct Tox_Memory FakeMemory::get_c_memory() { return Tox_Memory{&kFakeMemoryVtable, this}; }

}  // namespace tox::test
