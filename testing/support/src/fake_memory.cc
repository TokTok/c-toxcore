#include "../doubles/fake_memory.hh"

#include <cstdlib>
#include <iostream>
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

    void *ptr = std::malloc(size + sizeof(Header));
    if (!ptr) {
        return nullptr;
    }

    Header *header = static_cast<Header *>(ptr);
    header->size = size;
    header->magic = kMagic;

    current_allocation_ += size;
    if (current_allocation_ > max_allocation_) {
        max_allocation_ = current_allocation_;
    }

    void *res = header + 1;
    // std::cerr << "[FakeMemory] malloc(" << size << ") -> " << res << " (header=" << header << ")"
    // << std::endl;
    return res;
}

void *FakeMemory::realloc(void *ptr, size_t size)
{
    if (!ptr) {
        return malloc(size);
    }

    Header *old_header = static_cast<Header *>(ptr) - 1;
    if (old_header->magic != kMagic) {
        if (old_header->magic == kFreeMagic) {
            std::cerr << "[FakeMemory] realloc: Double realloc/free detected at " << ptr
                      << " (header=" << old_header << ")" << std::endl;
        } else {
            std::cerr << "[FakeMemory] realloc: Invalid pointer (wrong magic 0x" << std::hex
                      << old_header->magic << ") at " << ptr << " (header=" << old_header << ")"
                      << std::endl;
        }
        std::abort();
    }

    bool fail = failure_injector_ && failure_injector_(size);

    if (observer_) {
        observer_(!fail);
    }

    if (fail) {
        // If realloc fails, original block is left untouched.
        return nullptr;
    }

    size_t old_size = old_header->size;
    void *new_ptr = std::realloc(old_header, size + sizeof(Header));
    if (!new_ptr) {
        return nullptr;
    }

    Header *header = static_cast<Header *>(new_ptr);
    current_allocation_ -= old_size;
    current_allocation_ += size;
    if (current_allocation_ > max_allocation_) {
        max_allocation_ = current_allocation_;
    }

    header->size = size;
    header->magic = kMagic;
    void *res = header + 1;
    // std::cerr << "[FakeMemory] realloc(" << ptr << ", " << size << ") -> " << res << " (header="
    // << header << ")" << std::endl;
    return res;
}

void FakeMemory::free(void *ptr)
{
    if (!ptr) {
        return;
    }

    Header *header = static_cast<Header *>(ptr) - 1;
    if (header->magic != kMagic) {
        if (header->magic == kFreeMagic) {
            std::cerr << "[FakeMemory] free: Double free detected at " << ptr
                      << " (header=" << header << ")" << std::endl;
        } else {
            std::cerr << "[FakeMemory] free: Invalid pointer (wrong magic 0x" << std::hex
                      << header->magic << ") at " << ptr << " (header=" << header << ")"
                      << std::endl;
        }
        std::abort();
    }

    size_t size = header->size;
    current_allocation_ -= size;
    header->magic = kFreeMagic;  // Mark as free
    std::free(header);
}

void FakeMemory::set_failure_injector(FailureInjector injector)
{
    failure_injector_ = std::move(injector);
}

void FakeMemory::set_observer(Observer observer) { observer_ = std::move(observer); }

struct Tox_Memory FakeMemory::get_c_memory() { return Tox_Memory{&kFakeMemoryVtable, this}; }

}  // namespace tox::test
