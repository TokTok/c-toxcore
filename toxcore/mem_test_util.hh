#ifndef C_TOXCORE_TOXCORE_MEM_TEST_UTIL_H
#define C_TOXCORE_TOXCORE_MEM_TEST_UTIL_H

#include "mem.h"
#include "os_memory.h"
#include "test_util.hh"
#include "tox_memory_impl.h"

struct Memory_Class {
    static Tox_Memory_Funcs const vtable;
    Tox_Memory const self;

    operator Tox_Memory const *() const { return &self; }

    Memory_Class(Memory_Class const &) = default;
    Memory_Class()
        : self{&vtable, this}
    {
    }

    virtual ~Memory_Class();
    virtual tox_memory_malloc_cb malloc = 0;
    virtual tox_memory_realloc_cb realloc = 0;
    virtual tox_memory_dealloc_cb dealloc = 0;
};

/**
 * Base test Memory class that just forwards to os_memory. Can be
 * subclassed to override individual (or all) functions.
 */
class Test_Memory : public Memory_Class {
    const Tox_Memory *mem = REQUIRE_NOT_NULL(os_memory());

    void *malloc(void *obj, uint32_t size) override;
    void *realloc(void *obj, void *ptr, uint32_t size) override;
    void dealloc(void *obj, void *ptr) override;
};

#endif  // C_TOXCORE_TOXCORE_MEM_TEST_UTIL_H
