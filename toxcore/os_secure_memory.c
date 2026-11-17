/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2026 The TokTok team.
 */

#include "os_secure_memory.h"

#include <sodium.h>
#include <stddef.h>

#include "attributes.h"
#include "ccompat.h"
#include "mem.h"
#include "os_memory.h"

/** Sizes are rounded up to a multiple of this, because libsodium aligns the end of an allocation, not the start. */
#define OS_SECURE_MEMORY_ALIGNMENT 16

static void *_Nullable os_secure_malloc(void *_Nullable self, uint32_t size)
{
    // sodium_malloc needs libsodium to be initialised.
    if (sodium_init() == -1) {
        return nullptr;
    }
    const size_t units = ((size_t)size + OS_SECURE_MEMORY_ALIGNMENT - 1) / OS_SECURE_MEMORY_ALIGNMENT;
    return sodium_malloc(units * OS_SECURE_MEMORY_ALIGNMENT);
}

static void *_Nullable os_secure_realloc(void *_Nullable self, void *_Nullable ptr, uint32_t size)
{
    // We can't resize, because libsodium doesn't tell us the size of the old allocation.
    return ptr == nullptr ? os_secure_malloc(self, size) : nullptr;
}

static void os_secure_dealloc(void *_Nullable self, void *_Nullable ptr)
{
    sodium_free(ptr);
}

static const Memory_Funcs os_secure_memory_funcs = {
    os_secure_malloc,
    os_secure_realloc,
    os_secure_dealloc,
};
static const Memory os_secure_memory_obj = {&os_secure_memory_funcs};

const Memory *os_secure_memory(void)
{
#if defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
    return os_memory();
#else
    return &os_secure_memory_obj;
#endif /* FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION */
}
