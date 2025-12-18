/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2022-2025 The TokTok team.
 */
#include "os_memory.h"

#include <stdlib.h>

#include "attributes.h"
#include "tox_memory.h"
#include "tox_memory_impl.h" // IWYU pragma: keep

static void *_Owned _Nullable os_malloc(void *_Nonnull self, uint32_t size)
{
    // cppcheck-suppress misra-c2012-21.3
    return malloc(size);
}

static void *_Owned _Nullable os_realloc(void *_Nonnull self, void *_Owned _Nullable ptr, uint32_t size)
{
    // cppcheck-suppress misra-c2012-21.3
    return realloc(ptr, size);
}

static void os_dealloc(void *_Nonnull self, void *_Owned _Nullable ptr)
{
    // cppcheck-suppress misra-c2012-21.3
    free(ptr);
}

static const Tox_Memory_Funcs os_memory_funcs = {
    os_malloc,
    os_realloc,
    os_dealloc,
};
const Tox_Memory os_memory_obj = {&os_memory_funcs};

const Tox_Memory *os_memory(void)
{
    return &os_memory_obj;
}
