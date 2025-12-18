/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2025 The TokTok team.
 * Copyright © 2013 Tox project.
 */

#include "mem.h"

#include <string.h>

#include "ccompat.h"
#include "tox_memory.h"

void *_Owned _Nullable mem_balloc(const Memory *mem, uint32_t size)
{
    void *_Owned ptr = tox_memory_malloc(mem, size);
    return ptr;
}

void *_Owned _Nullable mem_brealloc(const Memory *mem, void *_Owned _Nullable ptr, uint32_t size)
{
    void *_Owned new_ptr = tox_memory_realloc(mem, ptr, size);
    return new_ptr;
}

void *_Owned _Nullable mem_alloc(const Memory *mem, uint32_t size)
{
    void *_Owned ptr = tox_memory_malloc(mem, size);
    if (ptr != nullptr) {
        memset(ptr, 0, size);
    }
    return ptr;
}

void *_Owned _Nullable mem_valloc(const Memory *mem, uint32_t nmemb, uint32_t size)
{
    const uint32_t bytes = nmemb * size;

    if (size != 0 && bytes / size != nmemb) {
        return nullptr;
    }

    void *_Owned ptr = tox_memory_malloc(mem, bytes);

    if (ptr != nullptr) {
        memset(ptr, 0, bytes);
    }

    return ptr;
}

void *_Owned _Nullable mem_vrealloc(const Memory *mem, void *_Owned _Nullable ptr, uint32_t nmemb, uint32_t size)
{
    const uint32_t bytes = nmemb * size;

    if (size != 0 && bytes / size != nmemb) {
        mem_delete(mem, ptr);
        return nullptr;
    }

    void *_Owned new_ptr = tox_memory_realloc(mem, ptr, bytes);
    return new_ptr;
}

void mem_delete(const Memory *mem, void *_Owned _Nullable ptr)
{
    tox_memory_dealloc(mem, ptr);
}
