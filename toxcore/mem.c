/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2023 The TokTok team.
 * Copyright © 2013 Tox project.
 */

#include "mem.h"

#include <string.h>

#include "ccompat.h"
#include "tox_memory.h"

void *mem_balloc(const Memory *mem, uint32_t size)
{
    void *const ptr = tox_memory_malloc(mem, size);
    return ptr;
}

void *mem_brealloc(const Memory *mem, void *ptr, uint32_t size)
{
    void *const new_ptr = tox_memory_realloc(mem, ptr, size);
    return new_ptr;
}

void *mem_alloc(const Memory *mem, uint32_t size)
{
    void *const ptr = tox_memory_malloc(mem, size);
    if (ptr != nullptr) {
        memset(ptr, 0, size);
    }
    return ptr;
}

void *mem_valloc(const Memory *mem, uint32_t nmemb, uint32_t size)
{
    const uint32_t bytes = nmemb * size;

    if (size != 0 && bytes / size != nmemb) {
        return nullptr;
    }

    void *const ptr = tox_memory_malloc(mem, bytes);
    if (ptr != nullptr) {
        memset(ptr, 0, bytes);
    }
    return ptr;
}

void *mem_vrealloc(const Memory *mem, void *ptr, uint32_t nmemb, uint32_t size)
{
    const uint32_t bytes = nmemb * size;

    if (size != 0 && bytes / size != nmemb) {
        return nullptr;
    }

    void *const new_ptr = tox_memory_realloc(mem, ptr, bytes);
    return new_ptr;
}

void mem_delete(const Memory *mem, void *ptr) { tox_memory_dealloc(mem, ptr); }
