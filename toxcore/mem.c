/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2023 The TokTok team.
 * Copyright © 2013 Tox project.
 */

#include "mem.h"

void *mem_balloc(const Memory *mem, uint32_t size)
{
    void *const ptr = tox_memory_malloc(mem, size);
    return ptr;
}

void *mem_alloc(const Memory *mem, uint32_t size)
{
    void *const ptr = tox_memory_calloc(mem, 1, size);
    return ptr;
}

void *mem_valloc(const Memory *mem, uint32_t nmemb, uint32_t size)
{
    void *const ptr = tox_memory_calloc(mem, nmemb, size);
    return ptr;
}

void *mem_vrealloc(const Memory *mem, void *ptr, uint32_t nmemb, uint32_t size)
{
    void *const new_ptr = tox_memory_vrealloc(mem, ptr, nmemb, size);
    return new_ptr;
}

void mem_delete(const Memory *mem, void *ptr)
{
    tox_memory_dealloc(mem, ptr);
}
