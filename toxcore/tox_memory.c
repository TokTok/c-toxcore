/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2018 The TokTok team.
 * Copyright © 2013 Tox project.
 */
#include "tox_memory.h"

#include <string.h>

#include "ccompat.h"
#include "tox_memory_impl.h"

Tox_Memory *tox_memory_new(const Tox_Memory_Funcs *funcs, void *user_data)
{
    const Tox_Memory bootstrap = {funcs, user_data};

    Tox_Memory *mem = tox_memory_alloc(&bootstrap, sizeof(Tox_Memory));

    if (mem == nullptr) {
        return nullptr;
    }

    *mem = bootstrap;

    return mem;
}

void tox_memory_free(Tox_Memory *mem)
{
    if (mem == nullptr) {
        return;
    }

    tox_memory_dealloc(mem, mem);
}

void *tox_memory_malloc(const Tox_Memory *mem, uint32_t size)
{
    void *const ptr = mem->funcs->malloc_callback(mem->user_data, size);
    return ptr;
}

void *tox_memory_alloc(const Tox_Memory *mem, uint32_t size)
{
    void *const ptr = tox_memory_malloc(mem, size);
    if (ptr != nullptr) {
        memset(ptr, 0, size);
    }
    return ptr;
}

void *tox_memory_realloc(const Tox_Memory *mem, void *ptr, uint32_t size)
{
    void *const new_ptr = mem->funcs->realloc_callback(mem->user_data, ptr, size);
    return new_ptr;
}

void tox_memory_dealloc(const Tox_Memory *mem, void *ptr)
{
    mem->funcs->dealloc_callback(mem->user_data, ptr);
}
