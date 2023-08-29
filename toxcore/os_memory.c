/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2022-2023 The TokTok team.
 */
#include "os_memory.h"

#include <stdlib.h>

#include "ccompat.h"
#include "tox_memory_impl.h"

non_null()
static void *os_malloc(void *self, uint32_t size)
{
    // cppcheck-suppress misra-c2012-21.3
    return malloc(size);
}

non_null(1) nullable(2)
static void *os_realloc(void *self, void *ptr, uint32_t size)
{
    // cppcheck-suppress misra-c2012-21.3
    return realloc(ptr, size);
}

non_null(1) nullable(2)
static void os_free(void *self, void *ptr)
{
    // cppcheck-suppress misra-c2012-21.3
    free(ptr);
}

static const Tox_Memory_Funcs os_memory_funcs = {
    os_malloc,
    os_realloc,
    os_free,
};
const Tox_Memory os_memory_obj = {&os_memory_funcs};

const Tox_Memory *os_memory(void)
{
    return &os_memory_obj;
}
