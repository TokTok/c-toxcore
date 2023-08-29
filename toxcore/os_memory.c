#include "os_memory.h"

#include <stdlib.h>

#include "ccompat.h"
#include "tox_memory_impl.h"

non_null()
static void *os_malloc(void *self, uint32_t size)
{
    return malloc(size);
}

non_null()
static void *os_calloc(void *self, uint32_t nmemb, uint32_t size)
{
    return calloc(nmemb, size);
}

non_null(1) nullable(2)
static void *os_vrealloc(void *self, void *ptr, uint32_t nmemb, uint32_t size)
{
    const uint32_t bytes = nmemb * size;

    if (size != 0 && bytes / size != nmemb) {
        return nullptr;
    }

    return realloc(ptr, bytes);
}

non_null(1) nullable(2)
static void os_free(void *self, void *ptr)
{
    free(ptr);
}

static const Tox_Memory_Funcs os_memory_funcs = {
    os_malloc,
    os_calloc,
    os_vrealloc,
    os_free,
};
static const Tox_Memory os_memory_obj = {&os_memory_funcs};

const Tox_Memory *os_memory(void)
{
    return &os_memory_obj;
}
