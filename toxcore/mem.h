/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2025 The TokTok team.
 * Copyright © 2013 Tox project.
 */

/**
 * Memory allocation and deallocation functions.
 */
#ifndef C_TOXCORE_TOXCORE_MEM_H
#define C_TOXCORE_TOXCORE_MEM_H

#include <stdint.h>     // uint*_t

#include "attributes.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef void *mem_malloc_cb(void *obj, uint32_t size);
typedef void *mem_calloc_cb(void *obj, uint32_t nmemb, uint32_t size);
typedef void *mem_realloc_cb(void *obj, void *ptr, uint32_t size);
typedef void mem_free_cb(void *obj, void *ptr);

/** @brief Functions wrapping standard C memory allocation functions. */
typedef struct Memory_Funcs {
    mem_malloc_cb *malloc;
    mem_calloc_cb *calloc;
    mem_realloc_cb *realloc;
    mem_free_cb *free;
} Memory_Funcs;

typedef struct Memory {
    const Memory_Funcs *funcs;
    void *obj;
} Memory;

const Memory *os_memory(void);

/**
 * @brief Allocate an array of a given size for built-in types.
 *
 * The array will not be initialised. Supported built-in types are
 * `uint8_t`, `int8_t`, and `int16_t`.
 */
void *mem_balloc(non_null() const Memory *mem, uint32_t size);

/**
 * @brief Resize an array of a given size for built-in types.
 *
 * If used for a type other than byte-sized types, `size` needs to be manually
 * multiplied by the element size.
 */
void *mem_brealloc(non_null() const Memory *mem, nullable() void *ptr, uint32_t size);

/**
 * @brief Allocate a single object.
 *
 * Always use as `(T *)mem_alloc(mem, sizeof(T))`.
 */
void *mem_alloc(non_null() const Memory *mem, uint32_t size);

/**
 * @brief Allocate a vector (array) of objects.
 *
 * Always use as `(T *)mem_valloc(mem, N, sizeof(T))`.
 */
void *mem_valloc(non_null() const Memory *mem, uint32_t nmemb, uint32_t size);

/**
 * @brief Resize an object vector.
 *
 * Changes the size of (and possibly moves) the memory block pointed to by
 * @p ptr to be large enough for an array of @p nmemb elements, each of which
 * is @p size bytes. It is similar to the call
 *
 * @code
 * realloc(ptr, nmemb * size);
 * @endcode
 *
 * However, unlike that `realloc()` call, `mem_vrealloc()` fails safely in the
 * case where the multiplication would overflow. If such an overflow occurs,
 * `mem_vrealloc()` returns `nullptr`.
 */
void *mem_vrealloc(non_null() const Memory *mem, nullable() void *ptr, uint32_t nmemb, uint32_t size);

/** @brief Free an array, object, or object vector. */
void mem_delete(non_null() const Memory *mem, nullable() void *ptr);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* C_TOXCORE_TOXCORE_MEM_H */
