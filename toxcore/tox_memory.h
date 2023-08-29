/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2018 The TokTok team.
 * Copyright © 2013 Tox project.
 */

/**
 * Memory allocation and deallocation functions.
 */
#ifndef C_TOXCORE_TOXCORE_TOX_MEMORY_H
#define C_TOXCORE_TOXCORE_TOX_MEMORY_H

#include <stdint.h>     // uint*_t

#include "tox_attributes.h"

#ifdef __cplusplus
extern "C" {
#endif

/** @brief Functions wrapping standard C memory allocation functions. */
typedef struct Tox_Memory_Funcs Tox_Memory_Funcs;

/**
 * @brief A dynamic memory allocator.
 */
typedef struct Tox_Memory Tox_Memory;

/**
 * @brief Allocates a new allocator using itself to allocate its own memory.
 *
 * The passed `user_data` is stored and passed to allocator callbacks. It must
 * outlive the `Tox_Memory` object, since it may be used by the callback invoked
 * in `tox_memory_free`.
 *
 * @return NULL if allocation fails.
 */
non_null(1) nullable(2)
Tox_Memory *tox_memory_new(const Tox_Memory_Funcs *funcs, void *user_data);

/**
 * @brief Destroys the allocator using its own deallocation function.
 *
 * The stored `user_data` will not be deallocated.
 */
nullable(1) void tox_memory_free(Tox_Memory *mem);

/**
 * @brief Allocate an array of a given size for built-in types.
 *
 * The array will not be initialised. Supported built-in types are
 * `uint8_t`, `int8_t`, and `int16_t`.
 */
non_null() void *tox_memory_malloc(const Tox_Memory *mem, uint32_t size);

/**
 * @brief Allocate a vector (array) of zero-initialised objects.
 *
 * Always use as `(T *)tox_memory_calloc(mem, N, sizeof(T))`.
 *
 * @param mem The memory allocator.
 * @param nmemb Number of array elements (can be 1 to allocate a single object).
 * @param size Size in bytes of each element.
 */
non_null() void *tox_memory_calloc(const Tox_Memory *mem, uint32_t nmemb, uint32_t size);

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
non_null(1) nullable(2) void *tox_memory_vrealloc(const Tox_Memory *mem, void *ptr, uint32_t nmemb, uint32_t size);

/** @brief Free an array, object, or object vector. */
non_null(1) nullable(2) void tox_memory_dealloc(const Tox_Memory *mem, void *ptr);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  /* C_TOXCORE_TOXCORE_TOX_MEMORY_H */
