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
 * @brief Allocate a single zero-initialised object.
 *
 * Always use as `(T *)tox_memory_alloc(mem, sizeof(T))`. Unlike `calloc`, this
 * does not support allocating arrays. Use `malloc` and `memset` for that.
 *
 * @param mem The memory allocator.
 * @param size Size in bytes of each element.
 */
non_null() void *tox_memory_alloc(const Tox_Memory *mem, uint32_t size);

/** @brief Resize a memory chunk vector. */
non_null(1) nullable(2) void *tox_memory_realloc(const Tox_Memory *mem, void *ptr, uint32_t size);

/** @brief Free an array, object, or object vector. */
non_null(1) nullable(2) void tox_memory_dealloc(const Tox_Memory *mem, void *ptr);

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  // C_TOXCORE_TOXCORE_TOX_MEMORY_H
