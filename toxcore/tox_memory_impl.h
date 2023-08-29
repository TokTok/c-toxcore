/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2018 The TokTok team.
 * Copyright © 2013 Tox project.
 */

/**
 * Datatypes, functions and includes for the core networking.
 */
#ifndef C_TOXCORE_TOXCORE_TOX_MEMORY_IMPL_H
#define C_TOXCORE_TOXCORE_TOX_MEMORY_IMPL_H

#include <stdint.h>     // uint*_t

#include "tox_memory.h"

#ifdef __cplusplus
extern "C" {
#endif

/** @brief Allocate a byte array, similar to malloc. */
typedef void *tox_memory_malloc_cb(void *self, uint32_t size);
/** @brief Allocate a zero-initialised object array, similar to calloc. */
typedef void *tox_memory_calloc_cb(void *self, uint32_t nmemb, uint32_t size);
/** @brief Reallocate an object array, similar to realloc. */
typedef void *tox_memory_vrealloc_cb(void *self, void *ptr, uint32_t nmemb, uint32_t size);
/**
 * @brief Deallocate a byte or object array, similar to free.
 *
 * Note that `tox_memory_free` will use this callback to deallocate itself, so
 * once the deallocation is done, the allocator data structures can no longer be
 * referenced.
 */
typedef void tox_memory_dealloc_cb(void *self, void *ptr);

/** @brief Functions wrapping standard C memory allocation functions. */
struct Tox_Memory_Funcs {
    tox_memory_malloc_cb *malloc_callback;
    tox_memory_calloc_cb *calloc_callback;
    tox_memory_vrealloc_cb *realloc_callback;
    tox_memory_dealloc_cb *dealloc_callback;
};

struct Tox_Memory {
    const Tox_Memory_Funcs *funcs;
    void *user_data;
};

#ifdef __cplusplus
}  // extern "C"
#endif

#endif  /* C_TOXCORE_TOXCORE_TOX_MEMORY_IMPL_H */
