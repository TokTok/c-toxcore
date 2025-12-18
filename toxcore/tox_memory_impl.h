/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2025 The TokTok team.
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
typedef void *_Owned _Nullable tox_memory_malloc_cb(void *_Nonnull self, uint32_t size);
/** @brief Reallocate a byte array, similar to realloc. */
typedef void *_Owned _Nullable tox_memory_realloc_cb(void *_Nonnull self, void *_Owned _Nullable ptr, uint32_t size);
/**
 * @brief Deallocate a byte or object array, similar to free.
 *
 * Note that `tox_memory_free` will use this callback to deallocate itself, so
 * once the deallocation is done, the allocator data structures can no longer be
 * referenced.
 */
typedef void tox_memory_dealloc_cb(void *_Nonnull self, void *_Owned _Nullable ptr);

/** @brief Functions wrapping standard C memory allocation functions. */
struct Tox_Memory_Funcs {
    tox_memory_malloc_cb *_Nonnull malloc_callback;
    tox_memory_realloc_cb *_Nonnull realloc_callback;
    tox_memory_dealloc_cb *_Nonnull dealloc_callback;
};

struct Tox_Memory {
    const Tox_Memory_Funcs *_Nonnull funcs;
    void *_Nullable user_data;
};

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif  /* C_TOXCORE_TOXCORE_TOX_MEMORY_IMPL_H */
