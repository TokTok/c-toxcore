/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2018 The TokTok team.
 * Copyright © 2013 Tox project.
 * Copyright © 2013 plutooo
 */

/**
 * Utilities.
 */
#ifndef C_TOXCORE_TOXCORE_UTIL_H
#define C_TOXCORE_TOXCORE_UTIL_H

#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "attributes.h"
#include "mem.h"

#ifdef __cplusplus
extern "C" {
#endif

bool is_power_of_2(uint64_t x);

/** @brief Frees all pointers in a uint8_t pointer array, as well as the array itself. */
non_null(1) nullable(2)
void free_uint8_t_pointer_array(const Memory *mem, uint8_t **ary, size_t n_items);

/** Returns -1 if failed or 0 if success */
non_null() int create_recursive_mutex(pthread_mutex_t *mutex);

/**
 * @brief Checks whether two buffers are the same length and contents.
 *
 * Calls `memcmp` after checking the sizes are equal.
 *
 * @retval true if sizes and contents are equal.
 * @retval false otherwise.
 */
non_null() bool memeq(const uint8_t *a, size_t a_size, const uint8_t *b, size_t b_size);

/**
 * @brief Copies a byte array of a given size into a newly allocated one.
 *
 * @return nullptr on allocation failure or if the input data was nullptr or data_size was 0.
 */
nullable(1) uint8_t *memdup(const uint8_t *data, size_t data_size);

/**
 * @brief Set all bytes in `data` to 0.
 *
 * NOTE: This does not securely zero out data. DO NOT USE for sensitive data. Use
 * `crypto_memzero` from `crypto_core.h`, instead. This function is ok to use for
 * message buffers, public keys, encrypted data, etc. It is not ok for buffers
 * containing key material (secret keys, shared keys).
 */
nullable(1) void memzero(uint8_t *data, size_t data_size);

// Safe min/max functions with specific types. This forces the conversion to the
// desired type before the comparison expression, giving the choice of
// conversion to the caller. Use these instead of inline comparisons or MIN/MAX
// macros (effectively inline comparisons).
int16_t max_s16(int16_t a, int16_t b);
int32_t max_s32(int32_t a, int32_t b);
int64_t max_s64(int64_t a, int64_t b);

int16_t min_s16(int16_t a, int16_t b);
int32_t min_s32(int32_t a, int32_t b);
int64_t min_s64(int64_t a, int64_t b);

uint8_t max_u08(uint8_t a, uint8_t b);
uint16_t max_u16(uint16_t a, uint16_t b);
uint32_t max_u32(uint32_t a, uint32_t b);
uint64_t max_u64(uint64_t a, uint64_t b);

uint16_t min_u16(uint16_t a, uint16_t b);
uint32_t min_u32(uint32_t a, uint32_t b);
uint64_t min_u64(uint64_t a, uint64_t b);

// Comparison function: return -1 if a<b, 0 if a==b, 1 if a>b.
int cmp_uint(uint64_t a, uint64_t b);

/** @brief Returns a 32-bit hash of key of size len */
non_null()
uint32_t jenkins_one_at_a_time_hash(const uint8_t *key, size_t len);

/** @brief Computes a checksum of a byte array.
 *
 * @param data The byte array used to compute the checksum.
 * @param length The length in bytes of the passed data.
 *
 * @retval The resulting checksum.
 */
non_null()
uint16_t data_checksum(const uint8_t *data, uint32_t length);

/** @brief Compare elements with a less-than ordering: `a < b`. */
typedef bool sort_less_cb(const void *object, const void *a, const void *b);
/** @brief Get element from array at index. */
typedef const void *sort_get_cb(const void *arr, uint32_t index);
/** @brief Set element in array at index to new value (perform copy). */
typedef void sort_set_cb(void *arr, uint32_t index, const void *val);
/** @brief Get a sub-array at an index of a given size (mutable pointer).
 *
 * Used to index in the temporary array allocated by `sort_alloc_cb` and get
 * a sub-array for working memory.
 */
typedef void *sort_subarr_cb(void *arr, uint32_t index, uint32_t size);
/** @brief Allocate a new array of the element type.
 *
 * @param size The array size in elements of type T (not byte size). This value
 *   is always exactly the input array size as passed to `merge_sort`.
 */
typedef void *sort_alloc_cb(const void *object, uint32_t size);
/** @brief Free the element type array. */
typedef void sort_delete_cb(const void *object, void *arr, uint32_t size);

/** @brief Virtual function table for getting/setting elements in an array and
 * comparing them.
 *
 * Only the `less`, `alloc`, and `delete` functions get a `this`-pointer. We
 * assume that indexing in an array doesn't need any other information than the
 * array itself.
 *
 * For now, the `this`-pointer is const, because we assume sorting doesn't need
 * to mutate any state, but if necessary that can be changed in the future.
 */
typedef struct Sort_Funcs {
    sort_less_cb *less_callback;
    sort_get_cb *get_callback;
    sort_set_cb *set_callback;
    sort_subarr_cb *subarr_callback;
    sort_alloc_cb *alloc_callback;
    sort_delete_cb *delete_callback;
} Sort_Funcs;

/** @brief Non-recursive merge sort function to sort `arr[0...arr_size-1]`.
 *
 * Avoids `memcpy` and avoids treating elements as byte arrays. Instead, uses
 * callbacks to index in arrays and copy elements. This makes it quite a bit
 * slower than `qsort`, but works with elements that require special care when
 * being copied (e.g. if they are part of a graph or other data structure that
 * with pointers or other invariants).
 *
 * Allocates a single temporary array with the provided alloc callback, and
 * frees it at the end. This is significantly faster than an in-place
 * implementation.
 *
 * This could be made more efficient by providing range-copy functions instead
 * of calling the get/set callback for every element, but that increases code
 * complexity on the caller.
 *
 * Complexity:
 * - Space: `O(n) where n = array_size`.
 * - Time: `O(n * log n) where n = array_size`.
 *
 * @param[in,out] arr An array of type T.
 * @param arr_size Number of elements in @p arr (count, not byte size).
 * @param[in] object Comparator object.
 * @param[in] funcs Callback struct for elements of type T.
 */
non_null()
bool merge_sort(void *arr, uint32_t arr_size, const void *object, const Sort_Funcs *funcs);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* C_TOXCORE_TOXCORE_UTIL_H */
