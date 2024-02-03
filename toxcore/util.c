/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2018 The TokTok team.
 * Copyright © 2013 Tox project.
 * Copyright © 2013 plutooo
 */

/**
 * Utilities.
 */
#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 600
#endif /* _XOPEN_SOURCE */

#include "util.h"

#include <stdlib.h>
#include <string.h>

#include "attributes.h"
#include "ccompat.h"
#include "mem.h"

bool is_power_of_2(uint64_t x)
{
    return x != 0 && (x & (~x + 1)) == x;
}

void free_uint8_t_pointer_array(const Memory *mem, uint8_t **ary, size_t n_items)
{
    if (ary == nullptr) {
        return;
    }

    for (size_t i = 0; i < n_items; ++i) {
        if (ary[i] != nullptr) {
            mem_delete(mem, ary[i]);
        }
    }

    mem_delete(mem, ary);
}

uint16_t data_checksum(const uint8_t *data, uint32_t length)
{
    uint8_t checksum[2] = {0};
    uint16_t check;

    for (uint32_t i = 0; i < length; ++i) {
        checksum[i % 2] ^= data[i];
    }

    memcpy(&check, checksum, sizeof(check));
    return check;
}

int create_recursive_mutex(pthread_mutex_t *mutex)
{
    pthread_mutexattr_t attr;

    if (pthread_mutexattr_init(&attr) != 0) {
        return -1;
    }

    if (pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE) != 0) {
        pthread_mutexattr_destroy(&attr);
        return -1;
    }

    /* Create queue mutex */
    if (pthread_mutex_init(mutex, &attr) != 0) {
        pthread_mutexattr_destroy(&attr);
        return -1;
    }

    pthread_mutexattr_destroy(&attr);

    return 0;
}

bool memeq(const uint8_t *a, size_t a_size, const uint8_t *b, size_t b_size)
{
    return a_size == b_size && memcmp(a, b, a_size) == 0;
}

uint8_t *memdup(const uint8_t *data, size_t data_size)
{
    if (data == nullptr || data_size == 0) {
        return nullptr;
    }

    uint8_t *copy = (uint8_t *)malloc(data_size);

    if (copy != nullptr) {
        memcpy(copy, data, data_size);
    }

    return copy;
}

void memzero(uint8_t *data, size_t data_size)
{
    if (data == nullptr || data_size == 0) {
        return;
    }

    memset(data, 0, data_size);
}

int16_t max_s16(int16_t a, int16_t b)
{
    return a > b ? a : b;
}
int32_t max_s32(int32_t a, int32_t b)
{
    return a > b ? a : b;
}
int64_t max_s64(int64_t a, int64_t b)
{
    return a > b ? a : b;
}

int16_t min_s16(int16_t a, int16_t b)
{
    return a < b ? a : b;
}
int32_t min_s32(int32_t a, int32_t b)
{
    return a < b ? a : b;
}
int64_t min_s64(int64_t a, int64_t b)
{
    return a < b ? a : b;
}

uint8_t max_u08(uint8_t a, uint8_t b)
{
    return a > b ? a : b;
}
uint16_t max_u16(uint16_t a, uint16_t b)
{
    return a > b ? a : b;
}
uint32_t max_u32(uint32_t a, uint32_t b)
{
    return a > b ? a : b;
}
uint64_t max_u64(uint64_t a, uint64_t b)
{
    return a > b ? a : b;
}

uint16_t min_u16(uint16_t a, uint16_t b)
{
    return a < b ? a : b;
}
uint32_t min_u32(uint32_t a, uint32_t b)
{
    return a < b ? a : b;
}
uint64_t min_u64(uint64_t a, uint64_t b)
{
    return a < b ? a : b;
}

int cmp_uint(uint64_t a, uint64_t b)
{
    return (a > b ? 1 : 0) - (a < b ? 1 : 0);
}

uint32_t jenkins_one_at_a_time_hash(const uint8_t *key, size_t len)
{
    uint32_t hash = 0;

    for (uint32_t i = 0; i < len; ++i) {
        hash += key[i];
        hash += (uint32_t)((uint64_t)hash << 10);
        hash ^= hash >> 6;
    }

    hash += (uint32_t)((uint64_t)hash << 3);
    hash ^= hash >> 11;
    hash += (uint32_t)((uint64_t)hash << 15);
    return hash;
}

non_null()
static void merge_sort_merge_back(
    void *arr,
    const void *l_arr, uint32_t l_arr_size,
    const void *r_arr, uint32_t r_arr_size,
    uint32_t left_start,
    const void *object, const Sort_Funcs *funcs)
{
    uint32_t li = 0;
    uint32_t ri = 0;
    uint32_t k = left_start;

    while (li < l_arr_size && ri < r_arr_size) {
        const void *l = funcs->get_callback(l_arr, li);
        const void *r = funcs->get_callback(r_arr, ri);
        // !(r < l) <=> (r >= l) <=> (l <= r)
        if (!funcs->less_callback(object, r, l)) {
            funcs->set_callback(arr, k, l);
            ++li;
        } else {
            funcs->set_callback(arr, k, r);
            ++ri;
        }
        ++k;
    }

    /* Copy the remaining elements of `l_arr[]`, if there are any. */
    while (li < l_arr_size) {
        funcs->set_callback(arr, k, funcs->get_callback(l_arr, li));
        ++li;
        ++k;
    }

    /* Copy the remaining elements of `r_arr[]`, if there are any. */
    while (ri < r_arr_size) {
        funcs->set_callback(arr, k, funcs->get_callback(r_arr, ri));
        ++ri;
        ++k;
    }
}

/** Function to merge the two haves `arr[left_start..mid]` and `arr[mid+1..right_end]` of array `arr[]`. */
non_null()
static void merge_sort_merge(
    void *arr, uint32_t left_start, uint32_t mid, uint32_t right_end, void *tmp,
    const void *object, const Sort_Funcs *funcs)
{
    const uint32_t l_arr_size = mid - left_start + 1;
    const uint32_t r_arr_size = right_end - mid;

    /* Temporary arrays, using the tmp buffer created in `merge_sort` below. */
    void *l_arr = funcs->subarr_callback(tmp, 0, l_arr_size);
    void *r_arr = funcs->subarr_callback(tmp, l_arr_size, r_arr_size);

    /* Copy data to temp arrays `l_arr[]` and `r_arr[]`. */
    for (uint32_t i = 0; i < l_arr_size; ++i) {
        funcs->set_callback(l_arr, i, funcs->get_callback(arr, left_start + i));
    }
    for (uint32_t i = 0; i < r_arr_size; ++i) {
        funcs->set_callback(r_arr, i, funcs->get_callback(arr, mid + 1 + i));
    }

    /* Merge the temp arrays back into `arr[left_start..right_end]`. */
    merge_sort_merge_back(arr, l_arr, l_arr_size, r_arr, r_arr_size, left_start, object, funcs);
}

bool merge_sort(void *arr, uint32_t arr_size, const void *object, const Sort_Funcs *funcs)
{
    void *tmp = funcs->alloc_callback(object, arr_size);

    if (tmp == nullptr) {
        return false;
    }

    // Merge subarrays in bottom up manner.  First merge subarrays of
    // size 1 to create sorted subarrays of size 2, then merge subarrays
    // of size 2 to create sorted subarrays of size 4, and so on.
    for (uint32_t curr_size = 1; curr_size <= arr_size - 1; curr_size = 2 * curr_size) {
        // Pick starting point of different subarrays of current size
        for (uint32_t left_start = 0; left_start < arr_size - 1; left_start += 2 * curr_size) {
            // Find ending point of left subarray. mid+1 is starting
            // point of right
            const uint32_t mid = min_u32(left_start + curr_size - 1, arr_size - 1);
            const uint32_t right_end = min_u32(left_start + 2 * curr_size - 1, arr_size - 1);

            // Merge Subarrays arr[left_start...mid] & arr[mid+1...right_end]
            merge_sort_merge(arr, left_start, mid, right_end, tmp, object, funcs);
        }
    }

    funcs->delete_callback(object, tmp, arr_size);
    return true;
}
