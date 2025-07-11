/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2025 The TokTok team.
 * Copyright © 2013 Tox project.
 */

/** @file
 * @brief Implementation of an efficient array to store that we pinged something.
 */
#ifndef C_TOXCORE_TOXCORE_PING_ARRAY_H
#define C_TOXCORE_TOXCORE_PING_ARRAY_H

#include <stddef.h>
#include <stdint.h>

#include "attributes.h"
#include "crypto_core.h"
#include "mem.h"
#include "mono_time.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct Ping_Array Ping_Array;

/**
 * @brief Initialize a Ping_Array.
 *
 * @param size represents the total size of the array and should be a power of 2.
 * @param timeout represents the maximum timeout in seconds for the entry.
 *
 * @return pointer to allocated Ping_Array on success, nullptr on failure.
 */
struct Ping_Array *ping_array_new(non_null() const Memory *mem, uint32_t size, uint32_t timeout);

/**
 * @brief Free all the allocated memory in a @ref Ping_Array.
 */
void ping_array_kill(nullable() Ping_Array *array);
/**
 * @brief Add a data with length to the @ref Ping_Array list and return a ping_id.
 *
 * @return ping_id on success, 0 on failure.
 */
uint64_t ping_array_add(non_null() Ping_Array *array, non_null() const Mono_Time *mono_time, non_null() const Random *rng, non_null() const uint8_t *data, uint32_t length);

/**
 * @brief Check if @p ping_id is valid and not timed out.
 *
 * On success, copies the data into data of length,
 *
 * @return length of data copied on success, -1 on failure.
 */
int32_t ping_array_check(non_null() Ping_Array *array, non_null() const Mono_Time *mono_time, non_null() uint8_t *data, size_t length, uint64_t ping_id);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* C_TOXCORE_TOXCORE_PING_ARRAY_H */
