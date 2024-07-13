/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2023 The TokTok team.
 * Copyright © 2014 Tox project.
 */
#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 600
#endif /* _XOPEN_SOURCE */

#include "mono_time.h"

#include <pthread.h>
#include <time.h>

#include "ccompat.h"
#include "mem.h"
#include "os_time.h"
#include "tox_attributes.h"
#include "tox_time.h"
#include "util.h"

/** don't call into system billions of times for no reason */
struct Mono_Time {
    uint64_t cur_time;
    uint64_t base_time;

#ifndef ESP_PLATFORM
    /* protect `time` from concurrent access */
    pthread_rwlock_t *time_update_lock;
#endif /* ESP_PLATFORM */

    const Tox_Time *tm;
};

Mono_Time *mono_time_new(const Memory *mem, const Tox_Time *tm)
{
    Mono_Time *mono_time = (Mono_Time *)mem_alloc(mem, sizeof(Mono_Time));

    if (mono_time == nullptr) {
        return nullptr;
    }

#ifndef ESP_PLATFORM
    pthread_rwlock_t *rwlock = (pthread_rwlock_t *)mem_alloc(mem, sizeof(pthread_rwlock_t));

    if (rwlock == nullptr) {
        mem_delete(mem, mono_time);
        return nullptr;
    }

    if (pthread_rwlock_init(rwlock, nullptr) != 0) {
        mem_delete(mem, rwlock);
        mem_delete(mem, mono_time);
        return nullptr;
    }

    mono_time->time_update_lock = rwlock;
#endif /* ESP_PLATFORM */

    mono_time_set_current_time_callback(mono_time, tm);

    mono_time->cur_time = 0;
#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
    // Maximum reproducibility. Never return time = 0.
    mono_time->base_time = 1000000000;
#else
    // Never return time = 0 in case time() returns 0 (e.g. on microcontrollers
    // without battery-powered RTC or ones where NTP didn't initialise it yet).
    mono_time->base_time = max_u64(1, (uint64_t)time(nullptr)) * UINT64_C(1000) - current_time_monotonic(mono_time);
#endif /* FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION */

    mono_time_update(mono_time);

    return mono_time;
}

void mono_time_free(const Memory *mem, Mono_Time *mono_time)
{
    if (mono_time == nullptr) {
        return;
    }
#ifndef ESP_PLATFORM
    pthread_rwlock_destroy(mono_time->time_update_lock);
    mem_delete(mem, mono_time->time_update_lock);
#endif /* ESP_PLATFORM */
    mem_delete(mem, mono_time);
}

void mono_time_update(Mono_Time *mono_time)
{
    const uint64_t cur_time = tox_time_monotonic(mono_time->tm) + mono_time->base_time;

#ifndef ESP_PLATFORM
    pthread_rwlock_wrlock(mono_time->time_update_lock);
#endif /* ESP_PLATFORM */
    mono_time->cur_time = cur_time;
#ifndef ESP_PLATFORM
    pthread_rwlock_unlock(mono_time->time_update_lock);
#endif /* ESP_PLATFORM */
}

uint64_t mono_time_get_ms(const Mono_Time *mono_time)
{
#if !defined(ESP_PLATFORM) && !defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
    // Fuzzing is only single thread for now, no locking needed */
    pthread_rwlock_rdlock(mono_time->time_update_lock);
#endif /* !ESP_PLATFORM */
    const uint64_t cur_time = mono_time->cur_time;
#if !defined(ESP_PLATFORM) && !defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION)
    pthread_rwlock_unlock(mono_time->time_update_lock);
#endif /* !ESP_PLATFORM */
    return cur_time;
}

uint64_t mono_time_get(const Mono_Time *mono_time)
{
    return mono_time_get_ms(mono_time) / UINT64_C(1000);
}

bool mono_time_is_timeout(const Mono_Time *mono_time, uint64_t timestamp, uint64_t timeout)
{
    return timestamp + timeout <= mono_time_get(mono_time);
}

void mono_time_set_current_time_callback(Mono_Time *mono_time, const Tox_Time *tm)
{
    mono_time->tm = tm != nullptr ? tm : os_time();
}

/** @brief Return current monotonic time in milliseconds (ms).
 *
 * The starting point is unspecified and in particular is likely not comparable
 * to the return value of `mono_time_get_ms()`.
 */
uint64_t current_time_monotonic(const Mono_Time *mono_time)
{
    return tox_time_monotonic(mono_time->tm);
}
