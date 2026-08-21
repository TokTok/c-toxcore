/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2022-2026 The TokTok team.
 */

#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 600
#endif /* _XOPEN_SOURCE */

#include "mono_clock.h"

#include "ccompat.h"

#ifndef ESP_PLATFORM
#include <pthread.h>
#endif /* ESP_PLATFORM */

#include "attributes.h"
#include "ccompat.h"
#include "os_clock.h"
#include "util.h"

struct Mono_Clock {
    Clock clock;

    const Clock *_Nonnull source_clock;

    uint64_t cur_monotonic_ms;
    uint64_t cur_real_ms;
    uint64_t base_time_ms;

#ifndef ESP_PLATFORM
    pthread_rwlock_t *_Nonnull lock;
#endif /* ESP_PLATFORM */
};

static uint64_t mono_clock_monotonic_ms(void *_Nullable self)
{
    Mono_Clock *mc = (Mono_Clock *)self;
#ifndef ESP_PLATFORM
    pthread_rwlock_rdlock(mc->lock);
#endif /* ESP_PLATFORM */
    const uint64_t res = mc->cur_monotonic_ms;
#ifndef ESP_PLATFORM
    pthread_rwlock_unlock(mc->lock);
#endif /* ESP_PLATFORM */
    return res;
}

static uint64_t mono_clock_real_ms(void *_Nullable self)
{
    Mono_Clock *mc = (Mono_Clock *)self;
#ifndef ESP_PLATFORM
    pthread_rwlock_rdlock(mc->lock);
#endif /* ESP_PLATFORM */
    const uint64_t res = mc->cur_real_ms;
#ifndef ESP_PLATFORM
    pthread_rwlock_unlock(mc->lock);
#endif /* ESP_PLATFORM */
    return res;
}

static void mono_clock_update(void *_Nullable self)
{
    Mono_Clock *mc = (Mono_Clock *)self;
    const uint64_t mono = clock_monotonic_ms(mc->source_clock);

#ifndef ESP_PLATFORM
    pthread_rwlock_wrlock(mc->lock);
#endif /* ESP_PLATFORM */
    mc->cur_monotonic_ms = mc->base_time_ms + mono;
    mc->cur_real_ms = clock_real_ms(mc->source_clock);
#ifndef ESP_PLATFORM
    pthread_rwlock_unlock(mc->lock);
#endif /* ESP_PLATFORM */
}

static const Clock_Funcs mono_clock_funcs = {
    mono_clock_monotonic_ms,
    mono_clock_real_ms,
    mono_clock_update,
};

Mono_Clock *mono_clock_new(const Memory *mem, const Clock *source_clock)
{
    Mono_Clock *mc = (Mono_Clock *)mem_alloc(mem, sizeof(Mono_Clock));

    if (mc == nullptr) {
        return nullptr;
    }

    if (source_clock == nullptr) {
        source_clock = os_clock();
    }

    mc->clock.funcs = &mono_clock_funcs;
    mc->clock.user_data = mc;
    mc->source_clock = source_clock;

#ifndef ESP_PLATFORM
    pthread_rwlock_t *lock = (pthread_rwlock_t *)mem_alloc(mem, sizeof(pthread_rwlock_t));

    if (lock == nullptr) {
        mem_delete(mem, mc);
        return nullptr;
    }

    if (pthread_rwlock_init(lock, nullptr) != 0) {
        mem_delete(mem, lock);
        mem_delete(mem, mc);
        return nullptr;
    }

    mc->lock = lock;
#endif /* ESP_PLATFORM */

#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
    // Maximum reproducibility. Never return time = 0.
    mc->base_time_ms = UINT64_C(1000000000);
#else
    // Match legacy behavior: initialize base_time_ms so that the first
    // mono_clock_monotonic_ms returns approximately current real time.
    const uint64_t real = clock_real_ms(mc->source_clock);
    const uint64_t mono = clock_monotonic_ms(mc->source_clock);
    mc->base_time_ms = max_u64(UINT64_C(1000), real) - mono;
#endif /* FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION */

    mono_clock_update(mc);

    return mc;
}

void mono_clock_free(const Memory *mem, Mono_Clock *mc)
{
    if (mc == nullptr) {
        return;
    }

#ifndef ESP_PLATFORM
    pthread_rwlock_destroy(mc->lock);
    mem_delete(mem, mc->lock);
#endif /* ESP_PLATFORM */
    mem_delete(mem, mc);
}

const Clock *mono_clock_get_clock(const Mono_Clock *mc)
{
    return &mc->clock;
}

Clock *mono_clock_get_clock_mutable(Mono_Clock *mc)
{
    return &mc->clock;
}
