/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2026 The TokTok team.
 * Copyright © 2014 Tox project.
 */
#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 600
#endif /* _XOPEN_SOURCE */

#if !defined(OS_WIN32) && (defined(_WIN32) || defined(__WIN32__) || defined(WIN32))
#define OS_WIN32
#endif /* WIN32 */

#include "mono_time.h"

#include <time.h>

#ifdef OS_WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#endif /* OS_WIN32 */

#ifdef __APPLE__
#include <mach/clock.h>
#include <mach/mach.h>
#endif /* __APPLE__ */

#ifndef OS_WIN32
#include <sys/time.h>
#endif /* OS_WIN32 */

#include "ccompat.h"
#include "mem.h"
#include "mono_clock.h"
#include "os_clock.h"
#include "util.h"

struct Mono_Time {
    Mono_Clock *mc;
    Clock custom_source;
    mono_time_current_time_cb *cb;
    void *cb_user_data;
};

static uint64_t timespec_to_u64(struct timespec ts)
{
    return UINT64_C(1000) * ts.tv_sec + (ts.tv_nsec / UINT64_C(1000000));
}

#ifdef OS_WIN32
static uint64_t current_time_monotonic_default(void *_Nonnull user_data)
{
    LARGE_INTEGER freq;
    LARGE_INTEGER count;

    if (!QueryPerformanceFrequency(&freq)) {
        return 0;
    }

    if (!QueryPerformanceCounter(&count)) {
        return 0;
    }

    struct timespec sp = {0};
    sp.tv_sec = count.QuadPart / freq.QuadPart;

    if (freq.QuadPart < 1000000000) {
        sp.tv_nsec = (count.QuadPart % freq.QuadPart) * 1000000000 / freq.QuadPart;
    } else {
        sp.tv_nsec = (long)((count.QuadPart % freq.QuadPart) * (1000000000.0 / freq.QuadPart));
    }

    return timespec_to_u64(sp);
}
#else
#ifdef __APPLE__
static uint64_t current_time_monotonic_default(void *_Nonnull user_data)
{
    struct timespec clock_mono;
    clock_serv_t muhclock;
    mach_timespec_t machtime;

    host_get_clock_service(mach_host_self(), SYSTEM_CLOCK, &muhclock);
    clock_get_time(muhclock, &machtime);
    mach_port_deallocate(mach_task_self(), muhclock);

    clock_mono.tv_sec = machtime.tv_sec;
    clock_mono.tv_nsec = machtime.tv_nsec;
    return timespec_to_u64(clock_mono);
}
#else // !__APPLE__
static uint64_t current_time_monotonic_default(void *_Nonnull user_data)
{
    struct timespec clock_mono;
    clock_gettime(CLOCK_MONOTONIC, &clock_mono);
    return timespec_to_u64(clock_mono);
}
#endif /* !__APPLE__ */
#endif /* !OS_WIN32 */

static uint64_t legacy_monotonic_ms(void *self)
{
    Mono_Time *mt = (Mono_Time *)self;
    return mt->cb(mt->cb_user_data);
}

static uint64_t legacy_real_ms(void *self)
{
    return clock_real_ms(os_clock());
}

static const Clock_Funcs legacy_funcs = {
    legacy_monotonic_ms,
    legacy_real_ms,
    nullptr
};

Mono_Clock *mono_time_get_mono_clock(Mono_Time *mt)
{
    return mt->mc;
}

Mono_Time *mono_time_new(const Memory *mem, mono_time_current_time_cb *current_time_callback, void *user_data)
{
    Mono_Time *mt = (Mono_Time *)mem_alloc(mem, sizeof(Mono_Time));

    if (mt == nullptr) {
        return nullptr;
    }

    mt->custom_source.funcs = &legacy_funcs;
    mt->custom_source.user_data = mt;

    mono_time_set_current_time_callback(mt, current_time_callback, user_data);

    mt->mc = mono_clock_new(mem, &mt->custom_source);

    if (mt->mc == nullptr) {
        mem_delete(mem, mt);
        return nullptr;
    }

    return mt;
}

void mono_time_free(const Memory *mem, Mono_Time *mt)
{
    if (mt == nullptr) {
        return;
    }

    mono_clock_free(mem, mt->mc);
    mem_delete(mem, mt);
}

void mono_time_update(Mono_Time *mt)
{
    clock_update(mono_clock_get_clock_mutable(mt->mc));
}

uint64_t mono_time_get_ms(const Mono_Time *mt)
{
    return clock_monotonic_ms(mono_clock_get_clock(mt->mc));
}

uint64_t mono_time_get(const Mono_Time *mt)
{
    return mono_time_get_ms(mt) / UINT64_C(1000);
}

bool mono_time_is_timeout(const Mono_Time *mt, uint64_t timestamp, uint64_t timeout)
{
    return timestamp + timeout <= mono_time_get(mt);
}

void mono_time_set_current_time_callback(Mono_Time *mt,
        mono_time_current_time_cb *current_time_callback, void *user_data)
{
    if (current_time_callback == nullptr) {
        mt->cb = current_time_monotonic_default;
        mt->cb_user_data = mt;
    } else {
        mt->cb = current_time_callback;
        mt->cb_user_data = user_data;
    }
}

uint64_t current_time_monotonic(const Mono_Time *mt)
{
    return mt->cb(mt->cb_user_data);
}
