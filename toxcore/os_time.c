/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2022-2023 The TokTok team.
 */
#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 600
#endif /* _XOPEN_SOURCE */

#if !defined(OS_WIN32) && (defined(_WIN32) || defined(__WIN32__) || defined(WIN32))
#define OS_WIN32
#endif /* WIN32 */

#include "os_time.h"

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

#include <time.h>

#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
#include <assert.h>
#include "ccompat.h"
#endif /* FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION */

#include "tox_attributes.h"
#include "tox_time.h"
#include "tox_time_impl.h"

static uint64_t timespec_to_u64(struct timespec clock_mono)
{
    return UINT64_C(1000) * clock_mono.tv_sec + (clock_mono.tv_nsec / UINT64_C(1000000));
}

#ifdef OS_WIN32
non_null()
static uint64_t current_time_monotonic_default(void *user_data)
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
non_null()
static uint64_t current_time_monotonic_default(void *user_data)
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
non_null()
static uint64_t current_time_monotonic_default(void *user_data)
{
#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
    // This assert should always fail. If it does, the fuzzing harness didn't
    // override the mono time callback.
    assert(user_data == nullptr);
#endif /* FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION */
    struct timespec clock_mono;
    clock_gettime(CLOCK_MONOTONIC, &clock_mono);
    return timespec_to_u64(clock_mono);
}
#endif /* !__APPLE__ */
#endif /* !OS_WIN32 */

static const Tox_Time_Funcs os_time_funcs = {
    current_time_monotonic_default,
};

const Tox_Time os_time_obj = {&os_time_funcs};

const Tox_Time *os_time(void)
{
#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
    if ((true)) {
        return nullptr;
    }
#endif /* FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION */
    return &os_time_obj;
}
