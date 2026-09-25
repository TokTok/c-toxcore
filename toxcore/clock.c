/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2022-2026 The TokTok team.
 */

#include "clock.h"

#include "ccompat.h"

uint64_t clock_monotonic_ms(const Clock *clock)
{
    return clock->funcs->monotonic_ms(clock->user_data);
}

uint64_t clock_monotonic_s(const Clock *clock)
{
    return clock_monotonic_ms(clock) / UINT64_C(1000);
}

uint64_t clock_real_ms(const Clock *clock)
{
    return clock->funcs->real_ms(clock->user_data);
}

uint64_t clock_real_s(const Clock *clock)
{
    return clock_real_ms(clock) / UINT64_C(1000);
}

bool clock_is_timeout(const Clock *clock, uint64_t timestamp, uint64_t timeout)
{
    return timestamp + timeout <= clock_monotonic_s(clock);
}

void clock_update(Clock *clock)
{
    if (clock->funcs->update != nullptr) {
        clock->funcs->update(clock->user_data);
    }
}
