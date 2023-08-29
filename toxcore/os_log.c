/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2022-2023 The TokTok team.
 */
#include "os_log.h"

#include "ccompat.h"
#include "tox_log_impl.h"

non_null()
static void os_log_log(
        void *self, Tox_Log_Level level,
        const char *file, uint32_t line, const char *func,
        const char *message)
{
    // Do nothing with the log message by default.
    return;
}

static const Tox_Log_Funcs os_log_funcs = {
    os_log_log,
};

const Tox_Log os_log_obj = {&os_log_funcs};

const Tox_Log *os_log(void)
{
    return &os_log_obj;
}
