/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2022-2023 The TokTok team.
 */
#include "os_logger.h"

#include "ccompat.h"
#include "tox_logger_impl.h"

non_null()
static void os_logger_log(
        void *self, Tox_Log_Level level,
        const char *file, uint32_t line, const char *func,
        const char *message)
{
    // Do nothing with the log message by default.
    return;
}

static const Tox_Logger_Funcs os_logger_funcs = {
    os_logger_log,
};

static const Tox_Logger os_logger_obj = {&os_logger_funcs};

const Tox_Logger *os_logger(void)
{
    return &os_logger_obj;
}
