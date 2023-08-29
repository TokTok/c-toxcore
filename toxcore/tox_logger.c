/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2022-2023 The TokTok team.
 */
#include "tox_logger.h"

#include "ccompat.h"
#include "tox_logger_impl.h"

Tox_Logger *tox_logger_new(const Tox_Logger_Funcs *funcs, void *user_data, const Tox_Memory *mem)
{
    Tox_Logger *log = (Tox_Logger *)tox_memory_alloc(mem, sizeof(Tox_Logger));

    if (log == nullptr) {
        return nullptr;
    }

    log->funcs = funcs;
    log->user_data = user_data;

    log->mem = mem;

    return log;
}

void tox_logger_free(Tox_Logger *log)
{
    if (log == nullptr) {
        return;
    }
    tox_memory_dealloc(log->mem, log);
}

void tox_logger_log(
        const Tox_Logger *log, Tox_Log_Level level,
        const char *file, uint32_t line, const char *func,
        const char *message)
{
    log->funcs->log_callback(log->user_data, level, file, line, func, message);
}
