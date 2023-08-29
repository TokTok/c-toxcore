/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2022-2023 The TokTok team.
 */
#include "tox_log.h"

#include "ccompat.h"
#include "tox_log_impl.h"
#include "tox_memory.h"

Tox_Log *tox_log_new(const Tox_Log_Funcs *funcs, void *user_data, const Tox_Memory *mem)
{
    Tox_Log *log = (Tox_Log *)tox_memory_alloc(mem, sizeof(Tox_Log));

    if (log == nullptr) {
        return nullptr;
    }

    log->funcs = funcs;
    log->user_data = user_data;

    log->mem = mem;

    return log;
}

void tox_log_free(Tox_Log *log)
{
    if (log == nullptr || log->mem == nullptr) {
        return;
    }
    tox_memory_dealloc(log->mem, log);
}

void tox_log_log(
        const Tox_Log *log, Tox_Log_Level level,
        const char *file, uint32_t line, const char *func,
        const char *message)
{
    log->funcs->log_callback(log->user_data, level, file, line, func, message);
}
