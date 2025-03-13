/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2025 The TokTok team.
 * Copyright © 2013-2015 Tox project.
 */

/**
 * Text logging abstraction.
 */
#include "logger.h"

#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ccompat.h"
#include "mem.h"

struct Logger {
    const Memory *mem;

    logger_cb *callback;
    void *context;
    void *userdata;
};

/*
 * Public Functions
 */

Logger *logger_new(const Memory *mem)
{
    Logger *log = (Logger *)mem_alloc(mem, sizeof(Logger));

    if (log == nullptr) {
        return nullptr;
    }

    log->mem = mem;

    return log;
}

void logger_kill(Logger *log)
{
    if (log == nullptr) {
        return;
    }

    mem_delete(log->mem, log);
}

void logger_callback_log(Logger *log, logger_cb *function, void *context, void *userdata)
{
    assert(log != nullptr);
    log->callback = function;
    log->context  = context;
    log->userdata = userdata;
}

void logger_write(const Logger *log, Logger_Level level, const char *file, uint32_t line, const char *func,
                  const char *format, ...)
{
    if (log == nullptr) {
        return;
    }

    if (log->callback == nullptr) {
        return;
    }

    // Only pass the file name, not the entire file path, for privacy reasons.
    // The full path may contain PII of the person compiling toxcore (their
    // username and directory layout).
    const char *filename = strrchr(file, '/');
    file = filename != nullptr ? filename + 1 : file;
#if defined(_WIN32) || defined(__CYGWIN__)
    // On Windows, the path separator *may* be a backslash, so we look for that
    // one too.
    const char *windows_filename = strrchr(file, '\\');
    file = windows_filename != nullptr ? windows_filename + 1 : file;
#endif /* WIN32 */

    // Format message
    // TODO(goldroom): changed from 1024 to 4096
    char msg[4096];
    va_list args;
    va_start(args, format);
    vsnprintf(msg, sizeof(msg), format, args);
    va_end(args);

    log->callback(log->context, level, file, line, func, msg, log->userdata);
}

void logger_abort(void)
{
    abort();
}
