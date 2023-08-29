/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2022-2023 The TokTok team.
 */

#ifndef C_TOXCORE_TOXCORE_TOX_LOGGER_H
#define C_TOXCORE_TOXCORE_TOX_LOGGER_H

#include "tox_memory.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Severity level of log messages.
 */
typedef enum Tox_Log_Level {

    /**
     * Very detailed traces including all network activity.
     */
    TOX_LOG_LEVEL_TRACE,

    /**
     * Debug messages such as which port we bind to.
     */
    TOX_LOG_LEVEL_DEBUG,

    /**
     * Informational log messages such as video call status changes.
     */
    TOX_LOG_LEVEL_INFO,

    /**
     * Warnings about events_alloc inconsistency or logic errors.
     */
    TOX_LOG_LEVEL_WARNING,

    /**
     * Severe unexpected errors caused by external or events_alloc inconsistency.
     */
    TOX_LOG_LEVEL_ERROR,

} Tox_Log_Level;


typedef struct Tox_Logger_Funcs Tox_Logger_Funcs;

typedef struct Tox_Logger Tox_Logger;

non_null(1, 3) nullable(2)
Tox_Logger *tox_logger_new(const Tox_Logger_Funcs *funcs, void *user_data, const Tox_Memory *mem);

nullable(1) void tox_logger_free(Tox_Logger *log);

non_null() void tox_logger_log(
        const Tox_Logger *log, Tox_Log_Level level,
        const char *file, uint32_t line, const char *func,
        const char *message);

#ifdef __cplusplus
}
#endif

#endif // C_TOXCORE_TOXCORE_TOX_LOGGER_H
