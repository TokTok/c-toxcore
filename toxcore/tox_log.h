/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2022-2023 The TokTok team.
 */

#ifndef C_TOXCORE_TOXCORE_TOX_LOG_H
#define C_TOXCORE_TOXCORE_TOX_LOG_H

#include "tox_attributes.h"
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

const char *tox_log_level_to_string(Tox_Log_Level value);


typedef struct Tox_Log_Funcs Tox_Log_Funcs;

typedef struct Tox_Log Tox_Log;

non_null(1, 3) nullable(2)
Tox_Log *tox_log_new(const Tox_Log_Funcs *funcs, void *user_data, const Tox_Memory *mem);

nullable(1)
void tox_log_free(Tox_Log *log);

non_null()
void tox_log_log(
    const Tox_Log *log, Tox_Log_Level level,
    const char *file, uint32_t line, const char *func,
    const char *message);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* C_TOXCORE_TOXCORE_TOX_LOG_H */
