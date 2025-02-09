/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2022-2025 The TokTok team.
 */

#ifndef C_TOXCORE_TOXCORE_TOX_LOG_H
#define C_TOXCORE_TOXCORE_TOX_LOG_H

#include <stdint.h>     // uint32_t

#include "tox_attributes.h"
#include "tox_log_level.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifndef TOX_MEMORY_DEFINED
#define TOX_MEMORY_DEFINED
typedef struct Tox_Memory Tox_Memory;
#endif /* TOX_MEMORY_DEFINED */

typedef struct Tox_Log_Funcs Tox_Log_Funcs;

typedef struct Tox_Log Tox_Log;

tox_non_null(1, 3) tox_nullable(2)
Tox_Log *tox_log_new(const Tox_Log_Funcs *funcs, void *user_data, const Tox_Memory *mem);

tox_nullable(1)
void tox_log_free(Tox_Log *log);

tox_non_null()
void tox_log_log(
    const Tox_Log *log, Tox_Log_Level level,
    const char *file, uint32_t line, const char *func,
    const char *message);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* C_TOXCORE_TOXCORE_TOX_LOG_H */
