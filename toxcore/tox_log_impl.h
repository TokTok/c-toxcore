/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2022-2023 The TokTok team.
 */

#ifndef C_TOXCORE_TOXCORE_TOX_LOGGER_IMPL_H
#define C_TOXCORE_TOXCORE_TOX_LOGGER_IMPL_H

#include "tox_log.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief This event is triggered when the toxcore library logs a message.
 *
 * This is mostly useful for debugging. This callback can be called from any
 * function, not just tox_iterate. This means the user data lifetime must at
 * least extend between registering and unregistering it or tox_kill.
 *
 * Other toxcore modules such as toxav may concurrently call this callback at
 * any time. Thus, user code must make sure it is equipped to handle concurrent
 * execution, e.g. by employing appropriate mutex locking.
 *
 * @param self The user data pointer passed to `tox_log_new`.
 * @param level The severity of the log message.
 * @param file The source file from which the message originated.
 * @param line The source line from which the message originated.
 * @param func The function from which the message originated.
 * @param message The log message.
 */
typedef void tox_log_log_cb(
        void *self, Tox_Log_Level level,
        const char *file, uint32_t line, const char *func,
        const char *message);


struct Tox_Log_Funcs {
    tox_log_log_cb *log_callback;
};

struct Tox_Log {
    const Tox_Log_Funcs *funcs;
    void *user_data;

    const Tox_Memory *mem;
};

#ifdef __cplusplus
}
#endif

#endif // C_TOXCORE_TOXCORE_TOX_LOGGER_IMPL_H
