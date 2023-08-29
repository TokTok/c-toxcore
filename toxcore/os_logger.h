/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2022-2023 The TokTok team.
 */

#ifndef C_TOXCORE_TOXCORE_OS_LOGGER_H
#define C_TOXCORE_TOXCORE_OS_LOGGER_H

#include "tox_logger.h"

#ifdef __cplusplus
extern "C" {
#endif

const Tox_Logger *os_logger(void);

#ifdef __cplusplus
}
#endif

#endif // C_TOXCORE_TOXCORE_OS_LOGGER_H
