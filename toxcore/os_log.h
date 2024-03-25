/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2022-2023 The TokTok team.
 */

#ifndef C_TOXCORE_TOXCORE_OS_LOG_H
#define C_TOXCORE_TOXCORE_OS_LOG_H

#include "tox_log.h"

#ifdef __cplusplus
extern "C" {
#endif

extern const Tox_Log os_log_obj;

const Tox_Log *os_log(void);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* C_TOXCORE_TOXCORE_OS_LOG_H */
