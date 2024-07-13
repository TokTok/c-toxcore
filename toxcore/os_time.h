/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2022-2023 The TokTok team.
 */

#ifndef C_TOXCORE_TOXCORE_OS_TIME_H
#define C_TOXCORE_TOXCORE_OS_TIME_H

#include "tox_time.h"

#ifdef __cplusplus
extern "C" {
#endif

extern const Tox_Time os_time_obj;

const Tox_Time *os_time(void);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* C_TOXCORE_TOXCORE_OS_TIME_H */
