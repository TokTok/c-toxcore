/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2022-2023 The TokTok team.
 */

#ifndef C_TOXCORE_TOXCORE_OS_NETWORK_H
#define C_TOXCORE_TOXCORE_OS_NETWORK_H

#include "tox_network.h"

#ifdef __cplusplus
extern "C" {
#endif

extern const Tox_Network os_network_obj;

const Tox_Network *os_network(void);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* C_TOXCORE_TOXCORE_OS_NETWORK_H */
