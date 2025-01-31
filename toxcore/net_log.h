/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2025 The TokTok team.
 * Copyright © 2013 Tox project.
 */

#ifndef C_TOXCORE_TOXCORE_NET_LOG_H
#define C_TOXCORE_TOXCORE_NET_LOG_H

#include <stdbool.h>    // bool
#include <stdint.h>     // uint*_t

#include "attributes.h"
#include "logger.h"
#include "network.h"

#ifdef __cplusplus
extern "C" {
#endif

non_null()
void net_log_data(const Logger *log, const char *message, const uint8_t *buffer,
                  uint16_t buflen, const IP_Port *ip_port, long res);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* C_TOXCORE_TOXCORE_NET_LOG_H */
