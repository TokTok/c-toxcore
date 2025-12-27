/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2025 The TokTok team.
 * Copyright © 2013-2015 Tox project.
 */
#ifndef C_TOXCORE_TOXAV_BWCONTROLLER_H
#define C_TOXCORE_TOXAV_BWCONTROLLER_H

#include <stdint.h>
#include <stddef.h>

#include "../toxcore/logger.h"
#include "../toxcore/mono_time.h"

#ifdef __cplusplus
extern "C" {
#endif

#define BWC_PACKET_ID 196

typedef struct BWController BWController;

typedef void bwc_loss_report_cb(BWController *bwc, uint32_t friend_number, float loss, void *user_data);

typedef int bwc_send_packet_cb(void *user_data, const uint8_t *data, uint16_t length);

BWController *bwc_new(const Logger *log, uint32_t friendnumber,
                      bwc_loss_report_cb *mcb, void *mcb_user_data,
                      bwc_send_packet_cb *send_packet, void *send_packet_user_data,
                      Mono_Time *bwc_mono_time);

void bwc_kill(BWController *bwc);

void bwc_add_lost(BWController *bwc, uint32_t bytes_lost);
void bwc_add_recv(BWController *bwc, uint32_t recv_bytes);

void bwc_handle_packet(BWController *bwc, const uint8_t *data, size_t length);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* C_TOXCORE_TOXAV_BWCONTROLLER_H */
