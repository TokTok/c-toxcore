/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2020 The TokTok team.
 * Copyright © 2015 Tox project.
 */

#ifndef C_TOXCORE_TOXCORE_GROUP_ONION_ANNOUNCE_H
#define C_TOXCORE_TOXCORE_GROUP_ONION_ANNOUNCE_H

#include "attributes.h"
#include "crypto_core.h"
#include "group_announce.h"
#include "mem.h"
#include "onion_announce.h"

void gca_onion_init(non_null() GC_Announces_List *group_announce, non_null() Onion_Announce *onion_a);

int create_gca_announce_request(non_null() const Memory *mem, non_null() const Random *rng, non_null() uint8_t *packet, uint16_t max_packet_length, non_null() const uint8_t *dest_client_id,
                                non_null() const uint8_t *public_key, non_null() const uint8_t *secret_key, non_null() const uint8_t *ping_id, non_null() const uint8_t *client_id, non_null() const uint8_t *data_public_key,
                                uint64_t sendback_data, non_null() const uint8_t *gc_data, uint16_t gc_data_length);

#endif /* C_TOXCORE_TOXCORE_GROUP_ONION_ANNOUNCE_H */
