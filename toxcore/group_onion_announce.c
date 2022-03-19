/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2020 The TokTok team.
 * Copyright © 2015 Tox project.
 */

#include "group_onion_announce.h"

#include "ccompat.h"

static pack_extra_data_cb pack_group_announces;
non_null()
static int pack_group_announces(void *object, const Logger *logger, const Mono_Time *mono_time,
                                uint8_t num_nodes, uint8_t *plain, uint16_t plain_size,
                                uint8_t *response, uint16_t response_size, uint16_t offset)
{
    GC_Announces_List *gc_announces_list = (GC_Announces_List *)object;
    GC_Public_Announce public_announce;

    if (gca_unpack_public_announce(logger, plain, plain_size,
                                   &public_announce) == -1) {
        LOGGER_WARNING(logger, "Failed to unpck public group announce");
        return -1;
    }

    const GC_Peer_Announce *new_announce = gca_add_announce(mono_time, gc_announces_list, &public_announce);

    if (new_announce == nullptr) {
        LOGGER_ERROR(logger, "Failed to add group announce");
        return -1;
    }

    GC_Announce gc_announces[GCA_MAX_SENT_ANNOUNCES];
    const int num_ann = (uint8_t)gca_get_announces(gc_announces_list,
                        gc_announces,
                        GCA_MAX_SENT_ANNOUNCES,
                        public_announce.chat_public_key,
                        new_announce->base_announce.peer_public_key);

    if (num_ann < 0) {
        LOGGER_ERROR(logger, "failed to get group announce");
        return -1;
    }

    size_t announces_length = 0;

    if (gca_pack_announces_list(logger, response + offset, response_size - offset, gc_announces, num_ann,
                                &announces_length) != num_ann) {
        LOGGER_WARNING(logger, "Failed to pack group announces list");
        return -1;
    }

    return announces_length;
}

void gca_onion_init(GC_Announces_List *group_announce, Onion_Announce *onion_a)
{
    onion_announce_extra_data_callback(onion_a, GCA_MAX_SENT_ANNOUNCES * sizeof(GC_Announce), pack_group_announces, group_announce);
}
