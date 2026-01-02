/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2025 The TokTok team.
 * Copyright © 2013-2015 Tox project.
 */
#include "toxav.h"
#include "toxav_private.h"

#include <stdlib.h>

#include "../toxcore/ccompat.h"
#include "../toxcore/tox.h"
#include "../toxcore/tox_private.h"
#include "../toxcore/tox_struct.h"
#include "../toxcore/Messenger.h" // For PACKET_ID_MSI if needed, but we use numeric or define
#include "../toxcore/net_crypto.h" // For PACKET_ID_MSI

Tox *toxav_get_tox(const ToxAV *av)
{
    return av->tox;
}

static bool legacy_send_lossy(uint32_t friend_number, const uint8_t *data, size_t length, void *user_data)
{
    Tox *tox = (Tox *)user_data;
    Tox_Err_Friend_Custom_Packet error;
    tox_friend_send_lossy_packet(tox, friend_number, data, length, &error);
    return error == TOX_ERR_FRIEND_CUSTOM_PACKET_OK;
}

static bool legacy_send_lossless(uint32_t friend_number, const uint8_t *data, size_t length, void *user_data)
{
    Tox *tox = (Tox *)user_data;
    Tox_Err_Friend_Custom_Packet error;
    tox_friend_send_lossless_packet(tox, friend_number, data, length, &error);
    return error == TOX_ERR_FRIEND_CUSTOM_PACKET_OK;
}

static bool legacy_friend_exists(uint32_t friend_number, void *user_data)
{
    const Tox *tox = (const Tox *)user_data;
    return tox_friend_exists(tox, friend_number);
}

static bool legacy_friend_connected(uint32_t friend_number, void *user_data)
{
    const Tox *tox = (const Tox *)user_data;
    Tox_Err_Friend_Query error;
    return tox_friend_get_connection_status(tox, friend_number, &error) != TOX_CONNECTION_NONE;
}

static void legacy_handle_rtp_packet(Tox *tox, Tox_Friend_Number friend_number, const uint8_t *data, size_t length, void *user_data)
{
    ToxAV *av = (ToxAV *)tox_get_av_object(tox);
    if (av != nullptr) {
        toxav_receive_packet(av, friend_number, data, length);
    }
}

static void legacy_handle_msi_packet(Tox *tox, Tox_Friend_Number friend_number, const uint8_t *data, size_t length, void *user_data)
{
    ToxAV *av = (ToxAV *)tox_get_av_object(tox);
    if (av != nullptr) {
        toxav_receive_packet(av, friend_number, data, length);
    }
}

ToxAV *toxav_new(Tox *tox, Toxav_Err_New *error)
{
    if (tox == nullptr) {
        if (error) {
            *error = TOXAV_ERR_NEW_NULL;
        }
        return nullptr;
    }

    const ToxAV_IO io = {
        legacy_send_lossy,
        legacy_send_lossless,
        legacy_friend_exists,
        legacy_friend_connected,
    };

    ToxAV *av = toxav_new_custom(&io, tox, error);
    if (av == nullptr) {
        return nullptr;
    }

    av->tox = tox;
    // We access internal toxcore structs here, which is allowed for compat/legacy layer
    av->mem = tox->sys.mem;
    logger_kill(av->log);
    av->log = tox->m->log;

    // Register callbacks
    tox_callback_friend_lossy_packet_per_pktid(av->tox, legacy_handle_rtp_packet, RTP_TYPE_AUDIO);
    tox_callback_friend_lossy_packet_per_pktid(av->tox, legacy_handle_rtp_packet, RTP_TYPE_VIDEO);
    tox_callback_friend_lossy_packet_per_pktid(av->tox, legacy_handle_rtp_packet, BWC_PACKET_ID);
    tox_callback_friend_lossless_packet_per_pktid(av->tox, legacy_handle_msi_packet, PACKET_ID_MSI);

    tox_set_av_object(av->tox, av);
    return av;
}
