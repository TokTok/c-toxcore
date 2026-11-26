/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2026 The TokTok team.
 * Copyright © 2013-2015 Tox project.
 */

/**
 * The toxav.h functions that need a Tox instance: the A/V core bound to Tox.
 */
#include "toxav.h"

#include "av_core.h"
#include "bwcontroller.h"
#include "msi.h"
#include "rtp.h"

#include "../toxcore/Messenger.h"
#include "../toxcore/ccompat.h"
#include "../toxcore/net_crypto.h"
#include "../toxcore/tox.h"
#include "../toxcore/tox_private.h"
#include "../toxcore/tox_struct.h"  // IWYU pragma: keep

static_assert(MSI_PACKET_ID == PACKET_ID_MSI, "ToxAV and toxcore disagree on the MSI packet ID");
static_assert(RTP_MAX_PACKET_SIZE == TOX_MAX_CUSTOM_PACKET_SIZE, "ToxAV and toxcore disagree on the packet size");

#define SET_ERROR_PARAMETER(param, x) \
    do {                              \
        if (param != nullptr) {       \
            *param = x;               \
        }                             \
    } while (0)

static bool legacy_send_lossy(ToxAV *_Nonnull av, Tox_Friend_Number friend_number, const uint8_t *_Nonnull data, size_t length,
                              void *_Nonnull user_data)
{
    Tox *tox = (Tox *)user_data;
    Tox_Err_Friend_Custom_Packet error;
    tox_friend_send_lossy_packet(tox, friend_number, data, length, &error);
    return error == TOX_ERR_FRIEND_CUSTOM_PACKET_OK;
}

static bool legacy_send_lossless(ToxAV *_Nonnull av, Tox_Friend_Number friend_number, const uint8_t *_Nonnull data, size_t length,
                                 void *_Nonnull user_data)
{
    Tox *tox = (Tox *)user_data;
    Tox_Err_Friend_Custom_Packet error;
    tox_friend_send_lossless_packet(tox, friend_number, data, length, &error);
    return error == TOX_ERR_FRIEND_CUSTOM_PACKET_OK;
}

static bool legacy_friend_exists(Tox_Friend_Number friend_number, void *_Nonnull user_data)
{
    const Tox *tox = (const Tox *)user_data;
    return tox_friend_exists(tox, friend_number);
}

static bool legacy_friend_connected(Tox_Friend_Number friend_number, void *_Nonnull user_data)
{
    const Tox *tox = (const Tox *)user_data;
    Tox_Err_Friend_Query error;
    return tox_friend_get_connection_status(tox, friend_number, &error) != TOX_CONNECTION_NONE;
}

static void legacy_handle_packet(Tox *_Nonnull tox, Tox_Friend_Number friend_number, const uint8_t *_Nonnull data, size_t length,
                                 void *_Nullable user_data)
{
    ToxAV *av = (ToxAV *)tox_get_av_object(tox);
    if (av != nullptr) {
        av_core_receive_packet(av, friend_number, data, length);
    }
}

static void legacy_detach(Tox *_Nonnull tox)
{
    for (uint8_t i = PACKET_ID_RANGE_LOSSY_AV_START; i <= PACKET_ID_RANGE_LOSSY_AV_END; ++i) {
        tox_callback_friend_lossy_packet_per_pktid(tox, nullptr, i);
    }

    tox_callback_friend_lossy_packet_per_pktid(tox, nullptr, RTP_TYPE_AUDIO);
    tox_callback_friend_lossy_packet_per_pktid(tox, nullptr, RTP_TYPE_VIDEO);
    tox_callback_friend_lossy_packet_per_pktid(tox, nullptr, BWC_PACKET_ID);
    tox_callback_friend_lossless_packet_per_pktid(tox, nullptr, PACKET_ID_MSI);

    // set ToxAV object to NULL in toxcore, to signal ToxAV has been shutdown
    tox_set_av_object(tox, nullptr);
}

ToxAV *_Nullable toxav_new(Tox *_Nonnull tox, Toxav_Err_New *_Nullable error)
{
    if (tox == nullptr) {
        SET_ERROR_PARAMETER(error, TOXAV_ERR_NEW_NULL);
        return nullptr;
    }

    if (tox_get_av_object(tox) != nullptr) {
        SET_ERROR_PARAMETER(error, TOXAV_ERR_NEW_MULTIPLE);
        return nullptr;
    }

    const Av_Core_Network network = {
        legacy_send_lossy,
        legacy_send_lossless,
        legacy_friend_exists,
        legacy_friend_connected,
        tox,
    };
    // We access internal toxcore structs here.
    ToxAV *av = av_core_new(tox->sys.mem, tox->m->log, tox->sys.mono_time_callback, tox->sys.mono_time_user_data, &network);

    if (av == nullptr) {
        SET_ERROR_PARAMETER(error, TOXAV_ERR_NEW_MALLOC);
        return nullptr;
    }

    tox_callback_friend_lossy_packet_per_pktid(tox, legacy_handle_packet, RTP_TYPE_AUDIO);
    tox_callback_friend_lossy_packet_per_pktid(tox, legacy_handle_packet, RTP_TYPE_VIDEO);
    tox_callback_friend_lossy_packet_per_pktid(tox, legacy_handle_packet, BWC_PACKET_ID);
    tox_callback_friend_lossless_packet_per_pktid(tox, legacy_handle_packet, PACKET_ID_MSI);

    // save ToxAV object into toxcore
    tox_set_av_object(tox, av);

    SET_ERROR_PARAMETER(error, TOXAV_ERR_NEW_OK);
    return av;
}

void toxav_kill(ToxAV *_Nullable av)
{
    if (av == nullptr) {
        return;
    }

    legacy_detach(toxav_get_tox(av));
    av_core_kill(av);
}

Tox *_Nonnull toxav_get_tox(const ToxAV *_Nonnull av)
{
    return (Tox *)av_core_network_user_data(av);
}
