/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2026 The TokTok team.
 * Copyright © 2013-2015 Tox project.
 */

/**
 * The toxav.h API: a Tox_Av bound to a Tox instance.
 */
#include "toxav.h"

#include <pthread.h>

#include "tox_av.h"
#include "tox_av_private.h"
#include "toxav_struct.h"

#include "../toxcore/Messenger.h"  // For the logger
#include "../toxcore/ccompat.h"
#include "../toxcore/logger.h"
#include "../toxcore/mem.h"
#include "../toxcore/net_crypto.h" // For PACKET_ID_MSI
#include "../toxcore/tox.h"
#include "../toxcore/tox_private.h"
#include "../toxcore/tox_struct.h" // IWYU pragma: keep

#define SET_ERROR_PARAMETER(param, x) \
    do {                              \
        if (param != nullptr) {       \
            *param = x;               \
        }                             \
    } while (0)

static_assert(MSI_PACKET_ID == PACKET_ID_MSI, "ToxAV and toxcore disagree on the MSI packet ID");
static_assert(RTP_MAX_PACKET_SIZE == TOX_MAX_CUSTOM_PACKET_SIZE, "ToxAV and toxcore disagree on the packet size");

static_assert((uint32_t)TOXAV_FRIEND_CALL_STATE_NONE == (uint32_t)TOX_AV_FRIEND_CALL_STATE_NONE, "call state");
static_assert((uint32_t)TOXAV_FRIEND_CALL_STATE_ERROR == (uint32_t)TOX_AV_FRIEND_CALL_STATE_ERROR, "call state");
static_assert((uint32_t)TOXAV_FRIEND_CALL_STATE_FINISHED == (uint32_t)TOX_AV_FRIEND_CALL_STATE_FINISHED, "call state");
static_assert((uint32_t)TOXAV_FRIEND_CALL_STATE_SENDING_A == (uint32_t)TOX_AV_FRIEND_CALL_STATE_SENDING_A, "call state");
static_assert((uint32_t)TOXAV_FRIEND_CALL_STATE_SENDING_V == (uint32_t)TOX_AV_FRIEND_CALL_STATE_SENDING_V, "call state");
static_assert((uint32_t)TOXAV_FRIEND_CALL_STATE_ACCEPTING_A == (uint32_t)TOX_AV_FRIEND_CALL_STATE_ACCEPTING_A, "call state");
static_assert((uint32_t)TOXAV_FRIEND_CALL_STATE_ACCEPTING_V == (uint32_t)TOX_AV_FRIEND_CALL_STATE_ACCEPTING_V, "call state");

struct ToxAV {
    const Memory *_Nonnull mem;
    Tox *_Nonnull tox;
    Tox_Av *_Nonnull av;

    pthread_mutex_t mutex[1];
    /** @guarded_by mutex */
    toxav_call_cb *_Nullable call_callback;
    /** @guarded_by mutex */
    void *_Nullable call_user_data;
    /** @guarded_by mutex */
    toxav_call_state_cb *_Nullable call_state_callback;
    /** @guarded_by mutex */
    void *_Nullable call_state_user_data;
    /** @guarded_by mutex */
    toxav_audio_bit_rate_cb *_Nullable audio_bit_rate_callback;
    /** @guarded_by mutex */
    void *_Nullable audio_bit_rate_user_data;
    /** @guarded_by mutex */
    toxav_video_bit_rate_cb *_Nullable video_bit_rate_callback;
    /** @guarded_by mutex */
    void *_Nullable video_bit_rate_user_data;
    /** @guarded_by mutex */
    toxav_audio_receive_frame_cb *_Nullable audio_receive_frame_callback;
    /** @guarded_by mutex */
    void *_Nullable audio_receive_frame_user_data;
    /** @guarded_by mutex */
    toxav_video_receive_frame_cb *_Nullable video_receive_frame_callback;
    /** @guarded_by mutex */
    void *_Nullable video_receive_frame_user_data;
};

static bool legacy_send_lossy(Tox_Av *_Nonnull av, Tox_Av_Friend_Number friend_number, const uint8_t *_Nonnull data, size_t length,
                              void *_Nonnull user_data)
{
    Tox *tox = (Tox *)user_data;
    Tox_Err_Friend_Custom_Packet error;
    tox_friend_send_lossy_packet(tox, friend_number, data, length, &error);
    return error == TOX_ERR_FRIEND_CUSTOM_PACKET_OK;
}

static bool legacy_send_lossless(Tox_Av *_Nonnull av, Tox_Av_Friend_Number friend_number, const uint8_t *_Nonnull data, size_t length,
                                 void *_Nonnull user_data)
{
    Tox *tox = (Tox *)user_data;
    Tox_Err_Friend_Custom_Packet error;
    tox_friend_send_lossless_packet(tox, friend_number, data, length, &error);
    return error == TOX_ERR_FRIEND_CUSTOM_PACKET_OK;
}

static bool legacy_friend_connected(Tox_Av_Friend_Number friend_number, void *_Nullable user_data)
{
    const Tox *tox = (const Tox *)user_data;
    Tox_Err_Friend_Query error;
    return tox_friend_get_connection_status(tox, friend_number, &error) != TOX_CONNECTION_NONE;
}

static void legacy_log(void *_Nullable context, Logger_Level level, const char *_Nonnull file, uint32_t line, const char *_Nonnull func,
                       const char *_Nonnull message, void *_Nullable userdata)
{
    const Logger *log = (const Logger *)userdata;
    logger_write(log, level, file, line, func, "%s", message);
}

static void legacy_handle_packet(Tox *_Nonnull tox, Tox_Friend_Number friend_number, const uint8_t *_Nonnull data, size_t length,
                                 void *_Nullable user_data)
{
    ToxAV *av = (ToxAV *)tox_get_av_object(tox);
    if (av != nullptr) {
        tox_av_receive_packet(av->av, friend_number, data, length);
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

    // set ToxAV object to NULL in toxcore
    tox_set_av_object(tox, nullptr);
}

ToxAV *_Nullable toxav_new(Tox *_Nullable tox, Toxav_Err_New *_Nullable error)
{
    if (tox == nullptr) {
        SET_ERROR_PARAMETER(error, TOXAV_ERR_NEW_NULL);
        return nullptr;
    }

    if (tox_get_av_object(tox) != nullptr) {
        SET_ERROR_PARAMETER(error, TOXAV_ERR_NEW_MULTIPLE);
        return nullptr;
    }

    const Tox_System *sys = tox_get_system(tox);
    ToxAV *av = (ToxAV *)mem_alloc(sys->mem, sizeof(ToxAV));

    if (av == nullptr) {
        SET_ERROR_PARAMETER(error, TOXAV_ERR_NEW_MALLOC);
        return nullptr;
    }

    if (pthread_mutex_init(av->mutex, nullptr) != 0) {
        mem_delete(sys->mem, av);
        SET_ERROR_PARAMETER(error, TOXAV_ERR_NEW_MALLOC);
        return nullptr;
    }

    Tox_Av *tox_av = tox_av_new_testing(sys->mem, sys->mono_time_callback, sys->mono_time_user_data, nullptr);

    if (tox_av == nullptr) {
        pthread_mutex_destroy(av->mutex);
        mem_delete(sys->mem, av);
        SET_ERROR_PARAMETER(error, TOXAV_ERR_NEW_MALLOC);
        return nullptr;
    }

    av->mem = sys->mem;
    av->tox = tox;
    av->av = tox_av;

    tox_av->friend_connected = legacy_friend_connected;
    tox_av->friend_connected_user_data = tox;
    // We access internal toxcore structs here, which is allowed for compat/legacy layer
    logger_callback_log(tox_av->log, legacy_log, nullptr, tox->m->log);

    tox_av_callback_send_lossy_packet(tox_av, legacy_send_lossy, tox);
    tox_av_callback_send_lossless_packet(tox_av, legacy_send_lossless, tox);

    // Register callbacks
    tox_callback_friend_lossy_packet_per_pktid(tox, legacy_handle_packet, RTP_TYPE_AUDIO);
    tox_callback_friend_lossy_packet_per_pktid(tox, legacy_handle_packet, RTP_TYPE_VIDEO);
    tox_callback_friend_lossy_packet_per_pktid(tox, legacy_handle_packet, BWC_PACKET_ID);
    tox_callback_friend_lossless_packet_per_pktid(tox, legacy_handle_packet, PACKET_ID_MSI);

    tox_set_av_object(tox, av);

    SET_ERROR_PARAMETER(error, TOXAV_ERR_NEW_OK);
    return av;
}

void toxav_kill(ToxAV *_Nullable av)
{
    if (av == nullptr) {
        return;
    }

    legacy_detach(av->tox);
    tox_av_kill(av->av);
    pthread_mutex_destroy(av->mutex);
    mem_delete(av->mem, av);
}

Tox *_Nonnull toxav_get_tox(const ToxAV *_Nonnull av)
{
    return av->tox;
}

uint32_t toxav_iteration_interval(const ToxAV *_Nonnull av)
{
    return tox_av_iteration_interval(av->av);
}

void toxav_iterate(ToxAV *_Nonnull av)
{
    tox_av_iterate(av->av);
}

uint32_t toxav_audio_iteration_interval(const ToxAV *_Nonnull av)
{
    return tox_av_audio_iteration_interval(av->av);
}

void toxav_audio_iterate(ToxAV *_Nonnull av)
{
    tox_av_audio_iterate(av->av);
}

uint32_t toxav_video_iteration_interval(const ToxAV *_Nonnull av)
{
    return tox_av_video_iteration_interval(av->av);
}

void toxav_video_iterate(ToxAV *_Nonnull av)
{
    tox_av_video_iterate(av->av);
}

static Toxav_Err_Call legacy_err_call(Tox_Err_Av_Call error)
{
    switch (error) {
        case TOX_ERR_AV_CALL_OK:
            return TOXAV_ERR_CALL_OK;

        case TOX_ERR_AV_CALL_MALLOC:
            return TOXAV_ERR_CALL_MALLOC;

        case TOX_ERR_AV_CALL_SYNC:
            return TOXAV_ERR_CALL_SYNC;

        case TOX_ERR_AV_CALL_FRIEND_NOT_CONNECTED:
            return TOXAV_ERR_CALL_FRIEND_NOT_CONNECTED;

        case TOX_ERR_AV_CALL_FRIEND_ALREADY_IN_CALL:
            return TOXAV_ERR_CALL_FRIEND_ALREADY_IN_CALL;

        case TOX_ERR_AV_CALL_INVALID_BIT_RATE:
            return TOXAV_ERR_CALL_INVALID_BIT_RATE;
    }

    return TOXAV_ERR_CALL_MALLOC;
}

bool toxav_call(ToxAV *_Nonnull av, Tox_Friend_Number friend_number, uint32_t audio_bit_rate, uint32_t video_bit_rate,
                Toxav_Err_Call *_Nullable error)
{
    Tox_Err_Av_Call av_error;
    const bool ok = tox_av_call(av->av, friend_number, audio_bit_rate, video_bit_rate, &av_error);

    // Tox doesn't connect friends that don't exist.
    if (av_error == TOX_ERR_AV_CALL_FRIEND_NOT_CONNECTED && !tox_friend_exists(av->tox, friend_number)) {
        SET_ERROR_PARAMETER(error, TOXAV_ERR_CALL_FRIEND_NOT_FOUND);
        return false;
    }

    SET_ERROR_PARAMETER(error, legacy_err_call(av_error));
    return ok;
}

static void legacy_call(Tox_Av *_Nonnull av, Tox_Av_Friend_Number friend_number, bool audio_enabled, bool video_enabled,
                        void *_Nonnull user_data)
{
    ToxAV *toxav = (ToxAV *)user_data;
    pthread_mutex_lock(toxav->mutex);
    toxav_call_cb *callback = toxav->call_callback;
    void *callback_user_data = toxav->call_user_data;
    pthread_mutex_unlock(toxav->mutex);

    if (callback != nullptr) {
        callback(toxav, friend_number, audio_enabled, video_enabled, callback_user_data);
    }
}

void toxav_callback_call(ToxAV *_Nonnull av, toxav_call_cb *_Nullable callback, void *_Nullable user_data)
{
    pthread_mutex_lock(av->mutex);
    av->call_callback = callback;
    av->call_user_data = user_data;
    pthread_mutex_unlock(av->mutex);
    tox_av_callback_call(av->av, callback != nullptr ? legacy_call : nullptr, av);
}

static Toxav_Err_Answer legacy_err_answer(Tox_Err_Av_Answer error)
{
    switch (error) {
        case TOX_ERR_AV_ANSWER_OK:
            return TOXAV_ERR_ANSWER_OK;

        case TOX_ERR_AV_ANSWER_SYNC:
            return TOXAV_ERR_ANSWER_SYNC;

        case TOX_ERR_AV_ANSWER_CODEC_INITIALIZATION:
            return TOXAV_ERR_ANSWER_CODEC_INITIALIZATION;

        case TOX_ERR_AV_ANSWER_FRIEND_NOT_CALLING:
            return TOXAV_ERR_ANSWER_FRIEND_NOT_CALLING;

        case TOX_ERR_AV_ANSWER_INVALID_BIT_RATE:
            return TOXAV_ERR_ANSWER_INVALID_BIT_RATE;
    }

    return TOXAV_ERR_ANSWER_SYNC;
}

bool toxav_answer(ToxAV *_Nonnull av, Tox_Friend_Number friend_number, uint32_t audio_bit_rate, uint32_t video_bit_rate,
                  Toxav_Err_Answer *_Nullable error)
{
    if (!tox_friend_exists(av->tox, friend_number)) {
        SET_ERROR_PARAMETER(error, TOXAV_ERR_ANSWER_FRIEND_NOT_FOUND);
        return false;
    }

    Tox_Err_Av_Answer av_error;
    const bool ok = tox_av_answer(av->av, friend_number, audio_bit_rate, video_bit_rate, &av_error);
    SET_ERROR_PARAMETER(error, legacy_err_answer(av_error));
    return ok;
}

static void legacy_call_state(Tox_Av *_Nonnull av, Tox_Av_Friend_Number friend_number, uint32_t state, void *_Nonnull user_data)
{
    ToxAV *toxav = (ToxAV *)user_data;
    pthread_mutex_lock(toxav->mutex);
    toxav_call_state_cb *callback = toxav->call_state_callback;
    void *callback_user_data = toxav->call_state_user_data;
    pthread_mutex_unlock(toxav->mutex);

    if (callback != nullptr) {
        callback(toxav, friend_number, state, callback_user_data);
    }
}

void toxav_callback_call_state(ToxAV *_Nonnull av, toxav_call_state_cb *_Nullable callback, void *_Nullable user_data)
{
    pthread_mutex_lock(av->mutex);
    av->call_state_callback = callback;
    av->call_state_user_data = user_data;
    pthread_mutex_unlock(av->mutex);
    tox_av_callback_call_state(av->av, callback != nullptr ? legacy_call_state : nullptr, av);
}

static bool legacy_call_control(Toxav_Call_Control control, Tox_Av_Call_Control *_Nonnull out)
{
    switch (control) {
        case TOXAV_CALL_CONTROL_RESUME: {
            *out = TOX_AV_CALL_CONTROL_RESUME;
            return true;
        }

        case TOXAV_CALL_CONTROL_PAUSE: {
            *out = TOX_AV_CALL_CONTROL_PAUSE;
            return true;
        }

        case TOXAV_CALL_CONTROL_CANCEL: {
            *out = TOX_AV_CALL_CONTROL_CANCEL;
            return true;
        }

        case TOXAV_CALL_CONTROL_MUTE_AUDIO: {
            *out = TOX_AV_CALL_CONTROL_MUTE_AUDIO;
            return true;
        }

        case TOXAV_CALL_CONTROL_UNMUTE_AUDIO: {
            *out = TOX_AV_CALL_CONTROL_UNMUTE_AUDIO;
            return true;
        }

        case TOXAV_CALL_CONTROL_HIDE_VIDEO: {
            *out = TOX_AV_CALL_CONTROL_HIDE_VIDEO;
            return true;
        }

        case TOXAV_CALL_CONTROL_SHOW_VIDEO: {
            *out = TOX_AV_CALL_CONTROL_SHOW_VIDEO;
            return true;
        }
    }

    return false;
}

static Toxav_Err_Call_Control legacy_err_call_control(Tox_Err_Av_Call_Control error)
{
    switch (error) {
        case TOX_ERR_AV_CALL_CONTROL_OK:
            return TOXAV_ERR_CALL_CONTROL_OK;

        case TOX_ERR_AV_CALL_CONTROL_SYNC:
            return TOXAV_ERR_CALL_CONTROL_SYNC;

        case TOX_ERR_AV_CALL_CONTROL_FRIEND_NOT_IN_CALL:
            return TOXAV_ERR_CALL_CONTROL_FRIEND_NOT_IN_CALL;

        case TOX_ERR_AV_CALL_CONTROL_INVALID_TRANSITION:
            return TOXAV_ERR_CALL_CONTROL_INVALID_TRANSITION;
    }

    return TOXAV_ERR_CALL_CONTROL_SYNC;
}

bool toxav_call_control(ToxAV *_Nonnull av, Tox_Friend_Number friend_number, Toxav_Call_Control control,
                        Toxav_Err_Call_Control *_Nullable error)
{
    if (!tox_friend_exists(av->tox, friend_number)) {
        SET_ERROR_PARAMETER(error, TOXAV_ERR_CALL_CONTROL_FRIEND_NOT_FOUND);
        return false;
    }

    Tox_Av_Call_Control av_control;

    if (!legacy_call_control(control, &av_control)) {
        SET_ERROR_PARAMETER(error, TOXAV_ERR_CALL_CONTROL_INVALID_TRANSITION);
        return false;
    }

    Tox_Err_Av_Call_Control av_error;
    const bool ok = tox_av_call_control(av->av, friend_number, av_control, &av_error);
    SET_ERROR_PARAMETER(error, legacy_err_call_control(av_error));
    return ok;
}

static Toxav_Err_Bit_Rate_Set legacy_err_bit_rate_set(Tox_Err_Av_Bit_Rate_Set error)
{
    switch (error) {
        case TOX_ERR_AV_BIT_RATE_SET_OK:
            return TOXAV_ERR_BIT_RATE_SET_OK;

        case TOX_ERR_AV_BIT_RATE_SET_SYNC:
            return TOXAV_ERR_BIT_RATE_SET_SYNC;

        case TOX_ERR_AV_BIT_RATE_SET_INVALID_BIT_RATE:
            return TOXAV_ERR_BIT_RATE_SET_INVALID_BIT_RATE;

        case TOX_ERR_AV_BIT_RATE_SET_FRIEND_NOT_IN_CALL:
            return TOXAV_ERR_BIT_RATE_SET_FRIEND_NOT_IN_CALL;
    }

    return TOXAV_ERR_BIT_RATE_SET_SYNC;
}

bool toxav_audio_set_bit_rate(ToxAV *_Nonnull av, Tox_Friend_Number friend_number, uint32_t bit_rate,
                              Toxav_Err_Bit_Rate_Set *_Nullable error)
{
    if (!tox_friend_exists(av->tox, friend_number)) {
        SET_ERROR_PARAMETER(error, TOXAV_ERR_BIT_RATE_SET_FRIEND_NOT_FOUND);
        return false;
    }

    Tox_Err_Av_Bit_Rate_Set av_error;
    const bool ok = tox_av_audio_set_bit_rate(av->av, friend_number, bit_rate, &av_error);
    SET_ERROR_PARAMETER(error, legacy_err_bit_rate_set(av_error));
    return ok;
}

bool toxav_video_set_bit_rate(ToxAV *_Nonnull av, Tox_Friend_Number friend_number, uint32_t bit_rate,
                              Toxav_Err_Bit_Rate_Set *_Nullable error)
{
    if (!tox_friend_exists(av->tox, friend_number)) {
        SET_ERROR_PARAMETER(error, TOXAV_ERR_BIT_RATE_SET_FRIEND_NOT_FOUND);
        return false;
    }

    Tox_Err_Av_Bit_Rate_Set av_error;
    const bool ok = tox_av_video_set_bit_rate(av->av, friend_number, bit_rate, &av_error);
    SET_ERROR_PARAMETER(error, legacy_err_bit_rate_set(av_error));
    return ok;
}

static void legacy_audio_bit_rate(Tox_Av *_Nonnull av, Tox_Av_Friend_Number friend_number, uint32_t audio_bit_rate,
                                  void *_Nonnull user_data)
{
    ToxAV *toxav = (ToxAV *)user_data;
    pthread_mutex_lock(toxav->mutex);
    toxav_audio_bit_rate_cb *callback = toxav->audio_bit_rate_callback;
    void *callback_user_data = toxav->audio_bit_rate_user_data;
    pthread_mutex_unlock(toxav->mutex);

    if (callback != nullptr) {
        callback(toxav, friend_number, audio_bit_rate, callback_user_data);
    }
}

void toxav_callback_audio_bit_rate(ToxAV *_Nonnull av, toxav_audio_bit_rate_cb *_Nullable callback, void *_Nullable user_data)
{
    pthread_mutex_lock(av->mutex);
    av->audio_bit_rate_callback = callback;
    av->audio_bit_rate_user_data = user_data;
    pthread_mutex_unlock(av->mutex);
    tox_av_callback_audio_bit_rate(av->av, callback != nullptr ? legacy_audio_bit_rate : nullptr, av);
}

static void legacy_video_bit_rate(Tox_Av *_Nonnull av, Tox_Av_Friend_Number friend_number, uint32_t video_bit_rate,
                                  void *_Nonnull user_data)
{
    ToxAV *toxav = (ToxAV *)user_data;
    pthread_mutex_lock(toxav->mutex);
    toxav_video_bit_rate_cb *callback = toxav->video_bit_rate_callback;
    void *callback_user_data = toxav->video_bit_rate_user_data;
    pthread_mutex_unlock(toxav->mutex);

    if (callback != nullptr) {
        callback(toxav, friend_number, video_bit_rate, callback_user_data);
    }
}

void toxav_callback_video_bit_rate(ToxAV *_Nonnull av, toxav_video_bit_rate_cb *_Nullable callback, void *_Nullable user_data)
{
    pthread_mutex_lock(av->mutex);
    av->video_bit_rate_callback = callback;
    av->video_bit_rate_user_data = user_data;
    pthread_mutex_unlock(av->mutex);
    tox_av_callback_video_bit_rate(av->av, callback != nullptr ? legacy_video_bit_rate : nullptr, av);
}

static Toxav_Err_Send_Frame legacy_err_send_frame(Tox_Err_Av_Send_Frame error)
{
    switch (error) {
        case TOX_ERR_AV_SEND_FRAME_OK:
            return TOXAV_ERR_SEND_FRAME_OK;

        case TOX_ERR_AV_SEND_FRAME_NULL:
            return TOXAV_ERR_SEND_FRAME_NULL;

        case TOX_ERR_AV_SEND_FRAME_FRIEND_NOT_IN_CALL:
            return TOXAV_ERR_SEND_FRAME_FRIEND_NOT_IN_CALL;

        case TOX_ERR_AV_SEND_FRAME_SYNC:
            return TOXAV_ERR_SEND_FRAME_SYNC;

        case TOX_ERR_AV_SEND_FRAME_INVALID:
            return TOXAV_ERR_SEND_FRAME_INVALID;

        case TOX_ERR_AV_SEND_FRAME_PAYLOAD_TYPE_DISABLED:
            return TOXAV_ERR_SEND_FRAME_PAYLOAD_TYPE_DISABLED;

        case TOX_ERR_AV_SEND_FRAME_RTP_FAILED:
            return TOXAV_ERR_SEND_FRAME_RTP_FAILED;
    }

    return TOXAV_ERR_SEND_FRAME_SYNC;
}

bool toxav_audio_send_frame(ToxAV *_Nonnull av, Tox_Friend_Number friend_number, const int16_t *_Nullable pcm, size_t sample_count,
                            uint8_t channels, uint32_t sampling_rate, Toxav_Err_Send_Frame *_Nullable error)
{
    if (!tox_friend_exists(av->tox, friend_number)) {
        SET_ERROR_PARAMETER(error, TOXAV_ERR_SEND_FRAME_FRIEND_NOT_FOUND);
        return false;
    }

    Tox_Err_Av_Send_Frame av_error;
    const bool ok = tox_av_audio_send_frame(av->av, friend_number, pcm, sample_count, channels, sampling_rate, &av_error);
    SET_ERROR_PARAMETER(error, legacy_err_send_frame(av_error));
    return ok;
}

bool toxav_video_send_frame(ToxAV *_Nonnull av, Tox_Friend_Number friend_number, uint16_t width, uint16_t height,
                            const uint8_t *_Nullable y, const uint8_t *_Nullable u, const uint8_t *_Nullable v, Toxav_Err_Send_Frame *_Nullable error)
{
    if (!tox_friend_exists(av->tox, friend_number)) {
        SET_ERROR_PARAMETER(error, TOXAV_ERR_SEND_FRAME_FRIEND_NOT_FOUND);
        return false;
    }

    Tox_Err_Av_Send_Frame av_error;
    const bool ok = tox_av_video_send_frame(av->av, friend_number, width, height, y, u, v, &av_error);
    SET_ERROR_PARAMETER(error, legacy_err_send_frame(av_error));
    return ok;
}

static void legacy_audio_receive_frame(Tox_Av *_Nonnull av, Tox_Av_Friend_Number friend_number, const int16_t *_Nonnull pcm,
                                       size_t sample_count, uint8_t channels, uint32_t sampling_rate, void *_Nonnull user_data)
{
    ToxAV *toxav = (ToxAV *)user_data;
    pthread_mutex_lock(toxav->mutex);
    toxav_audio_receive_frame_cb *callback = toxav->audio_receive_frame_callback;
    void *callback_user_data = toxav->audio_receive_frame_user_data;
    pthread_mutex_unlock(toxav->mutex);

    if (callback != nullptr) {
        callback(toxav, friend_number, pcm, sample_count, channels, sampling_rate, callback_user_data);
    }
}

void toxav_callback_audio_receive_frame(ToxAV *_Nonnull av, toxav_audio_receive_frame_cb *_Nullable callback, void *_Nullable user_data)
{
    pthread_mutex_lock(av->mutex);
    av->audio_receive_frame_callback = callback;
    av->audio_receive_frame_user_data = user_data;
    pthread_mutex_unlock(av->mutex);
    tox_av_callback_audio_receive_frame(av->av, callback != nullptr ? legacy_audio_receive_frame : nullptr, av);
}

static void legacy_video_receive_frame(Tox_Av *_Nonnull av, Tox_Av_Friend_Number friend_number, uint16_t width, uint16_t height,
                                       const uint8_t *_Nonnull y, const uint8_t *_Nonnull u, const uint8_t *_Nonnull v,
                                       int32_t ystride, int32_t ustride, int32_t vstride, void *_Nonnull user_data)
{
    ToxAV *toxav = (ToxAV *)user_data;
    pthread_mutex_lock(toxav->mutex);
    toxav_video_receive_frame_cb *callback = toxav->video_receive_frame_callback;
    void *callback_user_data = toxav->video_receive_frame_user_data;
    pthread_mutex_unlock(toxav->mutex);

    if (callback != nullptr) {
        callback(toxav, friend_number, width, height, y, u, v, ystride, ustride, vstride, callback_user_data);
    }
}

void toxav_callback_video_receive_frame(ToxAV *_Nonnull av, toxav_video_receive_frame_cb *_Nullable callback, void *_Nullable user_data)
{
    pthread_mutex_lock(av->mutex);
    av->video_receive_frame_callback = callback;
    av->video_receive_frame_user_data = user_data;
    pthread_mutex_unlock(av->mutex);
    tox_av_callback_video_receive_frame(av->av, callback != nullptr ? legacy_video_receive_frame : nullptr, av);
}
