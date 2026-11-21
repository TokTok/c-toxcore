/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2025 The TokTok team.
 * Copyright © 2013-2015 Tox project.
 */
#ifndef C_TOXCORE_TOXAV_TOXAV_STRUCT_H
#define C_TOXCORE_TOXAV_TOXAV_STRUCT_H

#include <pthread.h>

#include "tox_av.h"
#include "audio.h"
#include "video.h"
#include "bwcontroller.h"
#include "rtp.h"
#include "msi.h"

#include "../toxcore/logger.h"
#include "../toxcore/mono_time.h"
#include "../toxcore/mem.h"

typedef struct ToxAVCall ToxAVCall;

struct ToxAVCall {
    Tox_Av *_Nonnull av;

    pthread_mutex_t mutex_audio[1];
    /** @guarded_by mutex_audio */
    RTPSession *_Nullable audio_rtp;
    /** @guarded_by mutex_audio */
    ACSession *_Nullable audio;

    pthread_mutex_t mutex_video[1];
    /** @guarded_by mutex_video */
    RTPSession *_Nullable video_rtp;
    /** @guarded_by mutex_video */
    VCSession *_Nullable video;

    BWController *_Nullable bwc;

    bool active;
    MSICall *_Nullable msi_call;
    Tox_Av_Friend_Number friend_number;

    uint32_t audio_bit_rate; /* Sending audio bit rate */
    uint32_t video_bit_rate; /* Sending video bit rate */

    /** Required for monitoring changes in states */
    uint8_t previous_self_capabilities;

    tox_av_audio_receive_frame_cb *_Nullable acb;
    void *_Nullable acb_user_data;

    tox_av_video_receive_frame_cb *_Nullable vcb;
    void *_Nullable vcb_user_data;

    pthread_mutex_t toxav_call_mutex[1];

    struct ToxAVCall *_Nullable prev;
    struct ToxAVCall *_Nullable next;
};

/** Decode time statistics */
typedef struct DecodeTimeStats {
    /** Measure count */
    int32_t count;
    /** Last cycle total */
    int32_t total;
    /** Average decoding time in ms */
    int32_t average;

    /** Calculated iteration interval */
    uint32_t interval;
} DecodeTimeStats;

/** Asks the Tox of a ToxAV made by toxav_new whether a friend is connected. */
typedef bool tox_av_friend_connected_cb(Tox_Av_Friend_Number friend_number, void *_Nullable user_data);

struct Tox_Av {
    const struct Memory *_Nonnull mem;
    Logger *_Nonnull log;
    /** Only for a ToxAV made by toxav_new: replaces the pushed connection state. */
    tox_av_friend_connected_cb *_Nullable friend_connected;
    void *_Nullable friend_connected_user_data;

    MSISession *_Nonnull msi;

    /* Not mutex: frame sends send while holding a call's audio or video
     * mutex, which other functions lock after mutex. */
    pthread_mutex_t send_mutex[1];
    /** @guarded_by send_mutex */
    tox_av_send_lossy_packet_cb *_Nullable send_lossy;
    /** @guarded_by send_mutex */
    void *_Nullable send_lossy_user_data;
    /** @guarded_by send_mutex */
    tox_av_send_lossless_packet_cb *_Nullable send_lossless;
    /** @guarded_by send_mutex */
    void *_Nullable send_lossless_user_data;

    /**
     * The connected friends, in ascending order.
     *
     * @guarded_by mutex
     */
    Tox_Av_Friend_Number *_Nullable connected;
    /** @guarded_by mutex */
    uint32_t connected_count;

    /** @guarded_by mutex */
    ToxAVCall *_Nullable calls;
    pthread_mutex_t *_Nonnull mutex;

    /* Call callback */
    tox_av_call_cb *_Nullable ccb;
    void *_Nullable ccb_user_data;
    /* Call state callback */
    tox_av_call_state_cb *_Nullable scb;
    void *_Nullable scb_user_data;
    /* Audio frame receive callback */
    tox_av_audio_receive_frame_cb *_Nullable acb;
    void *_Nullable acb_user_data;
    /* Video frame receive callback */
    tox_av_video_receive_frame_cb *_Nullable vcb;
    void *_Nullable vcb_user_data;
    /* Bit rate control callback */
    tox_av_audio_bit_rate_cb *_Nullable abcb;
    void *_Nullable abcb_user_data;
    /* Bit rate control callback */
    tox_av_video_bit_rate_cb *_Nullable vbcb;
    void *_Nullable vbcb_user_data;

    /* keep track of decode times for audio and video */
    DecodeTimeStats audio_stats;
    DecodeTimeStats video_stats;

    Mono_Time *_Nonnull toxav_mono_time; // Tox_Av's own mono_time instance
};

#endif /* C_TOXCORE_TOXAV_TOXAV_STRUCT_H */
