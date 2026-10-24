/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2025 The TokTok team.
 * Copyright © 2013-2015 Tox project.
 */
#ifndef C_TOXCORE_TOXAV_TOXAV_PRIVATE_H
#define C_TOXCORE_TOXAV_TOXAV_PRIVATE_H

#include <pthread.h>

#include "toxav.h"
#include "audio.h"
#include "video.h"
#include "bwcontroller.h"
#include "rtp.h"
#include "msi.h"

#include "../toxcore/logger.h"
#include "../toxcore/mono_time.h"
#include "../toxcore/mem.h"

typedef struct ToxAVCall ToxAVCall;

struct ToxAV_IO {
    toxav_send_lossy_cb *_Nullable send_lossy;
    toxav_send_lossless_cb *_Nullable send_lossless;
    toxav_friend_exists_cb *_Nullable friend_exists;
    toxav_friend_connected_cb *_Nullable friend_connected;
    toxav_time_cb *_Nullable current_time;
};

struct ToxAVCall {
    ToxAV *_Nonnull av;

    pthread_mutex_t mutex_audio[1];
    RTPSession *_Nullable audio_rtp;
    ACSession *_Nullable audio;

    pthread_mutex_t mutex_video[1];
    RTPSession *_Nullable video_rtp;
    VCSession *_Nullable video;

    BWController *_Nullable bwc;

    bool active;
    MSICall *_Nullable msi_call;
    Tox_Friend_Number friend_number;

    uint32_t audio_bit_rate; /* Sending audio bit rate */
    uint32_t video_bit_rate; /* Sending video bit rate */

    /** Required for monitoring changes in states */
    uint8_t previous_self_capabilities;

    toxav_audio_receive_frame_cb *_Nullable acb;
    void *_Nullable acb_user_data;

    toxav_video_receive_frame_cb *_Nullable vcb;
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

/* Forward declaration for Tox if needed, but we try to avoid it in core.
 * However, struct ToxAV has `Tox *` for legacy support. */
#ifndef TOX_DEFINED
#define TOX_DEFINED
typedef struct Tox Tox;
#endif /* TOX_DEFINED */

struct ToxAV {
    const struct Memory *_Nonnull mem;
    Logger *_Nonnull log;
    Tox *_Nonnull tox;
    MSISession *_Nonnull msi;

    ToxAV_IO io;
    void *_Nullable io_user_data;

    /* Two-way storage: first is array of calls and second is list of calls with head and tail */
    ToxAVCall *_Nullable *_Nullable calls;
    uint32_t calls_tail;
    uint32_t calls_head;
    pthread_mutex_t *_Nonnull mutex;

    /* Call callback */
    toxav_call_cb *_Nullable ccb;
    void *_Nullable ccb_user_data;
    /* Call state callback */
    toxav_call_state_cb *_Nullable scb;
    void *_Nullable scb_user_data;
    /* Audio frame receive callback */
    toxav_audio_receive_frame_cb *_Nullable acb;
    void *_Nullable acb_user_data;
    /* Video frame receive callback */
    toxav_video_receive_frame_cb *_Nullable vcb;
    void *_Nullable vcb_user_data;
    /* Bit rate control callback */
    toxav_audio_bit_rate_cb *_Nullable abcb;
    void *_Nullable abcb_user_data;
    /* Bit rate control callback */
    toxav_video_bit_rate_cb *_Nullable vbcb;
    void *_Nullable vbcb_user_data;

    /* keep track of decode times for audio and video */
    DecodeTimeStats audio_stats;
    DecodeTimeStats video_stats;

    Mono_Time *_Nonnull toxav_mono_time; // ToxAV's own mono_time instance
};

#endif /* C_TOXCORE_TOXAV_TOXAV_PRIVATE_H */
