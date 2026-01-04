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

typedef struct ToxAVCall ToxAVCall;

struct ToxAV_IO {
    toxav_send_lossy_cb *send_lossy;
    toxav_send_lossless_cb *send_lossless;
    toxav_friend_exists_cb *friend_exists;
    toxav_friend_connected_cb *friend_connected;
    toxav_time_cb *current_time;
};

struct ToxAVCall {
    ToxAV *av;

    pthread_mutex_t mutex_audio[1];
    RTPSession *audio_rtp;
    ACSession *audio;

    pthread_mutex_t mutex_video[1];
    RTPSession *video_rtp;
    VCSession *video;

    BWController *bwc;

    bool active;
    MSICall *msi_call;
    Tox_Friend_Number friend_number;

    uint32_t audio_bit_rate; /* Sending audio bit rate */
    uint32_t video_bit_rate; /* Sending video bit rate */

    /** Required for monitoring changes in states */
    uint8_t previous_self_capabilities;

    toxav_audio_receive_frame_cb *acb;
    void *acb_user_data;

    pthread_mutex_t toxav_call_mutex[1];

    struct ToxAVCall *prev;
    struct ToxAVCall *next;
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
    const struct Tox_Memory *mem;
    Logger *log;
    Tox *tox;
    MSISession *msi;

    ToxAV_IO io;
    void *io_user_data;

    /* Two-way storage: first is array of calls and second is list of calls with head and tail */
    ToxAVCall **calls;
    uint32_t calls_tail;
    uint32_t calls_head;
    pthread_mutex_t mutex[1];

    /* Call callback */
    toxav_call_cb *ccb;
    void *ccb_user_data;
    /* Call state callback */
    toxav_call_state_cb *scb;
    void *scb_user_data;
    /* Audio frame receive callback */
    toxav_audio_receive_frame_cb *acb;
    void *acb_user_data;
    /* Video frame receive callback */
    toxav_video_receive_frame_cb *vcb;
    void *vcb_user_data;
    /* Bit rate control callback */
    toxav_audio_bit_rate_cb *abcb;
    void *abcb_user_data;
    /* Bit rate control callback */
    toxav_video_bit_rate_cb *vbcb;
    void *vbcb_user_data;

    /* keep track of decode times for audio and video */
    DecodeTimeStats audio_stats;
    DecodeTimeStats video_stats;

    Mono_Time *toxav_mono_time; // ToxAV's own mono_time instance
};

#endif /* C_TOXCORE_TOXAV_TOXAV_PRIVATE_H */
