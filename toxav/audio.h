/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2018 The TokTok team.
 * Copyright © 2013-2015 Tox project.
 */
#ifndef C_TOXCORE_TOXAV_AUDIO_H
#define C_TOXCORE_TOXAV_AUDIO_H

#include "toxav.h"

#include "../toxcore/logger.h"
#include "../toxcore/util.h"

#include <opus.h>
#include <pthread.h>


#define AUDIO_JITTERBUFFER_COUNT (3)
#define AUDIO_START_SAMPLING_RATE (48000)
#define AUDIO_START_BITRATE_RATE (48000)
#define AUDIO_START_CHANNEL_COUNT (2)
#define AUDIO_OPUS_PACKET_LOSS_PERC (10)
#define AUDIO_OPUS_COMPLEXITY (10)

#define AUDIO_DECODER__START_SAMPLING_RATE (48000)
#define AUDIO_DECODER__START_CHANNEL_COUNT (2)


typedef struct ACSession_s {
    Logger *log;

    /* encoding */
    OpusEncoder *encoder;
    int32_t le_sample_rate; /* Last encoder sample rate */
    int32_t le_channel_count; /* Last encoder channel count */
    int32_t le_bit_rate; /* Last encoder bit rate */

    /* decoding */
    OpusDecoder *decoder;
    int32_t lp_channel_count; /* Last packet channel count */
    int32_t lp_sampling_rate; /* Last packet sample rate */
    int32_t lp_frame_duration; /* Last packet frame duration */
    int32_t ld_sample_rate; /* Last decoder sample rate */
    int32_t ld_channel_count; /* Last decoder channel count */
    uint64_t ldrts; /* Last decoder reconfiguration time stamp */
    void *j_buf;

    pthread_mutex_t queue_mutex[1];

    ToxAV *av;
    uint32_t friend_number;
    /* Audio frame receive callback */
    toxav_audio_receive_frame_cb *acb;
    void *acb_user_data;
} ACSession;

ACSession *ac_new(Logger *log, ToxAV *av, uint32_t friend_number, toxav_audio_receive_frame_cb *cb, void *cb_data);
void ac_kill(ACSession *ac);
void ac_iterate(ACSession *ac);
int ac_queue_message(Mono_Time *mono_time, void *acp, struct RTPMessage *msg);
int ac_reconfigure_encoder(ACSession *ac, int32_t bit_rate, int32_t sampling_rate, uint8_t channels);

#endif // C_TOXCORE_TOXAV_AUDIO_H
