/*
 * Copyright © 2018 zoff@zoff.cc and mail@strfry.org
 *
 * This file is part of Tox, the free peer to peer instant messenger.
 *
 * Tox is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Tox is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Tox.  If not, see <http://www.gnu.org/licenses/>.
 */


#include <assert.h>

#include "../../../toxcore/ccompat.h"
#include "../../audio.h"
#include "../../video.h"
#include "../../msi.h"
#include "../../ring_buffer.h"
#include "../../rtp.h"
#include "../../tox_generic.h"
#include "../../../toxcore/mono_time.h"
#include "../toxav_codecs.h"

#ifdef __cplusplus
extern "C" {
#endif
// for H264 ----------
#include <libavcodec/avcodec.h>
#include <libavutil/opt.h>
// for H264 ----------
#ifdef __cplusplus
}
#endif

// HINT: cant get the loglevel enum here for some reason. so here is the workaround.
#ifndef LOGGER_LEVEL_TRACE
#define LOGGER_LEVEL_TRACE 0
#endif
#ifndef LOGGER_LEVEL_DEBUG
#define LOGGER_LEVEL_DEBUG 1
#endif
#ifndef LOGGER_LEVEL_INFO
#define LOGGER_LEVEL_INFO 2
#endif
#ifndef LOGGER_LEVEL_WARNING
#define LOGGER_LEVEL_WARNING 3
#endif
#ifndef LOGGER_LEVEL_ERROR
#define LOGGER_LEVEL_ERROR 4
#endif
// HINT: cant get the loglevel enum here for some reason. so here is the workaround.

/* ---------------------------------------------------
 *
 * Hardware specific defines for encoders and decoder
 * use -DXXXXXX to enable at compile time, otherwise defaults will be used
 *
 * ---------------------------------------------------
 */


/* ---------------------------------------------------
 * DEFAULT
 */
#define ACTIVE_HW_CODEC_CONFIG_NAME "_DEFAULT_"
#define H264_WANT_ENCODER_NAME "not used with x264"
#define H264_WANT_DECODER_NAME "h264"
#define X264_ENCODE_USED 1
// #define RAPI_HWACCEL_ENC 1
// #define RAPI_HWACCEL_DEC 1
/* !!multithreaded H264 decoding adds about 80ms of delay!! (0 .. disable, 1 .. disable also?) */
#define H264_DECODER_THREADS 4
#define H264_DECODER_THREAD_FRAME_ACTIVE 1
/* multithreaded encoding seems to add less delay (0 .. disable) */
#define X264_ENCODER_THREADS 4
#define X264_ENCODER_SLICES 4
#define H264_ENCODE_MAX_BITRATE_OVER_ALLOW 1.3
#define H264_ENCODER_STARTWITH_PROFILE_HIGH 0
/* ---------------------------------------------------
 * DEFAULT
 */


#ifdef HW_CODEC_CONFIG_ACCELDEFAULT
/* ---------------------------------------------------
 * default with possible HW accel
 */
#undef ACTIVE_HW_CODEC_CONFIG_NAME
#undef RAPI_HWACCEL_ENC
#undef X264_ENCODE_USED
// --
#define ACTIVE_HW_CODEC_CONFIG_NAME "HW_CODEC_CONFIG_ACCELDEFAULT"
#define RAPI_HWACCEL_ENC 1
/* ---------------------------------------------------
 * default with possible HW accel
 */
#endif


#ifdef HW_CODEC_CONFIG_TRIFA
/* ---------------------------------------------------
 * TRIfA
 */
#undef ACTIVE_HW_CODEC_CONFIG_NAME
#undef H264_WANT_ENCODER_NAME
#undef H264_WANT_DECODER_NAME
#undef X264_ENCODE_USED
#undef RAPI_HWACCEL_ENC
#undef RAPI_HWACCEL_DEC
#undef H264_DECODER_THREADS
#undef H264_DECODER_THREAD_FRAME_ACTIVE
#undef X264_ENCODER_THREADS
#undef X264_ENCODER_SLICES
#undef H264_ENCODER_STARTWITH_PROFILE_HIGH
// --
#define ACTIVE_HW_CODEC_CONFIG_NAME "HW_CODEC_CONFIG_TRIFA"
#define _TRIFA_CODEC_DECODER_ 1
#define H264_WANT_DECODER_NAME "h264_mediacodec"
// #define H264_WANT_DECODER_NAME "h264"
#define X264_ENCODE_USED 1
// #define RAPI_HWACCEL_DEC 1
#define H264_DECODER_THREADS 3
#define H264_DECODER_THREAD_FRAME_ACTIVE 0
#define X264_ENCODER_THREADS 3
#define X264_ENCODER_SLICES 3
#define H264_ENCODER_STARTWITH_PROFILE_HIGH 0
/* ---------------------------------------------------
 * TRIfA
 */
#endif

#ifdef HW_CODEC_CONFIG_RPI3_TBW_BIDI
/* ---------------------------------------------------
 * RPI3 tbw-bidi
 */
#undef ACTIVE_HW_CODEC_CONFIG_NAME
#undef H264_WANT_ENCODER_NAME
#undef H264_WANT_DECODER_NAME
#undef X264_ENCODE_USED
#undef RAPI_HWACCEL_ENC
#undef RAPI_HWACCEL_DEC
#undef H264_DECODER_THREADS
#undef H264_DECODER_THREAD_FRAME_ACTIVE
#undef X264_ENCODER_THREADS
#undef X264_ENCODER_SLICES
#undef H264_ENCODER_STARTWITH_PROFILE_HIGH
// --
#define ACTIVE_HW_CODEC_CONFIG_NAME "HW_CODEC_CONFIG_RPI3_TBW_BIDI"
#define H264_WANT_ENCODER_NAME "h264_omx"
#define H264_WANT_DECODER_NAME "h264_mmal"
#define X264_ENCODE_USED 1
// #define RAPI_HWACCEL_ENC 1
#define RAPI_HWACCEL_DEC 1
#define H264_DECODER_THREADS 0
#define H264_DECODER_THREAD_FRAME_ACTIVE 0
#define X264_ENCODER_THREADS 1
#define X264_ENCODER_SLICES 1
#define H264_ENCODER_STARTWITH_PROFILE_HIGH 1
/* ---------------------------------------------------
 * RPI3 bidi
 */
#endif

#ifdef HW_CODEC_CONFIG_RPI3_TBW_TV
/* ---------------------------------------------------
 * RPI3 tbw-TV
 */
#undef ACTIVE_HW_CODEC_CONFIG_NAME
#undef H264_WANT_ENCODER_NAME
#undef H264_WANT_DECODER_NAME
#undef X264_ENCODE_USED
#undef RAPI_HWACCEL_ENC
#undef RAPI_HWACCEL_DEC
#undef H264_DECODER_THREADS
#undef H264_DECODER_THREAD_FRAME_ACTIVE
#undef X264_ENCODER_THREADS
#undef X264_ENCODER_SLICES
#undef H264_ENCODER_STARTWITH_PROFILE_HIGH
// --
#define ACTIVE_HW_CODEC_CONFIG_NAME "HW_CODEC_CONFIG_RPI3_TBW_TV"
#define H264_WANT_DECODER_NAME "h264_mmal"
//#define H264_WANT_DECODER_NAME "h264"
#define X264_ENCODE_USED 1
#define RAPI_HWACCEL_DEC 1
#define H264_DECODER_THREADS 0
#define H264_DECODER_THREAD_FRAME_ACTIVE 0
#define X264_ENCODER_THREADS 0
#define X264_ENCODER_SLICES 0
#define H264_ENCODER_STARTWITH_PROFILE_HIGH 0
/* ---------------------------------------------------
 * RPI3 tbw-TV
 */
#endif

#ifdef HW_CODEC_CONFIG_UTOX_LINNVENC
/* ---------------------------------------------------
 * UTOX linux
 */
#undef ACTIVE_HW_CODEC_CONFIG_NAME
#undef H264_WANT_ENCODER_NAME
#undef H264_WANT_DECODER_NAME
#undef X264_ENCODE_USED
#undef RAPI_HWACCEL_ENC
#undef RAPI_HWACCEL_DEC
#undef H264_DECODER_THREADS
#undef H264_DECODER_THREAD_FRAME_ACTIVE
#undef X264_ENCODER_THREADS
#undef X264_ENCODER_SLICES
#undef H264_ENCODER_STARTWITH_PROFILE_HIGH
// --
#define ACTIVE_HW_CODEC_CONFIG_NAME "HW_CODEC_CONFIG_UTOX_LINNVENC"
#define H264_WANT_ENCODER_NAME "h264_nvenc"
#define H264_WANT_DECODER_NAME "h264"
// #define X264_ENCODE_USED 1
#define RAPI_HWACCEL_ENC 1
#define H264_DECODER_THREADS 4
#define H264_DECODER_THREAD_FRAME_ACTIVE 0
#define X264_ENCODER_THREADS 4
#define X264_ENCODER_SLICES 4
#define H264_ENCODER_STARTWITH_PROFILE_HIGH 1
/* ---------------------------------------------------
 * UTOX linux
 */
#endif

#ifdef HW_CODEC_CONFIG_TBW_LINNVENC
/* ---------------------------------------------------
 * tbw usb linux
 */
#undef ACTIVE_HW_CODEC_CONFIG_NAME
#undef H264_WANT_ENCODER_NAME
#undef H264_WANT_DECODER_NAME
#undef X264_ENCODE_USED
#undef RAPI_HWACCEL_ENC
#undef RAPI_HWACCEL_DEC
#undef H264_DECODER_THREADS
#undef H264_DECODER_THREAD_FRAME_ACTIVE
#undef X264_ENCODER_THREADS
#undef X264_ENCODER_SLICES
#undef H264_ENCODER_STARTWITH_PROFILE_HIGH
// --
#define ACTIVE_HW_CODEC_CONFIG_NAME "HW_CODEC_CONFIG_TBW_LINNVENC"
#define H264_WANT_ENCODER_NAME "h264_nvenc"
#define H264_WANT_DECODER_NAME "h264" // "h264_cuvid"
// #define X264_ENCODE_USED 1
#define RAPI_HWACCEL_ENC 1
// #define RAPI_HWACCEL_DEC 1
#define H264_DECODER_THREADS 4
#define H264_DECODER_THREAD_FRAME_ACTIVE 0
#define X264_ENCODER_THREADS 4
#define X264_ENCODER_SLICES 4
#define H264_ENCODER_STARTWITH_PROFILE_HIGH 1
/* ---------------------------------------------------
 * tbw usb linux
 */
#endif

#ifdef HW_CODEC_CONFIG_UTOX_WIN7
/* ---------------------------------------------------
 * UTOX win7
 */
#undef ACTIVE_HW_CODEC_CONFIG_NAME
#undef H264_WANT_ENCODER_NAME
#undef H264_WANT_DECODER_NAME
#undef X264_ENCODE_USED
#undef RAPI_HWACCEL_ENC
#undef RAPI_HWACCEL_DEC
#undef H264_DECODER_THREADS
#undef H264_DECODER_THREAD_FRAME_ACTIVE
#undef X264_ENCODER_THREADS
#undef X264_ENCODER_SLICES
#undef H264_ENCODER_STARTWITH_PROFILE_HIGH
// --
#define ACTIVE_HW_CODEC_CONFIG_NAME "HW_CODEC_CONFIG_UTOX_WIN7"
#define H264_WANT_ENCODER_NAME "h264_nvenc"
#define H264_WANT_DECODER_NAME "h264"
// #define X264_ENCODE_USED 1
#define RAPI_HWACCEL_ENC 1
// #define RAPI_HWACCEL_DEC 1
#define H264_DECODER_THREADS 2
#define H264_DECODER_THREAD_FRAME_ACTIVE 1
#define X264_ENCODER_THREADS 6
#define X264_ENCODER_SLICES 6
#define H264_ENCODER_STARTWITH_PROFILE_HIGH 1
/* ---------------------------------------------------
 * UTOX win7
 */
#endif


#ifdef HW_CODEC_CONFIG_UTOX_UB81
/* ---------------------------------------------------
 * UTOX win7
 */
#undef ACTIVE_HW_CODEC_CONFIG_NAME
//#undef H264_WANT_ENCODER_NAME
//#undef H264_WANT_DECODER_NAME
#undef H264_DECODER_THREADS
#undef H264_DECODER_THREAD_FRAME_ACTIVE
#undef X264_ENCODER_THREADS
#undef X264_ENCODER_SLICES
#undef H264_ENCODER_STARTWITH_PROFILE_HIGH
// --
#define ACTIVE_HW_CODEC_CONFIG_NAME "HW_CODEC_CONFIG_UTOX_UB81"
#define H264_DECODER_THREADS 2
#define H264_DECODER_THREAD_FRAME_ACTIVE 1
#define X264_ENCODER_THREADS 6
#define X264_ENCODER_SLICES 6
#define H264_ENCODER_STARTWITH_PROFILE_HIGH 1
/* ---------------------------------------------------
 * UTOX win7
 */
#endif


void my_log_callback(void *ptr, int level, const char *fmt, va_list vargs)
{
    // !!WARNING!! ffmpeg somehow gives back bad strings, calling "strlen" will crash
    //             so no printf type of function will work!!
}

#ifdef X264_ENCODE_USED
#else
static int exists_encoder_codec_by_name(char *codec_name)
{
#if LIBAVCODEC_VERSION_INT < AV_VERSION_INT(58, 9, 100)
    avcodec_register_all();
#endif

    AVCodec *codec = NULL;
    codec = avcodec_find_encoder_by_name(codec_name);
    if (codec)
    {
        return 1;
    }

    return 0;
}
#endif

#ifdef X264_ENCODE_USED
#else
static int works_encoder_codec_by_name(char *codec_name)
{
#if LIBAVCODEC_VERSION_INT < AV_VERSION_INT(58, 9, 100)
    avcodec_register_all();
#endif

    AVCodec *codec = NULL;
    codec = avcodec_find_encoder_by_name(codec_name);
    if (codec)
    {
        AVCodecContext *avctx = avcodec_alloc_context3(codec);

        // -------- wanted (and also needed settings) --------
        av_opt_set(avctx->priv_data, "profile", "baseline", 0);
        avctx->profile = FF_PROFILE_H264_BASELINE;

        av_opt_set(avctx->priv_data, "annex_b", "1", 0);
        av_opt_set(avctx->priv_data, "repeat_headers", "1", 0);
        av_opt_set_int(avctx->priv_data, "b", 200 * 1000, 0);
        av_opt_set_int(avctx->priv_data, "bitrate", 200 * 1000, 0);

        av_opt_set_int(avctx->priv_data, "cbr", true, 0);
        av_opt_set(avctx->priv_data, "rc", "cbr_ld_hq", 0);
        av_opt_set_int(avctx->priv_data, "delay", 0, 0);

        if (strncmp(codec_name, "h264_nvenc", strlen("h264_nvenc")) == 0)
        {
            // av_opt_set(avctx->priv_data, "preset", "llhq", 0);
            av_opt_set(avctx->priv_data, "preset", "p3", 0);
            av_opt_set(avctx->priv_data, "rc", "cbr", 0);
            av_opt_set(avctx->priv_data, "tune", "ll", 0);
            av_opt_set(avctx->priv_data, "zerolatency", "true", 0);
        }
        else
        {
            av_opt_set(avctx->priv_data, "preset", "ultrafast", 0);
        }

        // HINT: needed for newer 264_nvenc versions
        av_opt_set(avctx->priv_data, "2pass", "false", 0);

        av_opt_set_int(avctx->priv_data, "bf", 0, 0);
        av_opt_set_int(avctx->priv_data, "qmin", 3, 0);
        av_opt_set_int(avctx->priv_data, "qmax", 51, 0);
        av_opt_set(avctx->priv_data, "forced-idr", "false", 0);
        av_opt_set_int(avctx->priv_data, "zerolatency", 1, AV_OPT_SEARCH_CHILDREN);
        av_opt_set(avctx->priv_data, "no-scenecut", "true", 0);
        av_opt_set(avctx->priv_data, "strict_gop", "true", 0);
        avctx->bit_rate = 200 * 1000;
        avctx->width = 1920;
        avctx->height = 1080;
        avctx->gop_size = 60;
        avctx->max_b_frames = 0;
        avctx->pix_fmt = AV_PIX_FMT_YUV420P;
        avctx->time_base.num = 1;
        avctx->time_base.den = 1000;

        avctx->time_base = (AVRational) {
            25, 1000
        };
        avctx->framerate = (AVRational) {
            1000, 25
        };
        // -------- wanted (and also needed settings) --------


        AVDictionary *opts = NULL;
        if (avcodec_open2(avctx, codec, &opts) < 0)
        {
            av_free(avctx);
            return 0;
        }

        av_dict_free(&opts);
        avcodec_free_context(&avctx);

        return 1;
    }

    return 0;
}
#endif

VCSession *vc_new_h264(Logger *log, ToxAV *av, uint32_t friend_number, toxav_video_receive_frame_cb *cb, void *cb_data,
                       VCSession *vc)
{

    // ENCODER -------

    LOGGER_API_WARNING(av->tox, "HW CODEC CONFIG ACTIVE: %s", ACTIVE_HW_CODEC_CONFIG_NAME);

#ifdef X264_ENCODE_USED
    vc->x264_software_encoder_used = 1;
    LOGGER_API_WARNING(av->tox, "x264_software_encoder_used:true:%d", vc->x264_software_encoder_used);
#else
    // ----- detect H264 encoder -----
    vc->x264_software_encoder_used = 0;
    LOGGER_API_WARNING(av->tox, "x264_software_encoder_used:false:%d", vc->x264_software_encoder_used);
    int res_detect = 0;

    res_detect = exists_encoder_codec_by_name("h264_omx");
    LOGGER_API_WARNING(av->tox, "h264_omx:e:%d", res_detect);
    res_detect = works_encoder_codec_by_name("h264_omx");
    LOGGER_API_WARNING(av->tox, "h264_omx:w:%d", res_detect);

    if (res_detect == 1)
    {
        strncpy(vc->encoder_codec_used_name, "h264_omx", strlen("h264_omx"));
        LOGGER_API_WARNING(av->tox, "using_encoder:%s", vc->encoder_codec_used_name);
    }
    else
    {
        res_detect = exists_encoder_codec_by_name("h264_nvenc");
        LOGGER_API_WARNING(av->tox, "h264_nvenc:e:%d", res_detect);
        res_detect = works_encoder_codec_by_name("h264_nvenc");
        LOGGER_API_WARNING(av->tox, "h264_nvenc:w:%d", res_detect);

        if (res_detect == 1)
        {
            strncpy(vc->encoder_codec_used_name, "h264_nvenc", strlen("h264_nvenc"));
            LOGGER_API_WARNING(av->tox, "using_encoder:%s", vc->encoder_codec_used_name);
        }
        else
        {
            res_detect = 0;
            //res_detect = exists_encoder_codec_by_name("h264_vaapi");
            //LOGGER_API_WARNING(av->tox, "h264_vaapi:e:%d", res_detect);
            //res_detect = works_encoder_codec_by_name("h264_vaapi");
            //LOGGER_API_WARNING(av->tox, "h264_vaapi:w:%d", res_detect);

            if (res_detect == 1)
            {
                strncpy(vc->encoder_codec_used_name, "h264_vaapi", strlen("h264_vaapi"));
                LOGGER_API_WARNING(av->tox, "using_encoder:%s", vc->encoder_codec_used_name);
            }
            else
            {
                res_detect = exists_encoder_codec_by_name("libx264");
                LOGGER_API_WARNING(av->tox, "libx264:e:%d", res_detect);
                res_detect = works_encoder_codec_by_name("libx264");
                LOGGER_API_WARNING(av->tox, "libx264:w:%d", res_detect);

                strncpy(vc->encoder_codec_used_name, "libx264", strlen("libx264"));
                LOGGER_API_WARNING(av->tox, "using_fallback_encoder:%s", vc->encoder_codec_used_name);

                vc->x264_software_encoder_used = 1;
            }
        }
    }
    // ----- detect H264 encoder -----
#endif


    if (vc->x264_software_encoder_used == 1)
    {

        LOGGER_API_WARNING(av->tox, "x264_software_encoder_used:02");

        x264_param_t param;

        // "ultrafast", "superfast", "veryfast", "faster", "fast", "medium", "slow", "slower", "veryslow", "placebo"

        if ((int)(H264_ENCODER_STARTWITH_PROFILE_HIGH) == 1) {
            if (x264_param_default_preset(&param, "superfast", "zerolatency,fastdecode") < 0) {
                // goto fail;
            }
        } else {
            if (x264_param_default_preset(&param, "ultrafast", "zerolatency,fastdecode") < 0) {
                // goto fail;
            }
        }

        /* Configure non-default params */
        // param.i_bitdepth = 8;
        param.i_csp = X264_CSP_I420;
        param.i_width  = 1920;
        param.i_height = 1080;
        vc->h264_enc_width = param.i_width;
        vc->h264_enc_height = param.i_height;

        param.i_threads = X264_ENCODER_THREADS;
        param.b_sliced_threads = true;
        param.i_slice_count = X264_ENCODER_SLICES;

        param.b_deterministic = false;
        //#// param.i_sync_lookahead = 0;
        //#// param.i_lookahead_threads = 0;
        param.b_intra_refresh = 16;
        param.rc.i_lookahead = 0;
        // param.b_cabac = 0;
        param.i_bframe = 0;
        // param.b_open_gop = 4;
        param.i_keyint_max = VIDEO_MAX_KF_H264;
        // param.rc.i_rc_method = X264_RC_CRF; // X264_RC_ABR;
        // param.i_nal_hrd = X264_NAL_HRD_CBR;

        //#// param.i_frame_reference = 1;

        param.b_vfr_input = 1; /* VFR input.  If 1, use timebase and timestamps for ratecontrol purposes.
                                * If 0, use fps only. */
        param.i_timebase_num = 1;       // 1 ms = timebase units = (1/1000)s
        param.i_timebase_den = 1000;   // 1 ms = timebase units = (1/1000)s
        param.b_repeat_headers = 1;
        param.b_annexb = 1;

        param.rc.f_rate_tolerance = VIDEO_F_RATE_TOLERANCE_H264;
        param.rc.i_vbv_buffer_size = VIDEO_BITRATE_INITIAL_VALUE_H264 * VIDEO_BUF_FACTOR_H264;
        param.rc.i_vbv_max_bitrate = VIDEO_BITRATE_INITIAL_VALUE_H264 * 1;
        // param.rc.i_bitrate = VIDEO_BITRATE_INITIAL_VALUE_H264 * VIDEO_BITRATE_FACTOR_H264;

        param.rc.i_qp_min = 3;
        param.rc.i_qp_max = 51; // max quantizer for x264

        vc->h264_enc_bitrate = VIDEO_BITRATE_INITIAL_VALUE_H264 * 1000;

        LOGGER_API_WARNING(av->tox, "vc_init_encoder_h264:vc->h264_enc_bitrate = %d", (int)vc->h264_enc_bitrate);

        param.rc.b_stat_read = 0;
        param.rc.b_stat_write = 0;

#if MIN_LOGGER_LEVEL >= LOGGER_LEVEL_INFO
        param.i_log_level = X264_LOG_ERROR; // X264_LOG_NONE;
#endif

        /* Apply profile restrictions. */

        if ((int)(H264_ENCODER_STARTWITH_PROFILE_HIGH) == 1) {
            if (x264_param_apply_profile(&param,
                                         "high") < 0) { // "baseline", "main", "high", "high10", "high422", "high444"
                // goto fail;
                LOGGER_API_WARNING(av->tox, "h264: setting high encoder failed");
            } else {
                LOGGER_API_WARNING(av->tox, "h264: setting high encoder OK");
            }
        } else {
            if (x264_param_apply_profile(&param,
                                         "baseline") < 0) { // "baseline", "main", "high", "high10", "high422", "high444"
                // goto fail;
                LOGGER_API_WARNING(av->tox, "h264: setting BASELINE encoder failed");
            } else {
                LOGGER_API_WARNING(av->tox, "h264: setting BASELINE encoder OK");
            }
        }

        if (x264_picture_alloc(&(vc->h264_in_pic), param.i_csp, param.i_width, param.i_height) < 0) {
            // goto fail;
        }

        // vc->h264_in_pic.img.plane[0] --> Y
        // vc->h264_in_pic.img.plane[1] --> U
        // vc->h264_in_pic.img.plane[2] --> V

        vc->h264_encoder = x264_encoder_open(&param);

    }
    else
    {

        LOGGER_API_WARNING(av->tox, "x264_software_encoder_used:03");

        vc->h264_encoder = NULL;

        // ------ ffmpeg encoder --------------------------------------------------------------
        // ------ ffmpeg encoder --------------------------------------------------------------
        // ------ ffmpeg encoder --------------------------------------------------------------
        // ------ ffmpeg encoder --------------------------------------------------------------
        // ------ ffmpeg encoder --------------------------------------------------------------

        AVCodec *codec2 = NULL;
        vc->h264_encoder2 = NULL;


    // https://github.com/FFmpeg/FFmpeg/blob/70d25268c21cbee5f08304da95be1f647c630c15/doc/APIchanges#L86
    // Deprecate use of av_register_all()
#if LIBAVCODEC_VERSION_INT < AV_VERSION_INT(58, 9, 100)
        avcodec_register_all();
#endif

        codec2 = NULL;
        codec2 = avcodec_find_encoder_by_name(vc->encoder_codec_used_name); //(H264_WANT_ENCODER_NAME);

        if (!codec2) {
            LOGGER_API_WARNING(av->tox, "codec not found HW Accel H264 on encoder, trying software decoder ...");
            codec2 = avcodec_find_encoder_by_name("libx264");
        } else {
            LOGGER_API_ERROR(av->tox, "FOUND: *HW Accel* H264 encoder: %s", vc->encoder_codec_used_name);
        }

        vc->h264_encoder2 = avcodec_alloc_context3(codec2);

        vc->h264_out_pic2 = av_packet_alloc();

        if ((int)(H264_ENCODER_STARTWITH_PROFILE_HIGH) == 1) {
            av_opt_set(vc->h264_encoder2->priv_data, "profile", "high", 0);
            vc->h264_encoder2->profile               = FF_PROFILE_H264_HIGH; // FF_PROFILE_H264_HIGH;
            // av_opt_set(vc->h264_encoder2->priv_data, "level", "4.0", AV_OPT_SEARCH_CHILDREN);
            // vc->h264_encoder2->level = 40; // 4.0
        } else {
            av_opt_set(vc->h264_encoder2->priv_data, "profile", "baseline", 0);
            vc->h264_encoder2->profile               = FF_PROFILE_H264_BASELINE; // FF_PROFILE_H264_HIGH;
            // av_opt_set(vc->h264_encoder2->priv_data, "level", "4.0", AV_OPT_SEARCH_CHILDREN);
            // vc->h264_encoder2->level = 40; // 4.0
        }

        av_opt_set(vc->h264_encoder2->priv_data, "annex_b", "1", 0);
        av_opt_set(vc->h264_encoder2->priv_data, "repeat_headers", "1", 0);
        // **11** // av_opt_set(vc->h264_encoder2->priv_data, "tune", "zerolatency", 0);
        av_opt_set_int(vc->h264_encoder2->priv_data, "b", VIDEO_BITRATE_INITIAL_VALUE_H264 * 1000, 0);
        av_opt_set_int(vc->h264_encoder2->priv_data, "bitrate", VIDEO_BITRATE_INITIAL_VALUE_H264 * 1000, 0);
        // av_opt_set_int(vc->h264_encoder2->priv_data, "minrate", 100000, 0);
        // av_opt_set_int(vc->h264_encoder2->priv_data, "maxrate", (int)((float)100000 * H264_ENCODE_MAX_BITRATE_OVER_ALLOW), 0);

        av_opt_set_int(vc->h264_encoder2->priv_data, "cbr", true, 0);
        av_opt_set(vc->h264_encoder2->priv_data, "rc", "cbr_ld_hq", 0);
        av_opt_set_int(vc->h264_encoder2->priv_data, "delay", 0, 0);
        // av_opt_set_int(vc->h264_encoder2->priv_data, "rc-lookahead", 0, 0);

        if (strncmp(vc->encoder_codec_used_name, "h264_nvenc", strlen("h264_nvenc")) == 0)
        {
            // av_opt_set(vc->h264_encoder2->priv_data, "preset", "llhq", 0);
            av_opt_set(vc->h264_encoder2->priv_data, "preset", "p3", 0);
            av_opt_set(vc->h264_encoder2->priv_data, "rc", "cbr", 0);
            av_opt_set(vc->h264_encoder2->priv_data, "tune", "ll", 0);
            av_opt_set(vc->h264_encoder2->priv_data, "zerolatency", "true", 0);
        }
        else
        {
            av_opt_set(vc->h264_encoder2->priv_data, "preset", "ultrafast", 0);
        }

        av_opt_set_int(vc->h264_encoder2->priv_data, "bf", 0, 0);
        av_opt_set_int(vc->h264_encoder2->priv_data, "qmin", 3, 0);
        av_opt_set_int(vc->h264_encoder2->priv_data, "qmax", 51, 0);
        av_opt_set(vc->h264_encoder2->priv_data, "forced-idr", "false", 0);
        av_opt_set_int(vc->h264_encoder2->priv_data, "zerolatency", 1, AV_OPT_SEARCH_CHILDREN);
        //y// av_opt_set_int(vc->h264_encoder2->priv_data, "refs", 0, 0);
        av_opt_set(vc->h264_encoder2->priv_data, "no-scenecut", "true", 0);
        av_opt_set(vc->h264_encoder2->priv_data, "strict_gop", "true", 0);

        // HINT: needed for newer 264_nvenc versions
        av_opt_set(vc->h264_encoder2->priv_data, "2pass", "false", 0);

        av_opt_set_int(vc->h264_encoder2->priv_data, "threads", X264_ENCODER_THREADS, 0);

        if (X264_ENCODER_SLICES > 0) {
            av_opt_set(vc->h264_encoder2->priv_data, "sliced_threads", "1", 0);
        } else {
            av_opt_set(vc->h264_encoder2->priv_data, "sliced_threads", "0", 0);
        }

        av_opt_set_int(vc->h264_encoder2->priv_data, "slice_count", X264_ENCODER_SLICES, 0);

        /* put sample parameters */
        vc->h264_encoder2->bit_rate = VIDEO_BITRATE_INITIAL_VALUE_H264 * 1000;
        vc->h264_enc_bitrate = VIDEO_BITRATE_INITIAL_VALUE_H264 * 1000;

        /* resolution must be a multiple of two */
        vc->h264_encoder2->width = 1920;
        vc->h264_encoder2->height = 1080;

        vc->h264_enc_width = vc->h264_encoder2->width;
        vc->h264_enc_height = vc->h264_encoder2->height;

        vc->h264_encoder2->gop_size = VIDEO_MAX_KF_H264;
        // vc->h264_encoder2->keyint_min = VIDEO_MAX_KF_H264;
        vc->h264_encoder2->max_b_frames = 0;
        vc->h264_encoder2->pix_fmt = AV_PIX_FMT_YUV420P;

        vc->h264_encoder2->time_base.num = 1;
        vc->h264_encoder2->time_base.den = 1000;

        // without these it won't work !! ---------------------
        vc->h264_encoder2->time_base = (AVRational) {
            1, 30
        };
        vc->h264_encoder2->framerate = (AVRational) {
            30, 1
        };
        // without these it won't work !! ---------------------

        // vc->h264_encoder2->flags2 |= AV_CODEC_FLAG2_LOCAL_HEADER;
        // vc->h264_encoder2->flags2 |= AV_CODEC_FLAG2_FAST;

        AVDictionary *opts = NULL;

        if (avcodec_open2(vc->h264_encoder2, codec2, &opts) < 0) {
            LOGGER_API_ERROR(av->tox, "could not open codec H264 on encoder");
        }

        av_dict_free(&opts);


        // ------ ffmpeg encoder --------------------------------------------------------------
        // ------ ffmpeg encoder --------------------------------------------------------------
        // ------ ffmpeg encoder --------------------------------------------------------------
        // ------ ffmpeg encoder --------------------------------------------------------------
        // ------ ffmpeg encoder --------------------------------------------------------------

    }



//    goto good;

//fail:
//    vc->h264_encoder = NULL;

//good:

    // ENCODER -------


    // DECODER -------
    AVCodec *codec = NULL;
    vc->h264_decoder = NULL;

// https://github.com/FFmpeg/FFmpeg/blob/70d25268c21cbee5f08304da95be1f647c630c15/doc/APIchanges#L86
// Deprecate use of av_register_all()
#if LIBAVCODEC_VERSION_INT < AV_VERSION_INT(58, 9, 100)
    avcodec_register_all();
#endif

    codec = NULL;

#ifdef RAPI_HWACCEL_DEC

    codec = avcodec_find_decoder_by_name(H264_WANT_DECODER_NAME);

    if (!codec) {
        LOGGER_API_WARNING(av->tox, "codec not found HW Accel H264 on decoder, trying software decoder ...");
        codec = avcodec_find_decoder(AV_CODEC_ID_H264);
    } else {
        LOGGER_API_WARNING(av->tox, "FOUND: *HW Accel* H264 on decoder");
    }

#else
    codec = avcodec_find_decoder(AV_CODEC_ID_H264);
#endif


    if (!codec) {
        LOGGER_API_WARNING(av->tox, "codec not found H264 on decoder");
        assert(!"codec not found H264 on decoder");
    }

    vc->h264_decoder = avcodec_alloc_context3(codec);

    if (codec) {
#if LIBAVCODEC_VERSION_MAJOR < 60
        if (codec->capabilities & AV_CODEC_CAP_TRUNCATED) {
            vc->h264_decoder->flags |= AV_CODEC_FLAG_TRUNCATED; /* we do not send complete frames */
        }
#endif
        if (codec->capabilities & AV_CODEC_FLAG_LOW_DELAY) {
            vc->h264_decoder->flags |= AV_CODEC_FLAG_LOW_DELAY;
        }

        // vc->h264_decoder->flags |= AV_CODEC_FLAG_OUTPUT_CORRUPT;

#ifdef AV_CODEC_FLAG2_SHOW_ALL
        vc->h264_decoder->flags |= AV_CODEC_FLAG2_SHOW_ALL;
#else
        LOGGER_API_WARNING(av->tox, "!! AV_CODEC_FLAG2_SHOW_ALL not defined by ffmpeg version !!");
#endif
        // vc->h264_decoder->flags2 |= AV_CODEC_FLAG2_FAST;
        // vc->h264_decoder->flags |= AV_CODEC_FLAG_TRUNCATED;
        // vc->h264_decoder->flags2 |= AV_CODEC_FLAG2_CHUNKS;

        if (H264_DECODER_THREADS > 0) {
            if (codec->capabilities & AV_CODEC_CAP_SLICE_THREADS) {
                vc->h264_decoder->thread_count = H264_DECODER_THREADS;
                vc->h264_decoder->thread_type = FF_THREAD_SLICE;
                vc->h264_decoder->active_thread_type = FF_THREAD_SLICE;
            }

            if (H264_DECODER_THREAD_FRAME_ACTIVE == 1) {
                if (codec->capabilities & AV_CODEC_CAP_FRAME_THREADS) {
                    vc->h264_decoder->thread_count = H264_DECODER_THREADS;
                    vc->h264_decoder->thread_type |= FF_THREAD_FRAME;
                    vc->h264_decoder->active_thread_type |= FF_THREAD_FRAME;
                }
            }
        }

#if (defined (HW_CODEC_CONFIG_RPI3_TBW_TV) || defined (HW_CODEC_CONFIG_RPI3_TBW_BIDI)) && defined (RAPI_HWACCEL_DEC)
        LOGGER_API_WARNING(av->tox, "setting up h264_mmal decoder ...");
        av_opt_set_int(vc->h264_decoder->priv_data, "extra_buffers", 1, AV_OPT_SEARCH_CHILDREN);
        av_opt_set_int(vc->h264_decoder->priv_data, "extra_decoder_buffers", 1, AV_OPT_SEARCH_CHILDREN);
        LOGGER_API_WARNING(av->tox, "extra_buffers, extra_decoder_buffers");
#endif

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#if LIBAVCODEC_VERSION_INT < AV_VERSION_INT(59, 0, 0)
        vc->h264_decoder->refcounted_frames = 0;
#endif
        /*   When AVCodecContext.refcounted_frames is set to 0, the returned
        *             reference belongs to the decoder and is valid only until the
        *             next call to this function or until closing or flushing the
        *             decoder. The caller may not write to it.
        */
#pragma GCC diagnostic pop

        vc->h264_decoder->delay = 0;
        av_opt_set_int(vc->h264_decoder->priv_data, "delay", 0, AV_OPT_SEARCH_CHILDREN);

        vc->h264_decoder->time_base = (AVRational) {
            1, 30
        };
        vc->h264_decoder->framerate = (AVRational) {
            30, 1
        };




#ifdef _TRIFA_CODEC_DECODER_

        LOGGER_API_WARNING(av->tox, "setting up h264_mediacodec decoder ...");


        const uint8_t sps[] = {0x00, 0x00, 0x00, 0x01,      0x67, 0x42, 0xC0, 0x1E, 0xA6, 0x81, 0xE0, 0x51, 0xA1};
        // const uint8_t sps[] = {0x00, 0x00, 0x00, 0x01, 0x67, 0x42, 0x80, 0x0C, 0xE4, 0x40, 0xA0, 0xFD, 0x00, 0xDA, 0x14, 0x26, 0xA0};
        const uint8_t pps[] = {0x00, 0x00, 0x00, 0x01,      0x68, 0xCE, 0x38, 0x80};
        const size_t sps_pps_size = sizeof(sps) + sizeof(pps);

        vc->h264_decoder->extradata = (uint8_t *)av_mallocz(sps_pps_size + AV_INPUT_BUFFER_PADDING_SIZE);
        vc->h264_decoder->extradata_size = sps_pps_size;
        // memset(&vc->h264_decoder->extradata[vc->h264_decoder->extradata_size], 0, AV_INPUT_BUFFER_PADDING_SIZE);
        memcpy(vc->h264_decoder->extradata, sps, sizeof(sps));
        memcpy(vc->h264_decoder->extradata + sizeof(sps), pps, sizeof(pps));


        vc->h264_decoder->codec_type = AVMEDIA_TYPE_VIDEO;
        vc->h264_decoder->codec_id   = AV_CODEC_ID_H264;

        if (codec->capabilities & AV_CODEC_CAP_SLICE_THREADS) {
            vc->h264_decoder->thread_count = 1;
            vc->h264_decoder->thread_type = FF_THREAD_SLICE;
            vc->h264_decoder->active_thread_type = FF_THREAD_SLICE;
        }

        //if (codec->capabilities & AV_CODEC_CAP_FRAME_THREADS) {
        //    vc->h264_decoder->thread_count = 1;
        //    vc->h264_decoder->thread_type |= FF_THREAD_FRAME;
        //    vc->h264_decoder->active_thread_type |= FF_THREAD_FRAME;
        //}

        /*
            vc->h264_decoder->codec_tag  = 0x31637661; // ('1'<<24) + ('c'<<16) + ('v'<<8) + 'a';
            vc->h264_decoder->bit_rate              = 2500 * 1000;
            // codec->bits_per_coded_sample = par->bits_per_coded_sample;
            vc->h264_decoder->bits_per_raw_sample   = 8;
            vc->h264_decoder->profile               = FF_PROFILE_H264_HIGH;
            vc->h264_decoder->level                 = 40;
            vc->h264_decoder->has_b_frames          = 2;
        */


        vc->h264_decoder->pix_fmt                = AV_PIX_FMT_YUV420P;
        vc->h264_decoder->width                  = 480;
        vc->h264_decoder->height                 = 640;

        /*
            codec->field_order            = par->field_order;
            codec->color_range            = par->color_range;
            codec->color_primaries        = par->color_primaries;
            codec->color_trc              = par->color_trc;
            codec->colorspace             = par->color_space;
            codec->chroma_sample_location = par->chroma_location;
            codec->sample_aspect_ratio    = par->sample_aspect_ratio;
            codec->has_b_frames           = par->video_delay;
        */

        LOGGER_API_WARNING(av->tox, "setting up h264_mediacodec decoder ... DONE");

        av_log_set_level(AV_LOG_ERROR);

#endif



        if (avcodec_open2(vc->h264_decoder, codec, NULL) < 0) {
            LOGGER_API_WARNING(av->tox, "could not open codec H264 on decoder");
            assert(!"could not open codec H264 on decoder");
        }

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#if LIBAVCODEC_VERSION_INT < AV_VERSION_INT(59, 0, 0)
        vc->h264_decoder->refcounted_frames = 0;
#endif
#pragma GCC diagnostic pop
        /*   When AVCodecContext.refcounted_frames is set to 0, the returned
        *             reference belongs to the decoder and is valid only until the
        *             next call to this function or until closing or flushing the
        *             decoder. The caller may not write to it.
        */
    }


    // DECODER -------

    return vc;
}

int vc_reconfigure_encoder_h264(Logger *log, VCSession *vc, uint32_t bit_rate,
                                uint16_t width, uint16_t height,
                                int16_t kf_max_dist)
{
    if (!vc) {
        return -1;
    }

    if ((vc->h264_enc_width == width) &&
            (vc->h264_enc_height == height) &&
            (vc->video_rc_max_quantizer == vc->video_rc_max_quantizer_prev) &&
            (vc->video_rc_min_quantizer == vc->video_rc_min_quantizer_prev) &&
            (vc->video_encoder_coded_used == vc->video_encoder_coded_used_prev) &&
            (vc->h264_enc_bitrate != bit_rate) &&
            (kf_max_dist != -2)) {
        // only bit rate changed

        if (vc->h264_encoder) {

            x264_param_t param;
            x264_encoder_parameters(vc->h264_encoder, &param);

            // LOGGER_DEBUG(log, "vc_reconfigure_encoder_h264:vb=%d [bitrate only]", (int)(bit_rate / 1000));

            param.rc.f_rate_tolerance = VIDEO_F_RATE_TOLERANCE_H264;
            param.rc.i_vbv_buffer_size = (bit_rate / 1000) * VIDEO_BUF_FACTOR_H264;
            param.rc.i_vbv_max_bitrate = (bit_rate / 1000) * 1;

            // param.rc.i_bitrate = (bit_rate / 1000) * VIDEO_BITRATE_FACTOR_H264;
            vc->h264_enc_bitrate = bit_rate;

            int res = x264_encoder_reconfig(vc->h264_encoder, &param);
        } else {

            if (vc->x264_software_encoder_used == 0)
            {
                vc->h264_encoder2->bit_rate = bit_rate;
                vc->h264_enc_bitrate = bit_rate;

                // LOGGER_API_WARNING(vc->av->tox, "vc_reconfigure_encoder_h264:1:bit_rate = %d vc->h264_enc_bitrate = %d", (int)bit_rate, (int)vc->h264_enc_bitrate);

                av_opt_set_int(vc->h264_encoder2->priv_data, "b", bit_rate, 0);
                av_opt_set_int(vc->h264_encoder2->priv_data, "bitrate", bit_rate, 0);
                // av_opt_set_int(vc->h264_encoder2->priv_data, "minrate", bit_rate, 0);
                // av_opt_set_int(vc->h264_encoder2->priv_data, "maxrate", (int)((float)bit_rate * H264_ENCODE_MAX_BITRATE_OVER_ALLOW), 0);
            }
        }


    } else {
        if ((vc->h264_enc_width != width) ||
                (vc->h264_enc_height != height) ||
                (vc->h264_enc_bitrate != bit_rate) ||
                (vc->video_rc_max_quantizer != vc->video_rc_max_quantizer_prev) ||
                (vc->video_rc_min_quantizer != vc->video_rc_min_quantizer_prev) ||
                (vc->video_encoder_coded_used != vc->video_encoder_coded_used_prev) ||
                (kf_max_dist == -2)
           ) {
            // input image size changed

            if (vc->x264_software_encoder_used == 1) {
                if (vc->h264_encoder) {

                    x264_param_t param;

                    if ((int)(H264_ENCODER_STARTWITH_PROFILE_HIGH) == 1) {
                        if (x264_param_default_preset(&param, "superfast", "zerolatency,fastdecode") < 0) {
                            // goto fail;
                        }
                    } else {
                        if (x264_param_default_preset(&param, "ultrafast", "zerolatency,fastdecode") < 0) {
                            // goto fail;
                        }
                    }

                    /* Configure non-default params */
                    // param.i_bitdepth = 8;
                    param.i_csp = X264_CSP_I420;
                    param.i_width  = width;
                    param.i_height = height;
                    vc->h264_enc_width = param.i_width;
                    vc->h264_enc_height = param.i_height;
                    param.i_threads = X264_ENCODER_THREADS;
                    param.b_sliced_threads = true;
                    param.i_slice_count = X264_ENCODER_SLICES;

                    param.b_deterministic = false;
                    //#// param.i_sync_lookahead = 0;
                    //#// param.i_lookahead_threads = 0;
                    param.b_intra_refresh = 16;
                    param.rc.i_lookahead = 0;
                    // param.b_cabac = 0;
                    param.i_bframe = 0;
                    // param.b_open_gop = 4;
                    param.i_keyint_max = VIDEO_MAX_KF_H264;
                    // param.rc.i_rc_method = X264_RC_ABR;
                    //#// param.i_frame_reference = 1;

                    param.b_vfr_input = 1; /* VFR input.  If 1, use timebase and timestamps for ratecontrol purposes.
                                * If 0, use fps only. */
                    param.i_timebase_num = 1;       // 1 ms = timebase units = (1/1000)s
                    param.i_timebase_den = 1000;   // 1 ms = timebase units = (1/1000)s
                    param.b_repeat_headers = 1;
                    param.b_annexb = 1;

                    // LOGGER_ERROR(log, "vc_reconfigure_encoder_h264:vb=%d", (int)(bit_rate / 1000));

                    param.rc.f_rate_tolerance = VIDEO_F_RATE_TOLERANCE_H264;
                    param.rc.i_vbv_buffer_size = (bit_rate / 1000) * VIDEO_BUF_FACTOR_H264;
                    param.rc.i_vbv_max_bitrate = (bit_rate / 1000) * 1;

                    if ((vc->video_rc_min_quantizer >= 0) &&
                            (vc->video_rc_min_quantizer < vc->video_rc_max_quantizer) &&
                            (vc->video_rc_min_quantizer < 51)) {
                        param.rc.i_qp_min = vc->video_rc_min_quantizer;
                    }

                    if ((vc->video_rc_max_quantizer >= 0) &&
                            (vc->video_rc_min_quantizer < vc->video_rc_max_quantizer) &&
                            (vc->video_rc_max_quantizer < 51)) {
                        param.rc.i_qp_max = vc->video_rc_max_quantizer;
                    }

                    // param.rc.i_bitrate = (bit_rate / 1000) * VIDEO_BITRATE_FACTOR_H264;
                    vc->h264_enc_bitrate = bit_rate;

                    // LOGGER_API_WARNING(vc->av->tox, "vc_reconfigure_encoder_h264:2:bit_rate = %d vc->h264_enc_bitrate = %d", (int)bit_rate, (int)vc->h264_enc_bitrate);


                    param.rc.b_stat_read = 0;
                    param.rc.b_stat_write = 0;

#if MIN_LOGGER_LEVEL >= LOGGER_LEVEL_INFO
                    param.i_log_level = X264_LOG_ERROR; // X264_LOG_NONE;
#endif

                    /* Apply profile restrictions. */
                    if ((int)(H264_ENCODER_STARTWITH_PROFILE_HIGH) == 1) {
                        if (x264_param_apply_profile(&param,
                                                     "high") < 0) { // "baseline", "main", "high", "high10", "high422", "high444"
                            // goto fail;
                            // LOGGER_WARNING(log, "h264: setting high encoder failed (2)");
                        } else {
                            // LOGGER_WARNING(log, "h264: setting high encoder OK (2)");
                        }
                    } else {
                        if (x264_param_apply_profile(&param,
                                                     "baseline") < 0) { // "baseline", "main", "high", "high10", "high422", "high444"
                            // goto fail;
                            // LOGGER_WARNING(log, "h264: setting BASELINE encoder failed (2)");
                        } else {
                            // LOGGER_WARNING(log, "h264: setting BASELINE encoder OK (2)");
                        }
                    }

                    // LOGGER_ERROR(log, "H264: reconfigure encoder:001: w:%d h:%d w_new:%d h_new:%d BR:%d\n",
                    //              vc->h264_enc_width,
                    //              vc->h264_enc_height,
                    //              width,
                    //              height,
                    //              (int)bit_rate);

                    // free old stuff ---------
                    x264_encoder_close(vc->h264_encoder);
                    x264_picture_clean(&(vc->h264_in_pic));
                    // free old stuff ---------

                    // alloc with new values -------
                    if (x264_picture_alloc(&(vc->h264_in_pic), param.i_csp, param.i_width, param.i_height) < 0) {
                        // goto fail;
                    }

                    vc->h264_encoder = x264_encoder_open(&param);
                    // alloc with new values -------

                    vc->video_rc_max_quantizer_prev = vc->video_rc_max_quantizer;
                    vc->video_rc_min_quantizer_prev = vc->video_rc_min_quantizer;

                }

            } else {

                // --- ffmpeg encoder ---
                avcodec_free_context(&vc->h264_encoder2);


                AVCodec *codec2 = NULL;
                vc->h264_encoder2 = NULL;

// https://github.com/FFmpeg/FFmpeg/blob/70d25268c21cbee5f08304da95be1f647c630c15/doc/APIchanges#L86
// Deprecate use of av_register_all()
#if LIBAVCODEC_VERSION_INT < AV_VERSION_INT(58, 9, 100)
                avcodec_register_all();
#endif

                codec2 = NULL;
                codec2 = avcodec_find_encoder_by_name(vc->encoder_codec_used_name); //(H264_WANT_ENCODER_NAME);

                if (!codec2) {
                    // LOGGER_WARNING(log, "codec not found HW Accel H264 on encoder, trying software decoder ...");
                    codec2 = avcodec_find_encoder_by_name("libx264");
                } else {
                    // LOGGER_ERROR(log, "FOUND: *HW Accel* H264 encoder: %s", vc->encoder_codec_used_name);
                }

                vc->h264_encoder2 = avcodec_alloc_context3(codec2);

                if ((int)(H264_ENCODER_STARTWITH_PROFILE_HIGH) == 1) {
                    av_opt_set(vc->h264_encoder2->priv_data, "profile", "high", 0);
                    vc->h264_encoder2->profile               = FF_PROFILE_H264_HIGH; // FF_PROFILE_H264_HIGH;
                    // av_opt_set(vc->h264_encoder2->priv_data, "level", "4.0", AV_OPT_SEARCH_CHILDREN);
                    // vc->h264_encoder2->level = 40; // 4.0
                    // LOGGER_WARNING(log, "switching H264 encoder profile ... HIGH");

                } else {
                    av_opt_set(vc->h264_encoder2->priv_data, "profile", "baseline", 0);
                    vc->h264_encoder2->profile               = FF_PROFILE_H264_BASELINE; // FF_PROFILE_H264_HIGH;
                    // av_opt_set(vc->h264_encoder2->priv_data, "level", "4.0", AV_OPT_SEARCH_CHILDREN);
                    // vc->h264_encoder2->level = 40; // 4.0
                    // LOGGER_WARNING(log, "switching H264 encoder profile ... baseline");
                }

                av_opt_set(vc->h264_encoder2->priv_data, "annex_b", "1", 0);
                av_opt_set(vc->h264_encoder2->priv_data, "repeat_headers", "1", 0);
                // **11** // av_opt_set(vc->h264_encoder2->priv_data, "tune", "zerolatency", 0);
                av_opt_set_int(vc->h264_encoder2->priv_data, "b", bit_rate, 0);
                av_opt_set_int(vc->h264_encoder2->priv_data, "bitrate", bit_rate, 0);
                // av_opt_set_int(vc->h264_encoder2->priv_data, "minrate", bit_rate, 0);
                // av_opt_set_int(vc->h264_encoder2->priv_data, "maxrate", (int)((float)bit_rate * H264_ENCODE_MAX_BITRATE_OVER_ALLOW), 0);

                av_opt_set_int(vc->h264_encoder2->priv_data, "cbr", true, 0);
                av_opt_set(vc->h264_encoder2->priv_data, "rc", "cbr_ld_hq", 0);
                av_opt_set_int(vc->h264_encoder2->priv_data, "delay", 0, 0);
                // av_opt_set_int(vc->h264_encoder2->priv_data, "rc-lookahead", 0, 0);

                if (strncmp(vc->encoder_codec_used_name, "h264_nvenc", strlen("h264_nvenc")) == 0)
                {
                    // av_opt_set(vc->h264_encoder2->priv_data, "preset", "llhq", 0);
                    av_opt_set(vc->h264_encoder2->priv_data, "preset", "p3", 0);
                    av_opt_set(vc->h264_encoder2->priv_data, "rc", "cbr", 0);
                    av_opt_set(vc->h264_encoder2->priv_data, "tune", "ll", 0);
                    av_opt_set(vc->h264_encoder2->priv_data, "zerolatency", "true", 0);
                }
                else
                {
                    av_opt_set(vc->h264_encoder2->priv_data, "preset", "ultrafast", 0);
                }

                av_opt_set_int(vc->h264_encoder2->priv_data, "bf", 0, 0);
                av_opt_set_int(vc->h264_encoder2->priv_data, "qmin", 3, 0);
                av_opt_set_int(vc->h264_encoder2->priv_data, "qmax", 51, 0);
                av_opt_set(vc->h264_encoder2->priv_data, "forced-idr", "false", 0);
                av_opt_set_int(vc->h264_encoder2->priv_data, "zerolatency", 1, AV_OPT_SEARCH_CHILDREN);
                //y// av_opt_set_int(vc->h264_encoder2->priv_data, "refs", 1, 0);
                av_opt_set(vc->h264_encoder2->priv_data, "no-scenecut", "true", 0);
                av_opt_set(vc->h264_encoder2->priv_data, "strict_gop", "true", 0);

                // HINT: needed for newer 264_nvenc versions
                av_opt_set(vc->h264_encoder2->priv_data, "2pass", "false", 0);

                av_opt_set_int(vc->h264_encoder2->priv_data, "threads", X264_ENCODER_THREADS, 0);

                if (X264_ENCODER_SLICES > 0) {
                    av_opt_set(vc->h264_encoder2->priv_data, "sliced_threads", "1", 0);
                } else {
                    av_opt_set(vc->h264_encoder2->priv_data, "sliced_threads", "0", 0);
                }

                av_opt_set_int(vc->h264_encoder2->priv_data, "slice_count", X264_ENCODER_SLICES, 0);

                /* put sample parameters */
                vc->h264_encoder2->bit_rate = bit_rate;
                vc->h264_enc_bitrate = bit_rate;

                /* resolution must be a multiple of two */
                vc->h264_encoder2->width = width;
                vc->h264_encoder2->height = height;

                vc->h264_enc_width = vc->h264_encoder2->width;
                vc->h264_enc_height = vc->h264_encoder2->height;

                vc->h264_encoder2->gop_size = VIDEO_MAX_KF_H264;
                // vc->h264_encoder2->keyint_min = VIDEO_MAX_KF_H264;
                vc->h264_encoder2->max_b_frames = 0;
                vc->h264_encoder2->pix_fmt = AV_PIX_FMT_YUV420P;

                vc->h264_encoder2->time_base.num = 1;
                vc->h264_encoder2->time_base.den = 1000;

                // without these it won't work !! ---------------------
                vc->h264_encoder2->time_base = (AVRational) {
                    1, 30
                };
                vc->h264_encoder2->framerate = (AVRational) {
                    30, 1
                };
                // without these it won't work !! ---------------------

                /*
                av_opt_get(pCodecCtx->priv_data,"preset",0,(uint8_t **)&val_str);
                        printf("preset val: %s\n",val_str);
                        av_opt_get(pCodecCtx->priv_data,"tune",0,(uint8_t **)&val_str);
                        printf("tune val: %s\n",val_str);
                        av_opt_get(pCodecCtx->priv_data,"profile",0,(uint8_t **)&val_str);
                        printf("profile val: %s\n",val_str);
                av_free(val_str);
                */

                // vc->h264_encoder2->flags2 |= AV_CODEC_FLAG2_LOCAL_HEADER;
                // vc->h264_encoder2->flags2 |= AV_CODEC_FLAG2_FAST;

                AVDictionary *opts = NULL;

                if (avcodec_open2(vc->h264_encoder2, codec2, NULL) < 0) {
                    // LOGGER_ERROR(log, "could not open codec H264 on encoder");
                }

                av_dict_free(&opts);

                // --- ffmpeg encoder ---
            }
        }
    }

    return 0;
}

void get_info_from_sps(const Tox *tox, VCSession *vc, const Logger *log,
                       const uint8_t data[], const uint32_t data_len)
{

    if (data_len > 7) {
        // LOGGER_DEBUG(log, "SPS:len=%d bytes:%d %d %d %d %d %d %d %d", data_len, data[0], data[1], data[2], data[3], data[4],
        //              data[5], data[6], data[7]);

        if (
            (data[0] == 0x00)
            &&
            (data[1] == 0x00)
            &&
            (data[2] == 0x00)
            &&
            (data[3] == 0x01)
            &&
            ((data[4] & 0x1F) == 7) // only the lower 5bits of the 4th byte denote the NAL type
            // 7 --> SPS
            // 8 --> PPS
            // (data[4] == 0x67)
        ) {
            // parse only every 5 seconds
            if ((vc->last_parsed_h264_sps_ts + 5000) < current_time_monotonic(vc->av->toxav_mono_time)) {
                vc->last_parsed_h264_sps_ts = current_time_monotonic(vc->av->toxav_mono_time);

                // we found a NAL unit containing the SPS
                uint8_t h264_profile = data[5];
                uint8_t h264_constraint_set0_flag = ((data[6] >> 3)  & 0x01);
                uint8_t h264_constraint_set3_flag = (data[6]  & 0x01);
                uint8_t h264_level = data[7];

                if ((h264_profile == 66) && (h264_constraint_set3_flag = 0)) {
                    // LOGGER_DEBUG(log, "profile=%s level=%d", "baseline", h264_level);
                    vc->parsed_h264_sps_profile_i = h264_profile;
                } else if ((h264_profile == 66) && (h264_constraint_set3_flag = 1)) {
                    // LOGGER_DEBUG(log, "profile=%s level=%d", "contrained baseline", h264_level);
                    vc->parsed_h264_sps_profile_i = h264_profile;
                } else if ((h264_profile == 77) && (h264_constraint_set0_flag = 0)) {
                    // LOGGER_DEBUG(log, "profile=%s level=%d", "main", h264_level);
                    vc->parsed_h264_sps_profile_i = h264_profile;
                } else if ((h264_profile == 77) && (h264_constraint_set0_flag = 1)) {
                    // LOGGER_DEBUG(log, "profile=%s level=%d", "extended", h264_level);
                    vc->parsed_h264_sps_profile_i = h264_profile;
                } else if (h264_profile == 100) {
                    // LOGGER_DEBUG(log, "profile=%s level=%d", "high", h264_level);
                    vc->parsed_h264_sps_profile_i = h264_profile;
                } else if (h264_profile == 110) {
                    // LOGGER_DEBUG(log, "profile=%s level=%d", "high10", h264_level);
                    vc->parsed_h264_sps_profile_i = h264_profile;
                } else if (h264_profile == 122) {
                    // LOGGER_DEBUG(log, "profile=%s level=%d", "high422", h264_level);
                    vc->parsed_h264_sps_profile_i = h264_profile;
                } else if (h264_profile == 244) {
                    // LOGGER_DEBUG(log, "profile=%s level=%d", "high444", h264_level);
                    vc->parsed_h264_sps_profile_i = h264_profile;
                } else {
                    // LOGGER_DEBUG(log, "profile=%s level=%d", "unkwn", h264_level);
                    vc->parsed_h264_sps_profile_i = 0;
                }

                vc->parsed_h264_sps_level_i = h264_level;
            }
        }
    }
}

//static int32_t global_first_video_frame_data = 0;
//static int32_t global_decoder_delay_counter = 0;

void decode_frame_h264(VCSession *vc, Tox *tox, uint8_t skip_video_flag, uint64_t *a_r_timestamp,
                       uint64_t *a_l_timestamp,
                       uint64_t *v_r_timestamp, uint64_t *v_l_timestamp,
                       const struct RTPHeader *header_v3,
                       struct RTPMessage *p, vpx_codec_err_t rc,
                       uint32_t full_data_len,
                       uint8_t *ret_value)
{

    LOGGER_API_DEBUG(vc->av->tox, "decode_frame_h264:fnum=%d,len=%d", vc->friend_number, full_data_len);

    if (p == NULL) {
        LOGGER_API_DEBUG(vc->av->tox, "decode_frame_h264:NO data");
        return;
    }

    if (full_data_len < 1) {
        LOGGER_API_DEBUG(vc->av->tox, "decode_frame_h264:not enough data");
        free(p);
        p = NULL;
        return;
    }

    if (vc->h264_decoder == NULL) {
        LOGGER_API_DEBUG(vc->av->tox, "vc->h264_decoder:not ready");
        free(p);
        p = NULL;
        return;
    }


    if (vc->vcb_h264 != NULL) {
        // call callback function to give H264 buffer directly to the client
        vc->vcb_h264(vc->av, vc->friend_number, p->data, full_data_len, vc->vcb_h264_user_data);

        free(p);
        p = NULL;
        return;
    }

    if (vc->global_decode_first_frame_got == 0)
    {
        if (vc->global_decode_first_frame_delayed_by == 0)
        {
            vc->global_decode_first_frame_delayed_ms = current_time_monotonic(vc->av->toxav_mono_time);
        }
        vc->global_decode_first_frame_delayed_by++;
    }

    if (p) {
        get_info_from_sps(tox, vc, vc->log, p->data, full_data_len);
    }

    /*
     For decoding, call avcodec_send_packet() to give the decoder raw
          compressed data in an AVPacket.


          For decoding, call avcodec_receive_frame(). On success, it will return
          an AVFrame containing uncompressed audio or video data.


     *   Repeat this call until it returns AVERROR(EAGAIN) or an error. The
     *   AVERROR(EAGAIN) return value means that new input data is required to
     *   return new output. In this case, continue with sending input. For each
     *   input frame/packet, the codec will typically return 1 output frame/packet,
     *   but it can also be 0 or more than 1.

     */

    AVPacket *compr_data = NULL;
    compr_data = av_packet_alloc();

    if (compr_data == NULL) {
        LOGGER_API_DEBUG(vc->av->tox, "av_packet_alloc:ERROR");
        free(p);
        p = NULL;
        return;
    }

    uint64_t h_frame_record_timestamp = header_v3->frame_record_timestamp;

#if 0
    compr_data->pts = AV_NOPTS_VALUE;
    compr_data->dts = AV_NOPTS_VALUE;

    compr_data->duration = 0;
    compr_data->post = -1;
#endif

    compr_data->data = p->data;
    compr_data->size = (int)full_data_len; // hmm, "int" again

    if (header_v3->frame_record_timestamp > 0) {
        LOGGER_API_DEBUG(vc->av->tox, "in_pts:%lu", header_v3->frame_record_timestamp);
        compr_data->dts = (int64_t)(header_v3->frame_record_timestamp) - 1;
        compr_data->pts = (int64_t)(header_v3->frame_record_timestamp);
        compr_data->duration = 0; // (int64_t)(header_v3->frame_record_timestamp) + 1; // 0;
    }

    /* ------------------------------------------------------- */
    /* ------------------------------------------------------- */
    /* HINT: this is the only part that takes all the time !!! */
    /* HINT: this is the only part that takes all the time !!! */
    /* HINT: this is the only part that takes all the time !!! */


    /* ------------------------------------------------------- */
    /* ------------------------------------------------------- */
    // The input buffer, avpkt->data must be AV_INPUT_BUFFER_PADDING_SIZE larger than the actual
    // read bytes because some optimized bitstream readers read 32 or 64 bits at once and
    // could read over the end.
    /* ------------------------------------------------------- */
    /* ------------------------------------------------------- */

    int result_send_packet = avcodec_send_packet(vc->h264_decoder, compr_data);

    if (result_send_packet != 0) {
        LOGGER_API_DEBUG(vc->av->tox, "avcodec_send_packet:ERROR=%d", result_send_packet);
        av_packet_free(&compr_data);
        free(p);
        p = NULL;
        return;
    }

    /* HINT: this is the only part that takes all the time !!! */
    /* HINT: this is the only part that takes all the time !!! */
    /* HINT: this is the only part that takes all the time !!! */
    /* ------------------------------------------------------- */
    /* ------------------------------------------------------- */


    int ret_ = 0;

    while (ret_ >= 0) {

        // start_time_ms = current_time_monotonic(vc->av->toxav_mono_time);
        AVFrame *frame = av_frame_alloc();

        if (frame == NULL) {
            // stop decoding
            break;
        }

        ret_ = avcodec_receive_frame(vc->h264_decoder, frame);

        if (ret_ == AVERROR(EAGAIN) || ret_ == AVERROR_EOF) {
            // error
            av_frame_free(&frame);
            break;
        } else if (ret_ < 0) {
            // Error during decoding
            av_frame_free(&frame);
            break;
        } else if (ret_ == 0) {

            /*
                pkt_pts
                PTS copied from the AVPacket that was decoded to produce this frame.

                pkt_dts
                DTS copied from the AVPacket that triggered returning this frame.
            */

        if (vc->global_decode_first_frame_got == 0)
        {
            vc->global_decode_first_frame_got = 1;
            vc->global_decode_first_frame_delayed_ms =
                current_time_monotonic(vc->av->toxav_mono_time) - vc->global_decode_first_frame_delayed_ms;
            LOGGER_API_DEBUG(vc->av->tox, "X264 decoder delay: %d f, %d ms",
                    (vc->global_decode_first_frame_delayed_by - 1),
                    (int)vc->global_decode_first_frame_delayed_ms);
        }


            // calculate the real play delay (from toxcore-in to toxcore-out)
            // this seems to give incorrect values :-(
            if (header_v3->frame_record_timestamp > 0) {

                /*

                MMAL H264 Decoder - problem ?
                =============================

                 fps    ms delay    ms between frames   frames cached
                ---------------------------------------------------------
                 10     450         100                 ~4.5
                 20     230         50                  ~4.6
                 25     190         40                  ~4.75

                */

                // give back h264 decoder delay value to vc_iterate()

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#if LIBAVCODEC_VERSION_INT > AV_VERSION_INT(59, 0, 0)
                int32_t delta_value = (int32_t)(h_frame_record_timestamp - frame->pts);
#else
                int32_t delta_value = (int32_t)(h_frame_record_timestamp - frame->pkt_pts);
#endif

#if LIBAVCODEC_VERSION_INT > AV_VERSION_INT(59, 0, 0)
                LOGGER_API_DEBUG(vc->av->tox, "out_pts:%lu %lu %ld %ld",
                        frame->pts, frame->pkt_dts, frame->best_effort_timestamp, frame->pkt_pos);
#endif

                LOGGER_API_DEBUG(vc->av->tox, "dec:XX:03:%d %d %d %d %d",
                        delta_value,
                        (int)h_frame_record_timestamp,

#if LIBAVCODEC_VERSION_INT > AV_VERSION_INT(59, 0, 0)
                        (int)frame->pts,
#else
                        (int)frame->pkt_pts,
#endif

                        (int)frame->pkt_dts,
                        (int)frame->pts);
#pragma GCC diagnostic pop

                if ((delta_value >= 0) && (delta_value <= 1000))
                {
                    vc->video_decoder_caused_delay_ms = delta_value;
                    LOGGER_API_DEBUG(vc->av->tox, "dec:1:delta_value=%d", vc->video_decoder_caused_delay_ms);
                }
                else if (delta_value == -1)
                {
                    // since we do NOT have any idea how long the decoder delays frames,
                    // and the decoder will lie to us, we just assume some random value
                    // that works for our use cases (decoding on andriod via MediaCodec)
                    vc->video_decoder_caused_delay_ms = 1;
                    LOGGER_API_DEBUG(vc->av->tox, "dec:2:delta_value=%d", vc->video_decoder_caused_delay_ms);
                }

                // calc mean value
                vc->video_decoder_caused_delay_ms_array[vc->video_decoder_caused_delay_ms_array_index] = vc->video_decoder_caused_delay_ms;
                vc->video_decoder_caused_delay_ms_array_index = (vc->video_decoder_caused_delay_ms_array_index + 1) %
                        VIDEO_DECODER_CAUSED_DELAY_MS_ENTRIES;

                uint32_t mean_value = 0;

                for (int k = 0; k < VIDEO_DECODER_CAUSED_DELAY_MS_ENTRIES; k++) {
                    mean_value = mean_value + vc->video_decoder_caused_delay_ms_array[k];
                }

                if (mean_value == 0) {
                    vc->video_decoder_caused_delay_ms_mean_value = 0;
                } else {
                    vc->video_decoder_caused_delay_ms_mean_value = (mean_value * 10) / (VIDEO_DECODER_CAUSED_DELAY_MS_ENTRIES * 10);
                }

                LOGGER_API_DEBUG(vc->av->tox, "dec:video_decoder_caused_delay_ms_mean_value=%d",
                        vc->video_decoder_caused_delay_ms_mean_value);

            }

            // start_time_ms = current_time_monotonic(vc->av->toxav_mono_time);
            if ((frame->data[0] != NULL) && (frame->data[1] != NULL) && (frame->data[2] != NULL)) {

// -------- DEBUG:AUDIO/VIDEO DELAY/LATENCY --------
// -------- DEBUG:AUDIO/VIDEO DELAY/LATENCY --------
// -------- DEBUG:AUDIO/VIDEO DELAY/LATENCY --------
                *v_r_timestamp = h_frame_record_timestamp;
                *v_l_timestamp = current_time_monotonic(vc->av->toxav_mono_time);
// -------- DEBUG:AUDIO/VIDEO DELAY/LATENCY --------
// -------- DEBUG:AUDIO/VIDEO DELAY/LATENCY --------
// -------- DEBUG:AUDIO/VIDEO DELAY/LATENCY --------

                if (vc->vcb_pts)
                {
                    uint64_t pts_for_client = h_frame_record_timestamp;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

#if LIBAVCODEC_VERSION_INT > AV_VERSION_INT(59, 0, 0)
                    int32_t delta_check = (int32_t)(h_frame_record_timestamp - frame->pts);
#else
                    int32_t delta_check = (int32_t)(h_frame_record_timestamp - frame->pkt_pts);
#endif

                    if ((delta_check >= 0) && (delta_check <= 600))
                    {

#if LIBAVCODEC_VERSION_INT > AV_VERSION_INT(59, 0, 0)
                        pts_for_client = frame->pts;
#else
                        pts_for_client = frame->pkt_pts;
#endif
                    }
#pragma GCC diagnostic pop

                    LOGGER_API_DEBUG(vc->av->tox, "DDDDDDDDDD:%lu", pts_for_client);
                    vc->vcb_pts(vc->av, vc->friend_number, frame->width, frame->height,
                            (const uint8_t *)frame->data[0],
                            (const uint8_t *)frame->data[1],
                            (const uint8_t *)frame->data[2],
                            frame->linesize[0], frame->linesize[1],
                            frame->linesize[2], vc->vcb_pts_user_data,
                            pts_for_client);
                }
                else
                {
                    vc->vcb(vc->av, vc->friend_number, frame->width, frame->height,
                            (const uint8_t *)frame->data[0],
                            (const uint8_t *)frame->data[1],
                            (const uint8_t *)frame->data[2],
                            frame->linesize[0], frame->linesize[1],
                            frame->linesize[2], vc->vcb_user_data);
                }
            }

        } else {
            // some other error
        }

        av_frame_free(&frame);
    }

    av_packet_free(&compr_data);
    free(p);
}

uint32_t encode_frame_h264(ToxAV *av, uint32_t friend_number, uint16_t width, uint16_t height,
                           const uint8_t *y,
                           const uint8_t *u, const uint8_t *v, ToxAVCall *call,
                           uint64_t *video_frame_record_timestamp,
                           int vpx_encode_flags,
                           x264_nal_t **nal,
                           int *i_frame_size)
{

    if (call->video->x264_software_encoder_used == 1) {

        memcpy(call->video->h264_in_pic.img.plane[0], y, width * height);
        memcpy(call->video->h264_in_pic.img.plane[1], u, (width / 2) * (height / 2));
        memcpy(call->video->h264_in_pic.img.plane[2], v, (width / 2) * (height / 2));

        int i_nal;

        call->video->h264_in_pic.i_pts = (int64_t)(*video_frame_record_timestamp);
        LOGGER_API_DEBUG(av->tox, "X264:in_ts:%lu", (*video_frame_record_timestamp));

        if ((vpx_encode_flags & VPX_EFLAG_FORCE_KF) > 0) {
            call->video->h264_in_pic.i_type = X264_TYPE_IDR; // real full i-frame
            call->video->last_sent_keyframe_ts = current_time_monotonic(av->toxav_mono_time);
        } else {
            call->video->h264_in_pic.i_type = X264_TYPE_AUTO;
        }

        LOGGER_API_DEBUG(av->tox, "X264 IN frame type=%d", (int)call->video->h264_in_pic.i_type);

        *i_frame_size = x264_encoder_encode(call->video->h264_encoder,
                                            nal,
                                            &i_nal,
                                            &(call->video->h264_in_pic),
                                            &(call->video->h264_out_pic));


        *video_frame_record_timestamp = (uint64_t)call->video->h264_out_pic.i_pts;
        LOGGER_API_DEBUG(av->tox, "X264:out_ts:%lu", (*video_frame_record_timestamp));




        if (IS_X264_TYPE_I(call->video->h264_out_pic.i_type)) {
            LOGGER_API_DEBUG(av->tox, "X264 out frame type=%d", (int)call->video->h264_out_pic.i_type);
        }


        if (*i_frame_size < 0) {
            // some error
        } else if (*i_frame_size == 0) {
            // zero size output
        }

        if (*nal == NULL) {
            return 1;
        }

        if ((*nal)->p_payload == NULL) {
            return 1;
        }

        return 0;

    } else {

        AVFrame *frame;
        int ret;
        uint32_t result = 1;

        frame = av_frame_alloc();

        frame->format = call->video->h264_encoder2->pix_fmt;
        frame->width  = width;
        frame->height = height;

        ret = av_frame_get_buffer(frame, 32);

        if (ret < 0) {
            LOGGER_API_ERROR(av->tox, "av_frame_get_buffer:Could not allocate the video frame data");
        }

        /* make sure the frame data is writable */
        ret = av_frame_make_writable(frame);

        if (ret < 0) {
            LOGGER_API_ERROR(av->tox, "av_frame_make_writable:ERROR");
        }

        LOGGER_API_DEBUG(av->tox, "video packet record time[ECN:4a]: %d mtime=%d", (int)(*video_frame_record_timestamp),
                     (int)current_time_monotonic(av->toxav_mono_time));
        frame->pts = (int64_t)(*video_frame_record_timestamp);

        // copy YUV frame data into buffers
        memcpy(frame->data[0], y, width * height);
        memcpy(frame->data[1], u, (width / 2) * (height / 2));
        memcpy(frame->data[2], v, (width / 2) * (height / 2));

        // encode the frame
        ret = avcodec_send_frame(call->video->h264_encoder2, frame);

        if (ret < 0) {
            LOGGER_API_ERROR(av->tox, "Error sending a frame for encoding:ERROR");
        }

        ret = avcodec_receive_packet(call->video->h264_encoder2, call->video->h264_out_pic2);

        if (ret == AVERROR(EAGAIN) || ret == AVERROR_EOF) {
            *i_frame_size = 0;
        } else if (ret < 0) {
            *i_frame_size = 0;
            // Error during encoding
        } else {

            LOGGER_API_DEBUG(av->tox, "video packet record time[ECN:4b]: %d mtime=%d", (int)(*video_frame_record_timestamp),
                         (int)current_time_monotonic(av->toxav_mono_time));
            *video_frame_record_timestamp = (uint64_t)call->video->h264_out_pic2->pts;
            LOGGER_API_DEBUG(av->tox, "video packet record time[ECN:4c]: %d mtime=%d", (int)(*video_frame_record_timestamp),
                         (int)current_time_monotonic(av->toxav_mono_time));

            *i_frame_size = call->video->h264_out_pic2->size;

            result = 0;
        }

        av_frame_free(&frame);

        return result;

    }

}

uint32_t send_frames_h264(ToxAV *av, uint32_t friend_number, uint16_t width, uint16_t height,
                          const uint8_t *y,
                          const uint8_t *u, const uint8_t *v, ToxAVCall *call,
                          uint64_t *video_frame_record_timestamp,
                          int vpx_encode_flags,
                          x264_nal_t **nal,
                          int *i_frame_size,
                          TOXAV_ERR_SEND_FRAME *rc)
{

    if (call->video->x264_software_encoder_used == 1) {
        if (*i_frame_size > 0) {

            LOGGER_API_DEBUG(av->tox, "X264:send_ts:%lu", (*video_frame_record_timestamp));
            const uint32_t frame_length_in_bytes = *i_frame_size;
            const int keyframe = (int)call->video->h264_out_pic.b_keyframe;

            int res = rtp_send_data
                      (
                          call->video_rtp,
                          (const uint8_t *)((*nal)->p_payload),
                          frame_length_in_bytes,
                          keyframe,
                          *video_frame_record_timestamp,
                          (int32_t)0,
                          TOXAV_ENCODER_CODEC_USED_H264,
                          call->video_bit_rate,
                          call->video->client_video_capture_delay_ms,
                          call->video->video_encoder_frame_orientation_angle,
                          nullptr
                      );

            (*video_frame_record_timestamp)++;

            if (res < 0) {
                LOGGER_API_WARNING(av->tox, "Could not send video frame: %s", strerror(errno));
                *rc = TOXAV_ERR_SEND_FRAME_RTP_FAILED;
                return 1;
            }

            return 0;
        } else {
            *rc = TOXAV_ERR_SEND_FRAME_RTP_FAILED;
            return 1;
        }

    } else {

        if (*i_frame_size > 0) {

            LOGGER_API_DEBUG(av->tox, "video packet record time[1b]: %d mtime=%d", (int)(*video_frame_record_timestamp),
                         (int)current_time_monotonic(av->toxav_mono_time));
            const uint32_t frame_length_in_bytes = *i_frame_size;
            const int keyframe = (int)1;

            LOGGER_API_DEBUG(av->tox, "call->video->video_encoder_frame_orientation_angle==%d",
                         call->video->video_encoder_frame_orientation_angle);

            int res = rtp_send_data
                      (
                          call->video_rtp,
                          (const uint8_t *)(call->video->h264_out_pic2->data),
                          frame_length_in_bytes,
                          keyframe,
                          *video_frame_record_timestamp,
                          (int32_t)0,
                          TOXAV_ENCODER_CODEC_USED_H264,
                          call->video_bit_rate,
                          call->video->client_video_capture_delay_ms,
                          call->video->video_encoder_frame_orientation_angle,
                          nullptr
                      );

            (*video_frame_record_timestamp)++;


            av_packet_unref(call->video->h264_out_pic2);

            if (res < 0) {
                LOGGER_API_WARNING(av->tox, "Could not send video frame: %s", strerror(errno));
                *rc = TOXAV_ERR_SEND_FRAME_RTP_FAILED;
                return 1;
            }

            return 0;

        } else {
            *rc = TOXAV_ERR_SEND_FRAME_RTP_FAILED;
            return 1;
        }

    }

}

void vc_kill_h264(VCSession *vc)
{
    // encoder
    if (vc->x264_software_encoder_used == 1) {
        if (vc->h264_encoder) {
            x264_encoder_close(vc->h264_encoder);
            x264_picture_clean(&(vc->h264_in_pic));
        }
    } else {
        // --- ffmpeg encoder ---
        av_packet_free(&(vc->h264_out_pic2));
        avcodec_free_context(&(vc->h264_encoder2));
        // --- ffmpeg encoder ---
    }

    // decoder
    if (vc->h264_decoder->extradata) {
        av_free(vc->h264_decoder->extradata);
        vc->h264_decoder->extradata = NULL;
    }

    avcodec_free_context(&vc->h264_decoder);
}





// --------- H265 ---------
// --------- H265 ---------
// --------- H265 ---------

#ifdef HAVE_H265_ENCODER
static void vc_init_encoder_h265(Logger *log, VCSession *vc, uint32_t bit_rate,
                                uint16_t width, uint16_t height)
{
    // HINT: vc->av may be NULL here
    // LOGGER_API_WARNING(vc->av->tox, "H265 encoder init");

    x265_param *param = x265_param_alloc();
    if (x265_param_default_preset(param, "superfast", "fastdecode") != 0) {
        // LOGGER_API_WARNING(vc->av->tox, "H265 encoder:x265_param_default_preset error");
        printf("vc_init_encoder_h265: H265 encoder:x265_param_default_preset error\n");
        // goto fail;
    }

    vc->h265_enc_width = width;
    vc->h265_enc_height = height;

    param->sourceWidth = vc->h265_enc_width;
    param->sourceHeight = vc->h265_enc_height;
    param->fpsNum = 20;
    param->fpsDenom = 1;
    param->internalCsp = X265_CSP_I420;
    param->bframes = 0;
    param->bRepeatHeaders = 1;
    param->bAnnexB = 1;
    param->keyframeMax = 60; // every n-th frame is an I-frame
    param->bIntraRefresh = 1;


    // x265_param_parse(param, "fps", "20");
    x265_param_parse(param, "repeat-headers", "1");
    x265_param_parse(param, "annexb", "1");
    // x265_param_parse(param, "input-res", "1920x1080");
    x265_param_parse(param, "input-csp", "i420");

    // x265_param_parse(param, "rd", "1");
    x265_param_parse(param, "intra-refresh", "1");

    x265_param_parse(param, "frame-threads", "3");

    printf("vc_init_encoder_h265:vc->h264_enc_bitrate = %d\n", (int)vc->h264_enc_bitrate);
    vc->h264_enc_bitrate = bit_rate;
    //******// param->bitrate = 

    // https://x265.readthedocs.io/en/master/cli.html#quality-rate-control-and-rate-distortion-options
    // Specify the target bitrate in kbps. Default is 0 (CRF)

    char bitrate_str[20];
    memset(bitrate_str, 0, 20);
    snprintf(bitrate_str, sizeof(bitrate_str), "%d", (int)(bit_rate / 1000));
    // x265_param_parse(param, "bitrate", bitrate_str);
    x265_param_parse(param, "bitrate", "800");
    param->rc.bitrate = 800;
    printf("vc_init_encoder_h265:bit_rate = %d\n", (int)(bit_rate / 1000));

    // Range of values: an integer from 0 to 51
    // x265_param_parse(param, "qp", "50");

    vc->h265_in_pic = x265_picture_alloc();
    x265_picture_init(param, vc->h265_in_pic);

    vc->h265_out_pic = x265_picture_alloc();
    x265_picture_init(param, vc->h265_out_pic);

    // Allocate memory for YUV frame
    vc->h265_in_pic->colorSpace = X265_CSP_I420;
    vc->h265_in_pic->stride[0] = vc->h265_enc_width;
    vc->h265_in_pic->stride[1] = vc->h265_enc_width / 2;
    vc->h265_in_pic->stride[2] = vc->h265_enc_width / 2;
    vc->h265_in_pic->planes[0] = (uint8_t *)calloc(1, (vc->h265_enc_width * vc->h265_enc_height));
    vc->h265_in_pic->planes[1] = (uint8_t *)calloc(1, (vc->h265_enc_width * vc->h265_enc_height) / 4);
    vc->h265_in_pic->planes[2] = (uint8_t *)calloc(1, (vc->h265_enc_width * vc->h265_enc_height) / 4);

    vc->h265_encoder = x265_encoder_open(param);
    // LOGGER_API_WARNING(vc->av->tox, "H265 encoder:h265_encoder=%p", (void *)vc->h265_encoder);

    x265_param_free(param);
    // LOGGER_API_WARNING(vc->av->tox, "H265 encoder:h265_encoder:ready");
}
#endif

VCSession *vc_new_h265(Logger *log, ToxAV *av, uint32_t friend_number, toxav_video_receive_frame_cb *cb, void *cb_data,
                       VCSession *vc)
{
#ifdef HAVE_H265_ENCODER
    // ENCODER -------
    LOGGER_API_INFO(av->tox, "H265 encoder init");
    vc_init_encoder_h265(log, vc, (VIDEO_BITRATE_INITIAL_VALUE_H264 * 1000), 1920, 1080);
    LOGGER_API_INFO(av->tox, "H265 encoder ready");
    // ENCODER -------
#endif


    // DECODER -------
    LOGGER_API_INFO(av->tox, "H265 decoder init");

    AVCodec *codec = NULL;
    vc->h265_decoder = NULL;

#if LIBAVCODEC_VERSION_INT < AV_VERSION_INT(58, 9, 100)
    avcodec_register_all();
#endif

    codec = NULL;
    codec = avcodec_find_decoder(AV_CODEC_ID_H265);

    if (!codec) {
        LOGGER_API_WARNING(av->tox, "codec not found H265 on decoder");
        vc->h265_decoder = NULL;
    } else {

        vc->h265_decoder = avcodec_alloc_context3(codec);
        LOGGER_API_INFO(av->tox, "H265 decoder:h265_decoder=%p", (void *)vc->h265_decoder);

        if (codec) {

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#if LIBAVCODEC_VERSION_INT < AV_VERSION_INT(59, 0, 0)
            vc->h265_decoder->refcounted_frames = 0;
#endif
            /*   When AVCodecContext.refcounted_frames is set to 0, the returned
            *             reference belongs to the decoder and is valid only until the
            *             next call to this function or until closing or flushing the
            *             decoder. The caller may not write to it.
            */
#pragma GCC diagnostic pop

            vc->h265_decoder->delay = 0;
            av_opt_set_int(vc->h265_decoder->priv_data, "delay", 0, AV_OPT_SEARCH_CHILDREN);

            vc->h265_decoder->time_base = (AVRational) {
                1, 20
            };
            vc->h265_decoder->framerate = (AVRational) {
                20, 1
            };

            if (avcodec_open2(vc->h265_decoder, codec, NULL) < 0) {
                LOGGER_API_WARNING(av->tox, "could not open codec H265 on decoder");
                assert(!"could not open codec H265 on decoder");
            }

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#if LIBAVCODEC_VERSION_INT < AV_VERSION_INT(59, 0, 0)
            vc->h265_decoder->refcounted_frames = 0;
#endif
#pragma GCC diagnostic pop
            /*   When AVCodecContext.refcounted_frames is set to 0, the returned
            *             reference belongs to the decoder and is valid only until the
            *             next call to this function or until closing or flushing the
            *             decoder. The caller may not write to it.
            */

            LOGGER_API_INFO(av->tox, "H265 decoder:h265_decoder:ready");
        }
    }


    // DECODER -------

    return vc;
}

#ifdef HAVE_H265_ENCODER
static void vc_kill_encoder_h265(VCSession *vc)
{
    free(vc->h265_in_pic->planes[0]);
    free(vc->h265_in_pic->planes[1]);
    free(vc->h265_in_pic->planes[2]);
    x265_picture_free(vc->h265_in_pic);
    x265_picture_free(vc->h265_out_pic);
    x265_encoder_close(vc->h265_encoder);
}
#endif

int vc_reconfigure_encoder_h265(Logger *log, VCSession *vc, uint32_t bit_rate,
                                uint16_t width, uint16_t height,
                                int16_t kf_max_dist)
{
#ifdef HAVE_H265_ENCODER
    if (!vc) {
        return -1;
    }

    if ((vc->h265_enc_width == width) &&
            (vc->h265_enc_height == height) &&
            (vc->h264_enc_bitrate == bit_rate))
    {
        // no change
        return 0;
    }

    if ((vc->h265_enc_width == width) &&
            (vc->h265_enc_height == height) &&
            (vc->h264_enc_bitrate != bit_rate))
    {
        // HINT: just bitrate has changed
        // LOGGER_API_WARNING(vc->av->tox, "vc_reconfigure_encoder_h265:1:bit_rate = %d vc->h264_enc_bitrate = %d", (int)bit_rate, (int)vc->h264_enc_bitrate);
        x265_param *param = x265_param_alloc();
        x265_encoder_parameters(vc->h265_encoder, param);

        char bitrate_str[20];
        memset(bitrate_str, 0, 20);
        snprintf(bitrate_str, sizeof(bitrate_str), "%d", (int)(bit_rate / 1000));
        // x265_param_parse(param, "bitrate", bitrate_str);
        x265_param_parse(param, "bitrate", "800");
        param->rc.bitrate = 800;

        int res = x265_encoder_reconfig(vc->h265_encoder, param);
        printf("x265_encoder_reconfig:res=%d bitrate=%d\n", (int)res, (int)(bit_rate / 1000));
        x265_param_free(param);
    }
    else
    {
        // HINT: more has changed do a full encoder shutdown and re-init
        vc_kill_encoder_h265(vc);
        vc->h265_enc_height = height;
        vc->h265_enc_width = width;
        // LOGGER_API_WARNING(vc->av->tox, "vc_reconfigure_encoder_h265:2:bit_rate = %d vc->h264_enc_bitrate = %d", (int)bit_rate, (int)vc->h264_enc_bitrate);
        vc_init_encoder_h265(log, vc, bit_rate, width, height);
    }

    vc->h264_enc_bitrate = bit_rate;

#endif
    return 0;
}

void decode_frame_h265(VCSession *vc, Tox *tox, uint8_t skip_video_flag, uint64_t *a_r_timestamp,
                       uint64_t *a_l_timestamp,
                       uint64_t *v_r_timestamp, uint64_t *v_l_timestamp,
                       const struct RTPHeader *header_v3,
                       struct RTPMessage *p, vpx_codec_err_t rc,
                       uint32_t full_data_len,
                       uint8_t *ret_value)
{
    LOGGER_API_DEBUG(vc->av->tox, "decode_frame_h265:fnum=%d,len=%d", vc->friend_number, full_data_len);

    if (p == NULL) {
        LOGGER_API_DEBUG(vc->av->tox, "decode_frame_h265:NO data");
        return;
    }

    if (full_data_len < 1) {
        LOGGER_API_DEBUG(vc->av->tox, "decode_frame_h265:not enough data");
        free(p);
        p = NULL;
        return;
    }

    if (vc->h265_decoder == NULL) {
        LOGGER_API_DEBUG(vc->av->tox, "vc->h265_decoder:not ready");
        free(p);
        p = NULL;
        return;
    }


    if (vc->global_decode_first_frame_got == 0)
    {
        if (vc->global_decode_first_frame_delayed_by == 0)
        {
            vc->global_decode_first_frame_delayed_ms = current_time_monotonic(vc->av->toxav_mono_time);
        }
        vc->global_decode_first_frame_delayed_by++;
    }

    AVPacket *compr_data = NULL;
    compr_data = av_packet_alloc();

    if (compr_data == NULL) {
        LOGGER_API_DEBUG(vc->av->tox, "av_packet_alloc:ERROR");
        free(p);
        p = NULL;
        return;
    }

    uint64_t h_frame_record_timestamp = header_v3->frame_record_timestamp;

    compr_data->data = p->data;
    compr_data->size = (int)full_data_len; // hmm, "int" again

    if (header_v3->frame_record_timestamp > 0) {
        LOGGER_API_DEBUG(vc->av->tox, "in_pts:%lu", header_v3->frame_record_timestamp);
        compr_data->dts = (int64_t)(header_v3->frame_record_timestamp) - 1;
        compr_data->pts = (int64_t)(header_v3->frame_record_timestamp);
        compr_data->duration = 0; // (int64_t)(header_v3->frame_record_timestamp) + 1; // 0;
    }

    int result_send_packet = avcodec_send_packet(vc->h265_decoder, compr_data);

    if (result_send_packet != 0) {
        LOGGER_API_DEBUG(vc->av->tox, "avcodec_send_packet:ERROR=%d", result_send_packet);
        av_packet_free(&compr_data);
        free(p);
        p = NULL;
        return;
    }

    /* HINT: this is the only part that takes all the time !!! */
    /* HINT: this is the only part that takes all the time !!! */
    /* HINT: this is the only part that takes all the time !!! */
    /* ------------------------------------------------------- */
    /* ------------------------------------------------------- */


    int ret_ = 0;

    while (ret_ >= 0) {

        // start_time_ms = current_time_monotonic(vc->av->toxav_mono_time);
        AVFrame *frame = av_frame_alloc();

        if (frame == NULL) {
            // stop decoding
            break;
        }

        ret_ = avcodec_receive_frame(vc->h265_decoder, frame);

        if (ret_ == AVERROR(EAGAIN) || ret_ == AVERROR_EOF) {
            // error
            av_frame_free(&frame);
            break;
        } else if (ret_ < 0) {
            // Error during decoding
            av_frame_free(&frame);
            break;
        } else if (ret_ == 0) {


        if (vc->global_decode_first_frame_got == 0)
        {
            vc->global_decode_first_frame_got = 1;
            vc->global_decode_first_frame_delayed_ms =
                current_time_monotonic(vc->av->toxav_mono_time) - vc->global_decode_first_frame_delayed_ms;
            LOGGER_API_DEBUG(vc->av->tox, "X265 decoder delay: %d f, %d ms",
                    (vc->global_decode_first_frame_delayed_by - 1),
                    (int)vc->global_decode_first_frame_delayed_ms);
        }


            if (header_v3->frame_record_timestamp > 0) {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
#if LIBAVCODEC_VERSION_INT > AV_VERSION_INT(59, 0, 0)
                int32_t delta_value = (int32_t)(h_frame_record_timestamp - frame->pts);
#else
                int32_t delta_value = (int32_t)(h_frame_record_timestamp - frame->pkt_pts);
#endif

#if LIBAVCODEC_VERSION_INT > AV_VERSION_INT(59, 0, 0)
                LOGGER_API_DEBUG(vc->av->tox, "out_pts:%lu %lu %ld %ld",
                        frame->pts, frame->pkt_dts, frame->best_effort_timestamp, frame->pkt_pos);
#endif

                LOGGER_API_DEBUG(vc->av->tox, "dec:XX:03:%d %d %d %d %d",
                        delta_value,
                        (int)h_frame_record_timestamp,

#if LIBAVCODEC_VERSION_INT > AV_VERSION_INT(59, 0, 0)
                        (int)frame->pts,
#else
                        (int)frame->pkt_pts,
#endif

                        (int)frame->pkt_dts,
                        (int)frame->pts);
#pragma GCC diagnostic pop

                if ((delta_value >= 0) && (delta_value <= 1000))
                {
                    vc->video_decoder_caused_delay_ms = delta_value;
                    LOGGER_API_DEBUG(vc->av->tox, "dec:1:delta_value=%d", vc->video_decoder_caused_delay_ms);
                }
                else if (delta_value == -1)
                {
                    // since we do NOT have any idea how long the decoder delays frames,
                    // and the decoder will lie to us, we just assume some random value
                    // that works for our use cases (decoding on andriod via MediaCodec)
                    vc->video_decoder_caused_delay_ms = 1;
                    LOGGER_API_DEBUG(vc->av->tox, "dec:2:delta_value=%d", vc->video_decoder_caused_delay_ms);
                }

                // calc mean value
                vc->video_decoder_caused_delay_ms_array[vc->video_decoder_caused_delay_ms_array_index] = vc->video_decoder_caused_delay_ms;
                vc->video_decoder_caused_delay_ms_array_index = (vc->video_decoder_caused_delay_ms_array_index + 1) %
                        VIDEO_DECODER_CAUSED_DELAY_MS_ENTRIES;

                uint32_t mean_value = 0;

                for (int k = 0; k < VIDEO_DECODER_CAUSED_DELAY_MS_ENTRIES; k++) {
                    mean_value = mean_value + vc->video_decoder_caused_delay_ms_array[k];
                }

                if (mean_value == 0) {
                    vc->video_decoder_caused_delay_ms_mean_value = 0;
                } else {
                    vc->video_decoder_caused_delay_ms_mean_value = (mean_value * 10) / (VIDEO_DECODER_CAUSED_DELAY_MS_ENTRIES * 10);
                }

                LOGGER_API_DEBUG(vc->av->tox, "dec:video_decoder_caused_delay_ms_mean_value=%d",
                        vc->video_decoder_caused_delay_ms_mean_value);

            }

            // start_time_ms = current_time_monotonic(vc->av->toxav_mono_time);
            if ((frame->data[0] != NULL) && (frame->data[1] != NULL) && (frame->data[2] != NULL)) {

// -------- DEBUG:AUDIO/VIDEO DELAY/LATENCY --------
// -------- DEBUG:AUDIO/VIDEO DELAY/LATENCY --------
// -------- DEBUG:AUDIO/VIDEO DELAY/LATENCY --------
                *v_r_timestamp = h_frame_record_timestamp;
                *v_l_timestamp = current_time_monotonic(vc->av->toxav_mono_time);
// -------- DEBUG:AUDIO/VIDEO DELAY/LATENCY --------
// -------- DEBUG:AUDIO/VIDEO DELAY/LATENCY --------
// -------- DEBUG:AUDIO/VIDEO DELAY/LATENCY --------

                if (vc->vcb_pts)
                {
                    uint64_t pts_for_client = h_frame_record_timestamp;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"

#if LIBAVCODEC_VERSION_INT > AV_VERSION_INT(59, 0, 0)
                    int32_t delta_check = (int32_t)(h_frame_record_timestamp - frame->pts);
#else
                    int32_t delta_check = (int32_t)(h_frame_record_timestamp - frame->pkt_pts);
#endif

                    if ((delta_check >= 0) && (delta_check <= 600))
                    {

#if LIBAVCODEC_VERSION_INT > AV_VERSION_INT(59, 0, 0)
                        pts_for_client = frame->pts;
#else
                        pts_for_client = frame->pkt_pts;
#endif
                    }
#pragma GCC diagnostic pop

                    LOGGER_API_DEBUG(vc->av->tox, "DDDDDDDDDD:%lu", pts_for_client);
                    vc->vcb_pts(vc->av, vc->friend_number, frame->width, frame->height,
                            (const uint8_t *)frame->data[0],
                            (const uint8_t *)frame->data[1],
                            (const uint8_t *)frame->data[2],
                            frame->linesize[0], frame->linesize[1],
                            frame->linesize[2], vc->vcb_pts_user_data,
                            pts_for_client);
                }
                else
                {
                    vc->vcb(vc->av, vc->friend_number, frame->width, frame->height,
                            (const uint8_t *)frame->data[0],
                            (const uint8_t *)frame->data[1],
                            (const uint8_t *)frame->data[2],
                            frame->linesize[0], frame->linesize[1],
                            frame->linesize[2], vc->vcb_user_data);
                }
            }

        } else {
            // some other error
        }

        av_frame_free(&frame);
    }

    av_packet_free(&compr_data);
    free(p);

    return;
}

#ifdef HAVE_H265_ENCODER
uint32_t encode_frame_h265(ToxAV *av, uint32_t friend_number, uint16_t width, uint16_t height,
                           const uint8_t *y,
                           const uint8_t *u, const uint8_t *v, ToxAVCall *call,
                           uint64_t *video_frame_record_timestamp,
                           int vpx_encode_flags,
                           int *x265_num_nals,
                           x264_nal_t **nal,
                           int *i_frame_size, x265_nal** h265_nals)
{
    uint32_t i_nal;

    LOGGER_API_DEBUG(av->tox, "encode_frame_h265:start");

    call->video->h265_in_pic->pts = (int64_t)(*video_frame_record_timestamp);
    LOGGER_API_DEBUG(av->tox, "X265:in_ts:%lu", (*video_frame_record_timestamp));


    memcpy(call->video->h265_in_pic->planes[0], y, (width * height));
    memcpy(call->video->h265_in_pic->planes[1], u, (width / 2) * (height / 2));
    memcpy(call->video->h265_in_pic->planes[2], v, (width / 2) * (height / 2));
    x265_encoder_encode(call->video->h265_encoder, h265_nals, &i_nal, call->video->h265_in_pic, call->video->h265_out_pic);

    *video_frame_record_timestamp = (uint64_t)call->video->h265_out_pic->pts;
    LOGGER_API_DEBUG(av->tox, "X265:out_ts:%lu", (*video_frame_record_timestamp));
    LOGGER_API_DEBUG(av->tox, "X265:out_ts:dts:%d", (int)call->video->h265_out_pic->dts);
    LOGGER_API_DEBUG(av->tox, "X265:out_ts:pts:%d", (int)call->video->h265_out_pic->pts);

    *x265_num_nals = 0;

    if (*h265_nals == NULL) {
        return 1;
    }

    if (i_nal < 1) {
        return 1;
    }

    *x265_num_nals = (int)i_nal;
    *i_frame_size = (*h265_nals)[0].sizeBytes;

    if (*i_frame_size < 0) {
        // some error
    } else if (*i_frame_size == 0) {
        // zero size output
    }

    if ((*h265_nals)[0].payload == NULL) {
        LOGGER_API_WARNING(av->tox, "X265:ERR:099");
        return 1;
    }

    LOGGER_API_DEBUG(av->tox, "X265:done");
    return 0;
}
#endif

#ifdef HAVE_H265_ENCODER
uint32_t send_frames_h265(ToxAV *av, uint32_t friend_number, uint16_t width, uint16_t height,
                          const uint8_t *y,
                          const uint8_t *u, const uint8_t *v, ToxAVCall *call,
                          uint64_t *video_frame_record_timestamp,
                          int vpx_encode_flags,
                          x264_nal_t **nal,
                          int *i_frame_size,
                          int x265_num_nals,
                          x265_nal** h265_nals,
                          TOXAV_ERR_SEND_FRAME *rc)
{

    // Process the encoded data (NAL units)
    uint32_t need_buffer_bytes = 0;
    for (uint32_t i = 0; i < x265_num_nals; i++) {
        LOGGER_API_DEBUG(av->tox, "nal #%d", i);
        LOGGER_API_DEBUG(av->tox, "bytes: %d", (int)(*h265_nals)[i].sizeBytes);
        need_buffer_bytes = need_buffer_bytes + (*h265_nals)[i].sizeBytes;
    }

    if (need_buffer_bytes > 0) {
        uint8_t *needed_buffer = malloc(need_buffer_bytes);
        if (needed_buffer == nullptr) {
            *rc = TOXAV_ERR_SEND_FRAME_RTP_FAILED;
            return 1;
        }

        uint8_t *p1 = needed_buffer;
        for (uint32_t i = 0; i < x265_num_nals; i++) {
            memcpy(p1, (const uint8_t *)(*h265_nals)[i].payload, (*h265_nals)[i].sizeBytes);
            p1 = p1 + (*h265_nals)[i].sizeBytes;
        }

        LOGGER_API_DEBUG(av->tox, "X265:send_ts:%lu", (*video_frame_record_timestamp));
        const uint32_t frame_length_in_bytes = need_buffer_bytes;
        LOGGER_API_DEBUG(av->tox, "X265:sizebytes:%d", need_buffer_bytes);

        int res = rtp_send_data
                  (
                      call->video_rtp,
                      needed_buffer,
                      need_buffer_bytes,
                      0,
                      *video_frame_record_timestamp,
                      (int32_t)0,
                      TOXAV_ENCODER_CODEC_USED_H265,
                      call->video_bit_rate,
                      call->video->client_video_capture_delay_ms,
                      call->video->video_encoder_frame_orientation_angle,
                      nullptr
                  );
        (*video_frame_record_timestamp)++;

        free(needed_buffer);

        if (res < 0) {
            LOGGER_API_WARNING(av->tox, "Could not send video frame: %s", strerror(errno));
            *rc = TOXAV_ERR_SEND_FRAME_RTP_FAILED;
            return 1;
        } else {
            LOGGER_API_DEBUG(av->tox, "send video frame OK");
        }

        return 0;
    } else {
        *rc = TOXAV_ERR_SEND_FRAME_RTP_FAILED;
        return 1;
    }
}
#endif

void vc_kill_h265(VCSession *vc)
{
#ifdef HAVE_H265_ENCODER
    // encoder
    vc_kill_encoder_h265(vc);
#endif

    // decoder
    if (vc->h265_decoder != nullptr) {
        if (vc->h265_decoder->extradata) {
            av_free(vc->h265_decoder->extradata);
            vc->h265_decoder->extradata = NULL;
        }
        avcodec_free_context(&vc->h265_decoder);
        vc->h265_decoder = NULL;
    }
}

