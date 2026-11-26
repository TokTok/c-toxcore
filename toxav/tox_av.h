/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2026 The TokTok team.
 * Copyright © 2013-2015 Tox project.
 */

/** @file
 * @brief Audio/video calls that aren't bound to a Tox instance.
 *
 * A Tox_Av sends its packets through callbacks, and the client feeds it the
 * packets and friend connection changes it gets, e.g. from a Tox instance.
 *
 * This API can handle multiple calls. Each call has its state, in very rare
 * occasions the library can change the state of the call without apps
 * knowledge.
 *
 * @section tox_av_events Events and callbacks
 *
 * One callback can be registered per event. All events have a callback
 * function type named `tox_av_{event}_cb` and a function to register it named
 * `tox_av_callback_{event}`. Passing a NULL callback will result in no callback
 * being registered for that event. Lack of some event handlers will cause the
 * library to drop calls before they are started. Hanging up call from a
 * callback causes undefined behaviour.
 *
 * @section tox_av_threading Threading implications
 *
 * Only the iterate functions and the frame send functions may run on other
 * threads than the one calling the other functions.
 *
 * You have to choose either the single thread or the multi thread iterate
 * functions and read their documentation.
 *
 * tox_av_audio_send_frame and tox_av_video_send_frame send their packets right
 * away, so the send lossy packet callback runs on the threads calling them.
 *
 * Audio and video receive frame events are triggered from the iterate
 * functions. Any API function can fail if mutexes are held by another thread,
 * in which case they will set the SYNC error code.
 *
 * @subsection tox_av_multi_threading Separate audio and video threads
 *
 * Tox_Av supports either a single thread for audio and video or decoding and
 * encoding them in separate threads. You have to choose one mode and can not
 * mix function calls to those different modes.
 *
 * For best results use the multi-threaded mode and run the audio thread with
 * higher priority than the video thread. This prioritizes audio over video.
 */
#ifndef C_TOXCORE_TOXAV_TOX_AV_H
#define C_TOXCORE_TOXAV_TOX_AV_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Any number the client uses for a friend, e.g. its Tox friend number.
 */
typedef uint32_t Tox_Av_Friend_Number;

/**
 * @brief An audio/video session.
 *
 * Upon closing a Tox_Av, all active calls end, and the friends in them are told
 * that this client hung up.
 */
typedef struct Tox_Av Tox_Av;

/** @{
 * @brief Creation and destruction
 */

typedef enum Tox_Err_Av_New {
    /**
     * The function returned successfully.
     */
    TOX_ERR_AV_NEW_OK,

    /**
     * Memory allocation failure while trying to allocate structures required
     * for the A/V session.
     */
    TOX_ERR_AV_NEW_MALLOC,
} Tox_Err_Av_New;

/**
 * @brief Create a new A/V session.
 *
 * Packets go out through the send packet callbacks and come in through
 * tox_av_receive_packet. The client tells it which friends are connected with
 * tox_av_friend_connection_status.
 *
 * @param[out] error Error code.
 */
Tox_Av *_Nullable tox_av_new(Tox_Err_Av_New *_Nullable error);

/**
 * Releases all resources associated with the A/V session.
 *
 * If any calls were ongoing, they end, and the friends in them are told that
 * this client hung up. After calling this function, no other functions may be
 * called and the av pointer becomes invalid.
 */
void tox_av_kill(Tox_Av *_Nullable av);

/** @} */

/** @{
 * @brief Network
 */

/**
 * The function type for the send lossy packet callback.
 *
 * It sends an audio, video or bandwidth packet to a friend, e.g. with
 * tox_friend_send_lossy_packet. Tox_Av calls it from the threads calling
 * tox_av_audio_send_frame, tox_av_video_send_frame and tox_av_receive_packet,
 * possibly at the same time. Packets are at most 1373 bytes, the largest Tox
 * custom packet.
 *
 * @param friend_number The friend to send the packet to.
 * @param data The packet, starting with its packet ID.
 * @param length The length of the packet.
 *
 * @return true if the packet was sent.
 *
 * @thread any
 */
typedef bool tox_av_send_lossy_packet_cb(Tox_Av *_Nonnull av, Tox_Av_Friend_Number friend_number, const uint8_t data[_Nonnull], size_t length,
        void *_Nullable user_data);

/**
 * Set the callback for sending lossy packets. Pass NULL to unset.
 */
void tox_av_callback_send_lossy_packet(Tox_Av *_Nonnull av, tox_av_send_lossy_packet_cb *_Nullable callback, void *_Nullable user_data);

/**
 * The function type for the send lossless packet callback.
 *
 * It sends a call signalling packet to a friend, e.g. with
 * tox_friend_send_lossless_packet. Tox_Av calls it from the thread calling
 * tox_av_call, tox_av_answer, tox_av_call_control, tox_av_receive_packet,
 * tox_av_kill or an iterate function.
 *
 * @param friend_number The friend to send the packet to.
 * @param data The packet, starting with its packet ID.
 * @param length The length of the packet.
 *
 * @return true if the packet was sent.
 */
typedef bool tox_av_send_lossless_packet_cb(Tox_Av *_Nonnull av, Tox_Av_Friend_Number friend_number, const uint8_t data[_Nonnull], size_t length,
        void *_Nullable user_data);

/**
 * Set the callback for sending lossless packets. Pass NULL to unset.
 */
void tox_av_callback_send_lossless_packet(Tox_Av *_Nonnull av, tox_av_send_lossless_packet_cb *_Nullable callback, void *_Nullable user_data);

/**
 * @brief Feed a received packet (lossy or lossless) into Tox_Av.
 *
 * The packet type is determined by the first byte of the data (the packet ID).
 * Supported IDs:
 * - 69 (0x45): MSI (Call Signaling)
 * - 192 (0xC0): RTP Audio
 * - 193 (0xC1): RTP Video
 * - 196 (0xC4): Bandwidth Controller
 *
 * @param av The Tox_Av instance.
 * @param friend_number The friend number the packet was received from.
 * @param data The full packet data (including the Packet ID).
 * @param length The length of the packet data.
 */
void tox_av_receive_packet(Tox_Av *_Nonnull av, Tox_Av_Friend_Number friend_number, const uint8_t data[_Nonnull], size_t length);

/**
 * @brief Tell a Tox_Av whether a friend is connected.
 *
 * Friends start out not connected. A call to a friend who isn't connected
 * fails, and a call ends when its friend disconnects.
 */
void tox_av_friend_connection_status(Tox_Av *_Nonnull av, Tox_Av_Friend_Number friend_number, bool connected);

/** @} */

/** @{
 * @brief A/V event loop, single thread
 */

/**
 * Returns the interval in milliseconds when the next tox_av_iterate call should
 * be. If no call is active at the moment, this function returns 1000.
 * This function MUST be called from the same thread as tox_av_iterate.
 */
uint32_t tox_av_iteration_interval(const Tox_Av *_Nonnull av);

/**
 * Main loop for the session. This function needs to be called in intervals of
 * `tox_av_iteration_interval()` milliseconds.
 */
void tox_av_iterate(Tox_Av *_Nonnull av);

/** @} */

/** @{
 * @brief A/V event loop, multiple threads
 */

/**
 * Returns the interval in milliseconds when the next tox_av_audio_iterate call
 * should be. If no call is active at the moment, this function returns 1000.
 * This function MUST be called from the same thread as tox_av_audio_iterate.
 */
uint32_t tox_av_audio_iteration_interval(const Tox_Av *_Nonnull av);

/**
 * Main loop for the session. This function needs to be called in intervals of
 * `tox_av_audio_iteration_interval()` milliseconds. It is best called in a
 * separate thread from tox_av_video_iterate. The thread calling this function
 * should have higher priority than the one calling tox_av_video_iterate to
 * prioritize audio over video.
 */
void tox_av_audio_iterate(Tox_Av *_Nonnull av);

/**
 * Returns the interval in milliseconds when the next tox_av_video_iterate call
 * should be. If no call is active at the moment, this function returns 1000.
 * This function MUST be called from the same thread as tox_av_video_iterate.
 */
uint32_t tox_av_video_iteration_interval(const Tox_Av *_Nonnull av);

/**
 * Main loop for the session. This function needs to be called in intervals of
 * `tox_av_video_iteration_interval()` milliseconds. It is best called in a
 * separate thread from tox_av_audio_iterate. The thread calling this function
 * should have lower priority than the one calling tox_av_audio_iterate to
 * prioritize audio over video.
 */
void tox_av_video_iterate(Tox_Av *_Nonnull av);

/** @} */

/** @{
 * @brief Call setup
 */

typedef enum Tox_Err_Av_Call {
    /**
     * The function returned successfully.
     */
    TOX_ERR_AV_CALL_OK,

    /**
     * A resource allocation error occurred while trying to create the
     * structures required for the call.
     */
    TOX_ERR_AV_CALL_MALLOC,

    /**
     * Synchronization error occurred.
     */
    TOX_ERR_AV_CALL_SYNC,

    /**
     * The friend is not connected, as last told by
     * tox_av_friend_connection_status.
     */
    TOX_ERR_AV_CALL_FRIEND_NOT_CONNECTED,

    /**
     * Attempted to call a friend while already in an audio or video call with
     * them.
     */
    TOX_ERR_AV_CALL_FRIEND_ALREADY_IN_CALL,

    /**
     * Audio or video bit rate is invalid.
     */
    TOX_ERR_AV_CALL_INVALID_BIT_RATE,
} Tox_Err_Av_Call;

/**
 * Call a friend. This will start ringing the friend.
 *
 * It is the client's responsibility to stop ringing after a certain timeout,
 * if such behaviour is desired. If the client does not stop ringing, the
 * library will not stop until the friend is disconnected. Audio and video
 * receiving are both enabled by default.
 *
 * @param friend_number The friend number of the friend that should be called.
 * @param audio_bit_rate Audio bit rate in kbit/sec. Set this to 0 to disable
 *   audio sending.
 * @param video_bit_rate Video bit rate in kbit/sec. Set this to 0 to disable
 *   video sending.
 */
bool tox_av_call(Tox_Av *_Nonnull av, Tox_Av_Friend_Number friend_number, uint32_t audio_bit_rate, uint32_t video_bit_rate,
                 Tox_Err_Av_Call *_Nullable error);

/**
 * The function type for the call callback.
 *
 * @param friend_number The friend number from which the call is incoming.
 * @param audio_enabled True if friend is sending audio.
 * @param video_enabled True if friend is sending video.
 */
typedef void tox_av_call_cb(Tox_Av *_Nonnull av, Tox_Av_Friend_Number friend_number, bool audio_enabled, bool video_enabled,
                            void *_Nullable user_data);

/**
 * Set the callback for the `call` event. Pass NULL to unset.
 */
void tox_av_callback_call(Tox_Av *_Nonnull av, tox_av_call_cb *_Nullable callback, void *_Nullable user_data);

typedef enum Tox_Err_Av_Answer {
    /**
     * The function returned successfully.
     */
    TOX_ERR_AV_ANSWER_OK,

    /**
     * Synchronization error occurred.
     */
    TOX_ERR_AV_ANSWER_SYNC,

    /**
     * Failed to initialize codecs for call session. Note that codec initiation
     * will fail if there is no receive callback registered for either audio or
     * video.
     */
    TOX_ERR_AV_ANSWER_CODEC_INITIALIZATION,

    /**
     * The friend is not currently trying to initiate a call. This is also
     * returned if this client is already in a call with the friend.
     */
    TOX_ERR_AV_ANSWER_FRIEND_NOT_CALLING,

    /**
     * Audio or video bit rate is invalid.
     */
    TOX_ERR_AV_ANSWER_INVALID_BIT_RATE,
} Tox_Err_Av_Answer;

/**
 * Accept an incoming call.
 *
 * If answering fails for any reason, the call will still be pending and it is
 * possible to try and answer it later. Audio and video receiving are both
 * enabled by default.
 *
 * @param friend_number The friend number of the friend that is calling.
 * @param audio_bit_rate Audio bit rate in kbit/sec. Set this to 0 to disable
 *   audio sending.
 * @param video_bit_rate Video bit rate in kbit/sec. Set this to 0 to disable
 *   video sending.
 */
bool tox_av_answer(Tox_Av *_Nonnull av, Tox_Av_Friend_Number friend_number, uint32_t audio_bit_rate, uint32_t video_bit_rate,
                   Tox_Err_Av_Answer *_Nullable error);

/** @} */

/** @{
 * @brief Call state graph
 */

typedef enum Tox_Av_Friend_Call_State {
    /**
     * The empty bit mask. None of the bits specified below are set.
     */
    TOX_AV_FRIEND_CALL_STATE_NONE = 0,

    /**
     * Set by the AV core if an error occurred on the remote end or if friend
     * timed out. This is the final state after which no more state
     * transitions can occur for the call. This call state will never be
     * triggered in combination with other call states.
     */
    TOX_AV_FRIEND_CALL_STATE_ERROR = 1,

    /**
     * The call has finished. This is the final state after which no more state
     * transitions can occur for the call. This call state will never be
     * triggered in combination with other call states.
     */
    TOX_AV_FRIEND_CALL_STATE_FINISHED = 2,

    /**
     * The flag that marks that friend is sending audio.
     */
    TOX_AV_FRIEND_CALL_STATE_SENDING_A = 4,

    /**
     * The flag that marks that friend is sending video.
     */
    TOX_AV_FRIEND_CALL_STATE_SENDING_V = 8,

    /**
     * The flag that marks that friend is receiving audio.
     */
    TOX_AV_FRIEND_CALL_STATE_ACCEPTING_A = 16,

    /**
     * The flag that marks that friend is receiving video.
     */
    TOX_AV_FRIEND_CALL_STATE_ACCEPTING_V = 32,
} Tox_Av_Friend_Call_State;

/**
 * The function type for the call_state callback.
 *
 * @param friend_number The friend number for which the call state changed.
 * @param state The bitmask of the new call state which is guaranteed to be
 *   different than the previous state. The state is set to 0 when the call is
 *   paused. The bitmask represents all the activities currently performed by
 *   the friend.
 */
typedef void tox_av_call_state_cb(Tox_Av *_Nonnull av, Tox_Av_Friend_Number friend_number, uint32_t state, void *_Nullable user_data);

/**
 * Set the callback for the `call_state` event. Pass NULL to unset.
 */
void tox_av_callback_call_state(Tox_Av *_Nonnull av, tox_av_call_state_cb *_Nullable callback, void *_Nullable user_data);

/** @} */

/** @{
 * @brief Call control
 */

typedef enum Tox_Av_Call_Control {
    /**
     * Resume a previously paused call. Only valid if the pause was caused by
     * this client, if not, this control is ignored. Not valid before the call
     * is accepted.
     */
    TOX_AV_CALL_CONTROL_RESUME,

    /**
     * Put a call on hold. Not valid before the call is accepted.
     */
    TOX_AV_CALL_CONTROL_PAUSE,

    /**
     * Reject a call if it was not answered, yet. Cancel a call after it was
     * answered.
     */
    TOX_AV_CALL_CONTROL_CANCEL,

    /**
     * Request that the friend stops sending audio. Regardless of the friend's
     * compliance, this will cause the audio_receive_frame event to stop being
     * triggered on receiving an audio frame from the friend.
     */
    TOX_AV_CALL_CONTROL_MUTE_AUDIO,

    /**
     * Calling this control will notify client to start sending audio again.
     */
    TOX_AV_CALL_CONTROL_UNMUTE_AUDIO,

    /**
     * Request that the friend stops sending video. Regardless of the friend's
     * compliance, this will cause the video_receive_frame event to stop being
     * triggered on receiving a video frame from the friend.
     */
    TOX_AV_CALL_CONTROL_HIDE_VIDEO,

    /**
     * Calling this control will notify client to start sending video again.
     */
    TOX_AV_CALL_CONTROL_SHOW_VIDEO,
} Tox_Av_Call_Control;

typedef enum Tox_Err_Av_Call_Control {
    /**
     * The function returned successfully.
     */
    TOX_ERR_AV_CALL_CONTROL_OK,

    /**
     * Synchronization error occurred.
     */
    TOX_ERR_AV_CALL_CONTROL_SYNC,

    /**
     * This client is currently not in a call with the friend. Before the call
     * is answered, only CANCEL is a valid control.
     */
    TOX_ERR_AV_CALL_CONTROL_FRIEND_NOT_IN_CALL,

    /**
     * Happens if user tried to pause an already paused call or if trying to
     * resume a call that is not paused.
     */
    TOX_ERR_AV_CALL_CONTROL_INVALID_TRANSITION,
} Tox_Err_Av_Call_Control;

/**
 * Sends a call control command to a friend.
 *
 * @param friend_number The friend number of the friend this client is in a call
 *   with.
 * @param control The control command to send.
 *
 * @return true on success.
 */
bool tox_av_call_control(Tox_Av *_Nonnull av, Tox_Av_Friend_Number friend_number, Tox_Av_Call_Control control,
                         Tox_Err_Av_Call_Control *_Nullable error);

/** @} */

/** @{
 * @brief Controlling bit rates
 */

typedef enum Tox_Err_Av_Bit_Rate_Set {
    /**
     * The function returned successfully.
     */
    TOX_ERR_AV_BIT_RATE_SET_OK,

    /**
     * Synchronization error occurred.
     */
    TOX_ERR_AV_BIT_RATE_SET_SYNC,

    /**
     * The bit rate passed was not one of the supported values.
     */
    TOX_ERR_AV_BIT_RATE_SET_INVALID_BIT_RATE,

    /**
     * This client is currently not in a call with the friend.
     */
    TOX_ERR_AV_BIT_RATE_SET_FRIEND_NOT_IN_CALL,
} Tox_Err_Av_Bit_Rate_Set;

/** @} */

/** @{
 * @brief A/V sending
 */

typedef enum Tox_Err_Av_Send_Frame {
    /**
     * The function returned successfully.
     */
    TOX_ERR_AV_SEND_FRAME_OK,

    /**
     * In case of video, one of Y, U, or V was NULL. In case of audio, the
     * samples data pointer was NULL.
     */
    TOX_ERR_AV_SEND_FRAME_NULL,

    /**
     * This client is currently not in a call with the friend.
     */
    TOX_ERR_AV_SEND_FRAME_FRIEND_NOT_IN_CALL,

    /**
     * Synchronization error occurred.
     */
    TOX_ERR_AV_SEND_FRAME_SYNC,

    /**
     * One of the frame parameters was invalid. E.g. the resolution may be too
     * small or too large, or the audio sampling rate may be unsupported.
     */
    TOX_ERR_AV_SEND_FRAME_INVALID,

    /**
     * Either friend turned off audio or video receiving or we turned off
     * sending for the said payload.
     */
    TOX_ERR_AV_SEND_FRAME_PAYLOAD_TYPE_DISABLED,

    /**
     * Failed to push frame through RTP interface.
     */
    TOX_ERR_AV_SEND_FRAME_RTP_FAILED,
} Tox_Err_Av_Send_Frame;

/**
 * Send an audio frame to a friend.
 *
 * The expected format of the PCM data is:
 * `[s1c1][s1c2][...][s2c1][s2c2][...]...`
 * Meaning: sample 1 for channel 1, sample 1 for channel 2, ...
 * For mono audio, this has no meaning, every sample is subsequent. For stereo,
 * this means the expected format is LRLRLR... with samples for left and right
 * alternating.
 *
 * @param friend_number The friend number of the friend to which to send an
 *   audio frame.
 * @param pcm An array of audio samples. The size of this array must be
 *   `sample_count * channels`.
 * @param sample_count Number of samples in this frame. Valid numbers here are
 *   `((sample rate) * (audio length) / 1000)`, where audio length can be
 *   2.5, 5, 10, 20, 40 or 60 milliseconds.
 * @param channels Number of audio channels. Supported values are 1 and 2.
 * @param sampling_rate Audio sampling rate used in this frame. Valid sampling
 *   rates are 8000, 12000, 16000, 24000, or 48000.
 *
 * @thread any
 */
bool tox_av_audio_send_frame(Tox_Av *_Nonnull av, Tox_Av_Friend_Number friend_number, const int16_t pcm[_Nullable /*! sample_count * channels */],
                             size_t sample_count, uint8_t channels, uint32_t sampling_rate, Tox_Err_Av_Send_Frame *_Nullable error);

/**
 * Set the bit rate to be used in subsequent audio frames.
 *
 * @param friend_number The friend number of the friend for which to set the
 *   bit rate.
 * @param bit_rate The new audio bit rate in kbit/sec. Set to 0 to disable.
 *
 * @return true on success.
 */
bool tox_av_audio_set_bit_rate(Tox_Av *_Nonnull av, Tox_Av_Friend_Number friend_number, uint32_t bit_rate,
                               Tox_Err_Av_Bit_Rate_Set *_Nullable error);

/**
 * The function type for the audio_bit_rate callback. The event is triggered
 * when the network becomes too saturated for current bit rates at which point
 * Tox_Av suggests new bit rates.
 *
 * @param friend_number The friend number of the friend for which to set the
 *   bit rate.
 * @param audio_bit_rate Suggested maximum audio bit rate in kbit/sec.
 */
typedef void tox_av_audio_bit_rate_cb(Tox_Av *_Nonnull av, Tox_Av_Friend_Number friend_number, uint32_t audio_bit_rate,
                                      void *_Nullable user_data);

/**
 * Set the callback for the `audio_bit_rate` event. Pass NULL to unset.
 */
void tox_av_callback_audio_bit_rate(Tox_Av *_Nonnull av, tox_av_audio_bit_rate_cb *_Nullable callback, void *_Nullable user_data);

/**
 * Send a video frame to a friend.
 *
 * The video frame needs to be planar YUV420.
 * Y - plane should be of size: `width * height`
 * U - plane should be of size: `(width/2) * (height/2)`
 * V - plane should be of size: `(width/2) * (height/2)`
 *
 * @param friend_number The friend number of the friend to which to send a video
 *   frame.
 * @param width Width of the frame in pixels.
 * @param height Height of the frame in pixels.
 * @param y Y (Luminance) plane data.
 * @param u U (Chroma) plane data.
 * @param v V (Chroma) plane data.
 *
 * @thread any
 */
bool tox_av_video_send_frame(
    Tox_Av *_Nonnull av, Tox_Av_Friend_Number friend_number, uint16_t width, uint16_t height,
    const uint8_t y[_Nullable /*! width * height */],
    const uint8_t u[_Nullable /*! width/2 * height/2 */],
    const uint8_t v[_Nullable /*! width/2 * height/2 */],
    Tox_Err_Av_Send_Frame *_Nullable error);

/**
 * Set the bit rate to be used in subsequent video frames.
 *
 * @param friend_number The friend number of the friend for which to set the
 *   bit rate.
 * @param bit_rate The new video bit rate in kbit/sec. Set to 0 to disable.
 *
 * @return true on success.
 */
bool tox_av_video_set_bit_rate(Tox_Av *_Nonnull av, Tox_Av_Friend_Number friend_number, uint32_t bit_rate,
                               Tox_Err_Av_Bit_Rate_Set *_Nullable error);

/**
 * The function type for the video_bit_rate callback. The event is triggered
 * when the network becomes too saturated for current bit rates at which point
 * Tox_Av suggests new bit rates.
 *
 * @param friend_number The friend number of the friend for which to set the
 *   bit rate.
 * @param video_bit_rate Suggested maximum video bit rate in kbit/sec.
 */
typedef void tox_av_video_bit_rate_cb(Tox_Av *_Nonnull av, Tox_Av_Friend_Number friend_number, uint32_t video_bit_rate,
                                      void *_Nullable user_data);

/**
 * Set the callback for the `video_bit_rate` event. Pass NULL to unset.
 */
void tox_av_callback_video_bit_rate(Tox_Av *_Nonnull av, tox_av_video_bit_rate_cb *_Nullable callback, void *_Nullable user_data);

/** @} */

/** @{
 * @brief A/V receiving
 */

/**
 * The function type for the audio_receive_frame callback. The callback can be
 * called multiple times per single iteration depending on the amount of queued
 * frames in the buffer. The received format is the same as in send function.
 *
 * @param friend_number The friend number of the friend who sent an audio frame.
 * @param pcm An array of audio samples (`sample_count * channels` elements).
 * @param sample_count The number of audio samples per channel in the PCM array.
 * @param channels Number of audio channels.
 * @param sampling_rate Sampling rate used in this frame.
 */
typedef void tox_av_audio_receive_frame_cb(Tox_Av *_Nonnull av, Tox_Av_Friend_Number friend_number,
        const int16_t pcm[_Nonnull /*! sample_count * channels */], size_t sample_count,
        uint8_t channels, uint32_t sampling_rate, void *_Nullable user_data);

/**
 * Set the callback for the `audio_receive_frame` event. Pass NULL to unset.
 */
void tox_av_callback_audio_receive_frame(Tox_Av *_Nonnull av, tox_av_audio_receive_frame_cb *_Nullable callback, void *_Nullable user_data);

/**
 * The function type for the video_receive_frame callback.
 *
 * The size of plane data is derived from width and height as documented
 * below.
 *
 * Strides represent padding for each plane that may or may not be present.
 * You must handle strides in your image processing code. Strides are
 * negative if the image is bottom-up hence why you MUST `abs()` it when
 * calculating plane buffer size.
 *
 * @param friend_number The friend number of the friend who sent a video frame.
 * @param width Width of the frame in pixels.
 * @param height Height of the frame in pixels.
 * @param y Luminosity plane. `Size = MAX(width, abs(ystride)) * height`.
 * @param u U chroma plane. `Size = MAX((width+1)/2, abs(ustride)) * ((height+1)/2)`.
 * @param v V chroma plane. `Size = MAX((width+1)/2, abs(vstride)) * ((height+1)/2)`.
 * @param ystride Luminosity plane stride.
 * @param ustride U chroma plane stride.
 * @param vstride V chroma plane stride.
 */
typedef void tox_av_video_receive_frame_cb(
    Tox_Av *_Nonnull av, Tox_Av_Friend_Number friend_number,
    uint16_t width, uint16_t height,
    const uint8_t y[_Nonnull /*! max(width, abs(ystride)) * height */],
    const uint8_t u[_Nonnull /*! max((width+1)/2, abs(ustride)) * ((height+1)/2) */],
    const uint8_t v[_Nonnull /*! max((width+1)/2, abs(vstride)) * ((height+1)/2) */],
    int32_t ystride, int32_t ustride, int32_t vstride,
    void *_Nullable user_data);

/**
 * Set the callback for the `video_receive_frame` event. Pass NULL to unset.
 */
void tox_av_callback_video_receive_frame(Tox_Av *_Nonnull av, tox_av_video_receive_frame_cb *_Nullable callback, void *_Nullable user_data);

/** @} */

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* C_TOXCORE_TOXAV_TOX_AV_H */
