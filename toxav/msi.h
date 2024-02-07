/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2018 The TokTok team.
 * Copyright © 2013-2015 Tox project.
 */
#ifndef C_TOXCORE_TOXAV_MSI_H
#define C_TOXCORE_TOXAV_MSI_H

#include <pthread.h>
#include <stdint.h>

#include "audio.h"
#include "video.h"

#include "../toxcore/logger.h"

/**
 * Error codes.
 */
typedef enum MSIError {
    MSI_E_NONE,
    MSI_E_INVALID_MESSAGE,
    MSI_E_INVALID_PARAM,
    MSI_E_INVALID_STATE,
    MSI_E_STRAY_MESSAGE,
    MSI_E_SYSTEM,
    MSI_E_HANDLE,
    MSI_E_UNDISCLOSED, /* NOTE: must be last enum otherwise parsing will not work */
} MSIError;

/**
 * Supported capabilities
 */
typedef enum MSICapabilities {
    MSI_CAP_S_AUDIO = 4,  /* sending audio */
    MSI_CAP_S_VIDEO = 8,  /* sending video */
    MSI_CAP_R_AUDIO = 16, /* receiving audio */
    MSI_CAP_R_VIDEO = 32, /* receiving video */
} MSICapabilities;

/**
 * Call state identifiers.
 */
typedef enum MSICallState {
    MSI_CALL_INACTIVE = 0, /* Default */
    MSI_CALL_ACTIVE = 1,
    MSI_CALL_REQUESTING = 2, /* when sending call invite */
    MSI_CALL_REQUESTED = 3, /* when getting call invite */
} MSICallState;

/**
 * Callbacks ids that handle the states
 */
typedef enum MSICallbackID {
    MSI_ON_INVITE = 0, /* Incoming call */
    MSI_ON_START = 1, /* Call (RTP transmission) started */
    MSI_ON_END = 2, /* Call that was active ended */
    MSI_ON_ERROR = 3, /* On protocol error */
    MSI_ON_PEERTIMEOUT = 4, /* Peer timed out; stop the call */
    MSI_ON_CAPABILITIES = 5, /* Peer requested capabilities change */
} MSICallbackID;

/**
 * The call struct. Please do not modify outside msi.c
 */
typedef struct MSICall {
    struct MSISession *session;           /* Session pointer */

    MSICallState         state;
    uint8_t              peer_capabilities; /* Peer capabilities */
    uint8_t              self_capabilities; /* Self capabilities */
    uint16_t             peer_vfpsz;        /* Video frame piece size */
    uint32_t             friend_number;     /* Index of this call in MSISession */
    MSIError             error;             /* Last error */

    struct ToxAVCall     *av_call;           /* Pointer to av call handler */

    struct MSICall       *next;
    struct MSICall       *prev;
} MSICall;

/**
 * Expected return on success is 0, if any other number is
 * returned the call is considered errored and will be handled
 * as such which means it will be terminated without any notice.
 */
typedef int msi_action_cb(void *object, MSICall *call);

/**
 * Control session struct. Please do not modify outside msi.c
 */
typedef struct MSISession {
    /* Call handlers */
    MSICall       **calls;
    uint32_t        calls_tail;
    uint32_t        calls_head;

    void           *av;
    Tox            *tox;

    pthread_mutex_t mutex[1];

    msi_action_cb *invite_callback;
    msi_action_cb *start_callback;
    msi_action_cb *end_callback;
    msi_action_cb *error_callback;
    msi_action_cb *peertimeout_callback;
    msi_action_cb *capabilities_callback;
} MSISession;

/**
 * Start the control session.
 */
MSISession *msi_new(const Logger *log, Tox *tox);
/**
 * Terminate control session. NOTE: all calls will be freed
 */
int msi_kill(const Logger *log, Tox *tox, MSISession *session);
/**
 * Callback setters.
 */
void msi_callback_invite(MSISession *session, msi_action_cb *callback);
void msi_callback_start(MSISession *session, msi_action_cb *callback);
void msi_callback_end(MSISession *session, msi_action_cb *callback);
void msi_callback_error(MSISession *session, msi_action_cb *callback);
void msi_callback_peertimeout(MSISession *session, msi_action_cb *callback);
void msi_callback_capabilities(MSISession *session, msi_action_cb *callback);
/**
 * Send invite request to friend_number.
 */
int msi_invite(const Logger *log, MSISession *session, MSICall **call, uint32_t friend_number, uint8_t capabilities);
/**
 * Hangup call. NOTE: `call` will be freed
 */
int msi_hangup(const Logger *log, MSICall *call);
/**
 * Answer call request.
 */
int msi_answer(const Logger *log, MSICall *call, uint8_t capabilities);
/**
 * Change capabilities of the call.
 */
int msi_change_capabilities(const Logger *log, MSICall *call, uint8_t capabilities);

bool check_peer_offline_status(const Logger *log, const Tox *tox, MSISession *session, uint32_t friend_number);

#endif /* C_TOXCORE_TOXAV_MSI_H */
