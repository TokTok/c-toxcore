/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2025 The TokTok team.
 * Copyright © 2013-2015 Tox project.
 */
#ifndef C_TOXCORE_TOXAV_HACKS_H
#define C_TOXCORE_TOXAV_HACKS_H

#include "bwcontroller.h"
#include "msi.h"
#include "rtp.h"

#ifndef TOXAV_CALL_DEFINED
#define TOXAV_CALL_DEFINED
typedef struct ToxAVCall ToxAVCall;
#endif /* TOXAV_CALL_DEFINED */

ToxAVCall *_Nullable call_get(ToxAV *_Nonnull av, uint32_t friend_number);

RTPSession *_Nullable rtp_session_get(ToxAVCall *_Nonnull call, int payload_type);

MSISession *_Nullable tox_av_msi_get(const ToxAV *_Nonnull av);

BWController *_Nullable bwc_controller_get(const ToxAVCall *_Nonnull call);

const Logger *_Nonnull toxav_get_logger(const ToxAV *_Nonnull av);

#endif /* C_TOXCORE_TOXAV_HACKS_H */
