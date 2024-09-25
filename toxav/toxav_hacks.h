/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2018 The TokTok team.
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

non_null()
ToxAVCall *call_get(ToxAV *av, uint32_t friend_number);

non_null()
RTPSession *rtp_session_get(ToxAVCall *call, int payload_type);

non_null()
MSISession *tox_av_msi_get(const ToxAV *av);

non_null()
BWController *bwc_controller_get(const ToxAVCall *call);

non_null()
Mono_Time *toxav_get_av_mono_time(const ToxAV *av);

non_null()
const Logger *toxav_get_logger(const ToxAV *av);

#endif /* C_TOXCORE_TOXAV_HACKS_H */
