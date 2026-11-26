/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2026 The TokTok team.
 */
#ifndef C_TOXCORE_TOXAV_TOX_AV_PRIVATE_H
#define C_TOXCORE_TOXAV_TOX_AV_PRIVATE_H

#include "tox_av.h"

#include "../toxcore/mem.h"
#include "../toxcore/mono_time.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum Tox_Err_Av_New_Testing {
    TOX_ERR_AV_NEW_TESTING_OK,
    TOX_ERR_AV_NEW_TESTING_NULL,
    TOX_ERR_AV_NEW_TESTING_MALLOC,
} Tox_Err_Av_New_Testing;

/**
 * @brief Like tox_av_new, with this memory and clock.
 *
 * @param current_time The monotonic clock, or NULL for the system's.
 */
Tox_Av *_Nullable tox_av_new_testing(const Memory *_Nullable mem, mono_time_current_time_cb *_Nullable current_time,
                                     void *_Nullable current_time_user_data, Tox_Err_Av_New_Testing *_Nullable error);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* C_TOXCORE_TOXAV_TOX_AV_PRIVATE_H */
