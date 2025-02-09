/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2022-2025 The TokTok team.
 */

#ifndef C_TOXCORE_TOXCORE_TOX_SYSTEM_IMPL_H
#define C_TOXCORE_TOXCORE_TOX_SYSTEM_IMPL_H

#ifdef __cplusplus
extern "C" {
#endif

struct Tox_Log;
struct Tox_Memory;
struct Tox_Network;
struct Tox_Random;
struct Tox_Time;

struct Tox_System {
    const struct Tox_Log *log;
    const struct Tox_Memory *mem;
    const struct Tox_Network *ns;
    const struct Tox_Random *rng;
    const struct Tox_Time *tm;
};

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* C_TOXCORE_TOXCORE_TOX_SYSTEM_IMPL_H */
