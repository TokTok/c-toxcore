/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2022 The TokTok team.
 */

#include "internal.h"

#include <stdlib.h>
#include <string.h>

#include "../ccompat.h"

Tox_Events_State *tox_events_alloc(void *user_data)
{
    Tox_Events_State *state = (Tox_Events_State *)user_data;
    assert(state != nullptr);

    if (state->events == nullptr) {
        state->events = new (Tox_Events);
    }

    if (state->events == nullptr) {
        // It's still null => allocation failed.
        state->error = TOX_ERR_EVENTS_ITERATE_MALLOC;
    }

    return state;
}
