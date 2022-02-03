/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2022 The TokTok team.
 */

#include "tox_events.h"

#include <stdlib.h>
#include <string.h>

#include "ccompat.h"
#include "events/internal.h"
#include "tox.h"


/*****************************************************
 *
 * :: Set up event handlers.
 *
 *****************************************************/


void tox_events_init(Tox *tox)
{
    tox_callback_friend_message(tox, tox_events_handle_friend_message);
}

Tox_Events *tox_events_iterate(Tox *tox, Tox_Err_Events_Iterate *error)
{
    Tox_Events_State state = {0};
    tox_iterate(tox, &state);
    if (error != nullptr) {
        *error = state.error;
    }
    return state.events;
}

void tox_events_free(Tox_Events *events)
{
    if (events == nullptr) {
        return;
    }

    tox_events_clear_friend_messages(events);
    delete (events);
}
