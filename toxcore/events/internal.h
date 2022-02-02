/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2018 The TokTok team.
 * Copyright © 2013 Tox project.
 */

#ifndef C_TOXCORE_TOXCORE_TOX_EVENTS_INTERNAL_H
#define C_TOXCORE_TOXCORE_TOX_EVENTS_INTERNAL_H

#include "../tox_events.h"

#ifdef __cplusplus
extern "C" {
#endif

struct Tox_Events {
    Tox_Event_Friend_Message *friend_messages;
    uint32_t friend_messages_size;
    uint32_t friend_messages_capacity;
};

tox_friend_message_cb tox_events_handle_friend_message;
void tox_events_clear_friend_messages(Tox_Events *events);

Tox_Events *tox_events_alloc(void *user_data);

#ifdef __cplusplus
}
#endif

#endif // C_TOXCORE_TOXCORE_TOX_EVENTS_INTERNAL_H
