/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2018 The TokTok team.
 * Copyright © 2013 Tox project.
 */

#ifndef C_TOXCORE_TOXCORE_TOX_EVENTS_H
#define C_TOXCORE_TOXCORE_TOX_EVENTS_H

#include "tox.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct Tox_Event_Friend_Message Tox_Event_Friend_Message;

uint32_t tox_event_friend_message_get_friend_number(const Tox_Event_Friend_Message *friend_message);
Tox_Message_Type tox_event_friend_message_get_type(const Tox_Event_Friend_Message *friend_message);
uint16_t tox_event_friend_message_get_message_length(const Tox_Event_Friend_Message *friend_message);
uint8_t *tox_event_friend_message_get_message(const Tox_Event_Friend_Message *friend_message);

/**
 * TODO(iphydf): Document.
 */
typedef struct Tox_Events Tox_Events;

uint32_t tox_events_get_friend_messages_size(const Tox_Events *events);
const Tox_Event_Friend_Message *tox_events_get_friend_message(const Tox_Events *events, uint32_t index);

/**
 * TODO(iphydf): Document.
 */
void tox_events_init(Tox *tox);

/**
 * TODO(iphydf): Document.
 */
Tox_Events *tox_events_iterate(Tox *tox);

/**
 * TODO(iphydf): Document.
 */
void tox_events_free(Tox_Events *events);

#ifdef __cplusplus
}
#endif

#endif // C_TOXCORE_TOXCORE_TOX_EVENTS_H
