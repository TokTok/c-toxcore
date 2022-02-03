/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2018 The TokTok team.
 * Copyright © 2013 Tox project.
 */

#include "internal.h"

#include <stdlib.h>
#include <string.h>

#include "../ccompat.h"
#include "../tox.h"
#include "../tox_events.h"


/*****************************************************
 *
 * :: struct and accessors
 *
 *****************************************************/


struct Tox_Event_Friend_Message {
    uint32_t friend_number;
    Tox_Message_Type type;
    uint8_t *message;
    size_t message_length;
};

static void tox_event_friend_message_construct(Tox_Event_Friend_Message *friend_message)
{
    *friend_message = (Tox_Event_Friend_Message) {
        0
    };
}
static void tox_event_friend_message_destruct(Tox_Event_Friend_Message *friend_message)
{
    free(friend_message->message);
}

static void tox_event_friend_message_set_friend_number(Tox_Event_Friend_Message *friend_message,
        uint32_t friend_number)
{
    assert(friend_message != nullptr);
    friend_message->friend_number = friend_number;
}
uint32_t tox_event_friend_message_get_friend_number(const Tox_Event_Friend_Message *friend_message)
{
    assert(friend_message != nullptr);
    return friend_message->friend_number;
}

static void tox_event_friend_message_set_type(Tox_Event_Friend_Message *friend_message, Tox_Message_Type type)
{
    assert(friend_message != nullptr);
    friend_message->type = type;
}
Tox_Message_Type tox_event_friend_message_get_type(const Tox_Event_Friend_Message *friend_message)
{
    assert(friend_message != nullptr);
    return friend_message->type;
}

static bool tox_event_friend_message_set_message(Tox_Event_Friend_Message *friend_message, const uint8_t *message,
        size_t message_length)
{
    assert(friend_message != nullptr);

    if (friend_message->message != nullptr) {
        free(friend_message->message);
        friend_message->message = nullptr;
        friend_message->message_length = 0;
    }

    friend_message->message = (uint8_t *)malloc(message_length);

    if (friend_message->message == nullptr) {
        return false;
    }

    memcpy(friend_message->message, message, message_length);
    friend_message->message_length = message_length;
    return true;
}
size_t tox_event_friend_message_get_message_length(const Tox_Event_Friend_Message *friend_message)
{
    assert(friend_message != nullptr);
    return friend_message->message_length;
}
uint8_t *tox_event_friend_message_get_message(const Tox_Event_Friend_Message *friend_message)
{
    assert(friend_message != nullptr);
    return friend_message->message;
}


/*****************************************************
 *
 * :: add/clear/get
 *
 *****************************************************/


static Tox_Event_Friend_Message *tox_events_add_friend_message(Tox_Events *events)
{
    if (events->friend_messages_size == UINT32_MAX) {
        return nullptr;
    }

    if (events->friend_messages_size == events->friend_messages_capacity) {
        const uint32_t new_friend_messages_capacity = events->friend_messages_capacity * 2 + 1;
        Tox_Event_Friend_Message *new_friend_messages = (Tox_Event_Friend_Message *)realloc(
                    events->friend_messages, new_friend_messages_capacity * sizeof(Tox_Event_Friend_Message));

        if (new_friend_messages == nullptr) {
            return nullptr;
        }

        events->friend_messages = new_friend_messages;
        events->friend_messages_capacity = new_friend_messages_capacity;
    }

    Tox_Event_Friend_Message *const friend_message = &events->friend_messages[events->friend_messages_size];
    tox_event_friend_message_construct(friend_message);
    ++events->friend_messages_size;
    return friend_message;
}

void tox_events_clear_friend_messages(Tox_Events *events)
{
    if (events == nullptr) {
        return;
    }

    for (uint32_t i = 0; i < events->friend_messages_size; ++i) {
        tox_event_friend_message_destruct(&events->friend_messages[i]);
    }

    free(events->friend_messages);
    events->friend_messages = nullptr;
    events->friend_messages_size = 0;
    events->friend_messages_capacity = 0;
}

uint32_t tox_events_get_friend_messages_size(const Tox_Events *events)
{
    return events->friend_messages_size;
}

const Tox_Event_Friend_Message *tox_events_get_friend_message(const Tox_Events *events, uint32_t index)
{
    assert(index < events->friend_messages_size);
    assert(events->friend_messages != nullptr);
    return &events->friend_messages[index];
}


/*****************************************************
 *
 * :: event handler
 *
 *****************************************************/


void tox_events_handle_friend_message(Tox *tox, uint32_t friend_number, Tox_Message_Type type, const uint8_t *message,
                                      size_t length, void *user_data)
{
    Tox_Events *events = tox_events_alloc(user_data);

    if (events == nullptr) {
        return;
    }

    Tox_Event_Friend_Message *friend_message = tox_events_add_friend_message(events);

    if (friend_message == nullptr) {
        return;
    }

    tox_event_friend_message_set_friend_number(friend_message, friend_number);
    tox_event_friend_message_set_type(friend_message, type);
    tox_event_friend_message_set_message(friend_message, message, length);
}
