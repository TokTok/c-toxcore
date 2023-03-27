/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2023 The TokTok team.
 */

#include "events_alloc.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "../bin_pack.h"
#include "../bin_unpack.h"
#include "../ccompat.h"
#include "../tox.h"
#include "../tox_events.h"
#include "../tox_unpack.h"


/*****************************************************
 *
 * :: struct and accessors
 *
 *****************************************************/


struct Tox_Event_Group_Password {
    uint32_t group_number;
    uint8_t *password;
    uint32_t password_length;
};

non_null()
static void tox_event_group_password_construct(Tox_Event_Group_Password *group_password)
{
    *group_password = (Tox_Event_Group_Password) {
        0
    };
}
non_null()
static void tox_event_group_password_destruct(Tox_Event_Group_Password *group_password)
{
    free(group_password->password);
}

non_null()
static void tox_event_group_password_set_group_number(Tox_Event_Group_Password *group_password,
        uint32_t group_number)
{
    assert(group_password != nullptr);
    group_password->group_number = group_number;
}
uint32_t tox_event_group_password_get_group_number(const Tox_Event_Group_Password *group_password)
{
    assert(group_password != nullptr);
    return group_password->group_number;
}

non_null()
static bool tox_event_group_password_set_password(Tox_Event_Group_Password *group_password,
        const uint8_t *password, uint32_t password_length)
{
    assert(group_password != nullptr);

    if (group_password->password != nullptr) {
        free(group_password->password);
        group_password->password = nullptr;
        group_password->password_length = 0;
    }

    group_password->password = (uint8_t *)malloc(password_length);

    if (group_password->password == nullptr) {
        return false;
    }

    memcpy(group_password->password, password, password_length);
    group_password->password_length = password_length;
    return true;
}
size_t tox_event_group_password_get_password_length(const Tox_Event_Group_Password *group_password)
{
    assert(group_password != nullptr);
    return group_password->password_length;
}
const uint8_t *tox_event_group_password_get_password(const Tox_Event_Group_Password *group_password)
{
    assert(group_password != nullptr);
    return group_password->password;
}

non_null()
static bool tox_event_group_password_pack(
    const Tox_Event_Group_Password *event, Bin_Pack *bp)
{
    assert(event != nullptr);
    return bin_pack_array(bp, 2)
           && bin_pack_u32(bp, TOX_EVENT_GROUP_PASSWORD)
           && bin_pack_array(bp, 2)
           && bin_pack_u32(bp, event->group_number)
           && bin_pack_bin(bp, event->password, event->password_length);
}

non_null()
static bool tox_event_group_password_unpack(
    Tox_Event_Group_Password *event, Bin_Unpack *bu)
{
    assert(event != nullptr);
    if (!bin_unpack_array_fixed(bu, 2, nullptr)) {
        return false;
    }

    return bin_unpack_u32(bu, &event->group_number)
           && bin_unpack_bin(bu, &event->password, &event->password_length);
}


/*****************************************************
 *
 * :: add/clear/get
 *
 *****************************************************/


non_null()
static Tox_Event_Group_Password *tox_events_add_group_password(Tox_Events *events)
{
    if (events->group_password_size == UINT32_MAX) {
        return nullptr;
    }

    if (events->group_password_size == events->group_password_capacity) {
        const uint32_t new_group_password_capacity = events->group_password_capacity * 2 + 1;
        Tox_Event_Group_Password *new_group_password = (Tox_Event_Group_Password *)
                realloc(
                    events->group_password,
                    new_group_password_capacity * sizeof(Tox_Event_Group_Password));

        if (new_group_password == nullptr) {
            return nullptr;
        }

        events->group_password = new_group_password;
        events->group_password_capacity = new_group_password_capacity;
    }

    Tox_Event_Group_Password *const group_password =
        &events->group_password[events->group_password_size];
    tox_event_group_password_construct(group_password);
    ++events->group_password_size;
    return group_password;
}

void tox_events_clear_group_password(Tox_Events *events)
{
    if (events == nullptr) {
        return;
    }

    for (uint32_t i = 0; i < events->group_password_size; ++i) {
        tox_event_group_password_destruct(&events->group_password[i]);
    }

    free(events->group_password);
    events->group_password = nullptr;
    events->group_password_size = 0;
    events->group_password_capacity = 0;
}

uint32_t tox_events_get_group_password_size(const Tox_Events *events)
{
    if (events == nullptr) {
        return 0;
    }

    return events->group_password_size;
}

const Tox_Event_Group_Password *tox_events_get_group_password(const Tox_Events *events, uint32_t index)
{
    assert(index < events->group_password_size);
    assert(events->group_password != nullptr);
    return &events->group_password[index];
}

bool tox_events_pack_group_password(const Tox_Events *events, Bin_Pack *bp)
{
    const uint32_t size = tox_events_get_group_password_size(events);

    for (uint32_t i = 0; i < size; ++i) {
        if (!tox_event_group_password_pack(tox_events_get_group_password(events, i), bp)) {
            return false;
        }
    }
    return true;
}

bool tox_events_unpack_group_password(Tox_Events *events, Bin_Unpack *bu)
{
    Tox_Event_Group_Password *event = tox_events_add_group_password(events);

    if (event == nullptr) {
        return false;
    }

    return tox_event_group_password_unpack(event, bu);
}


/*****************************************************
 *
 * :: event handler
 *
 *****************************************************/


void tox_events_handle_group_password(Tox *tox, uint32_t group_number, const uint8_t *password, size_t length,
        void *user_data)
{
    Tox_Events_State *state = tox_events_alloc(user_data);
    assert(state != nullptr);

    if (state->events == nullptr) {
        return;
    }

    Tox_Event_Group_Password *group_password = tox_events_add_group_password(state->events);

    if (group_password == nullptr) {
        state->error = TOX_ERR_EVENTS_ITERATE_MALLOC;
        return;
    }

    tox_event_group_password_set_group_number(group_password, group_number);
    tox_event_group_password_set_password(group_password, password, length);
}
