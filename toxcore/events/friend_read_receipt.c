/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2022 The TokTok team.
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
#include "event_macros.h"


/*****************************************************
 *
 * :: struct and accessors
 *
 *****************************************************/


struct Tox_Event_Friend_Read_Receipt {
    uint32_t friend_number;
    uint32_t message_id;
};

EV_ACCESS_VALUE(Friend_Read_Receipt, friend_read_receipt, uint32_t, friend_number)
EV_ACCESS_VALUE(Friend_Read_Receipt, friend_read_receipt, uint32_t, message_id)

non_null()
static void tox_event_friend_read_receipt_construct(Tox_Event_Friend_Read_Receipt *friend_read_receipt)
{
    *friend_read_receipt = (Tox_Event_Friend_Read_Receipt) {
        0
    };
}
non_null()
static void tox_event_friend_read_receipt_destruct(Tox_Event_Friend_Read_Receipt *friend_read_receipt, const Memory *mem)
{
    return;
}

bool tox_event_friend_read_receipt_pack(
    const Tox_Event_Friend_Read_Receipt *event, Bin_Pack *bp)
{
    assert(event != nullptr);
    return bin_pack_array(bp, 2)
           && bin_pack_u32(bp, TOX_EVENT_FRIEND_READ_RECEIPT)
           && bin_pack_array(bp, 2)
           && bin_pack_u32(bp, event->friend_number)
           && bin_pack_u32(bp, event->message_id);
}

non_null()
static bool tox_event_friend_read_receipt_unpack_into(
    Tox_Event_Friend_Read_Receipt *event, Bin_Unpack *bu)
{
    assert(event != nullptr);
    if (!bin_unpack_array_fixed(bu, 2)) {
        return false;
    }

    return bin_unpack_u32(bu, &event->friend_number)
           && bin_unpack_u32(bu, &event->message_id);
}

EV_FUNCS(Friend_Read_Receipt, friend_read_receipt, FRIEND_READ_RECEIPT)


/*****************************************************
 *
 * :: event handler
 *
 *****************************************************/


void tox_events_handle_friend_read_receipt(Tox *tox, uint32_t friend_number, uint32_t message_id, void *user_data)
{
    Tox_Event_Friend_Read_Receipt *friend_read_receipt = tox_event_friend_read_receipt_alloc(user_data);

    if (friend_read_receipt == nullptr) {
        return;
    }

    tox_event_friend_read_receipt_set_friend_number(friend_read_receipt, friend_number);
    tox_event_friend_read_receipt_set_message_id(friend_read_receipt, message_id);
}
