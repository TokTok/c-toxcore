/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2025 The TokTok team.
 * Copyright © 2014 Tox project.
 */

/**
 * Handle friend requests.
 */
#ifndef C_TOXCORE_TOXCORE_FRIEND_REQUESTS_H
#define C_TOXCORE_TOXCORE_FRIEND_REQUESTS_H

#include <stddef.h>

#include "attributes.h"
#include "friend_connection.h"
#include "mem.h"

// TODO(Jfreegman): This should be the maximum size that an onion client can handle.
#define MAX_FRIEND_REQUEST_DATA_SIZE (ONION_CLIENT_MAX_DATA_SIZE - 100)

typedef struct Friend_Requests Friend_Requests;

/** Set and get the nospam variable used to prevent one type of friend request spam. */
void set_nospam(non_null() Friend_Requests *fr, uint32_t num);
uint32_t get_nospam(non_null() const Friend_Requests *fr);

/** @brief Remove real_pk from received_requests list.
 *
 * @retval 0 if it removed it successfully.
 * @retval -1 if it didn't find it.
 */
int remove_request_received(non_null() Friend_Requests *fr, non_null() const uint8_t *real_pk);

typedef void fr_friend_request_cb(void *object, const uint8_t *public_key, const uint8_t *message, size_t length,
                                  void *user_data);

/** Set the function that will be executed when a friend request for us is received. */
void callback_friendrequest(non_null() Friend_Requests *fr, non_null() fr_friend_request_cb *function, non_null() void *object);

typedef int filter_function_cb(void *object, const uint8_t *public_key);

/** @brief Set the function used to check if a friend request should be displayed to the user or not.
 * It must return 0 if the request is ok (anything else if it is bad).
 */
void set_filter_function(non_null() Friend_Requests *fr, non_null() filter_function_cb *function, non_null() void *userdata);

/** Sets up friendreq packet handlers. */
void friendreq_init(non_null() Friend_Requests *fr, non_null() Friend_Connections *fr_c);

Friend_Requests *friendreq_new(non_null() const Memory *mem);

void friendreq_kill(nullable() Friend_Requests *fr);
#endif /* C_TOXCORE_TOXCORE_FRIEND_REQUESTS_H */
