/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2020-2021 The TokTok team.
 */

/* announce_lookups : supporting data structures for announce_client */

#ifndef C_TOXCORE_TOXCORE_ANNOUNCE_LOOKUPS_H
#define C_TOXCORE_TOXCORE_ANNOUNCE_LOOKUPS_H

#include "DHT.h"
#include "forwarding.h"
#include "timed_auth.h"

#define PENDING_TIMEOUT 3

#define MAX_ROUTE_LENGTH (MAX_FORWARD_CHAIN_LENGTH + 1)

#define MAX_PACKED_NODE_SIZE (MAX_PACKED_IPPORT_SIZE + CRYPTO_PUBLIC_KEY_SIZE)
#define DATA_SEARCH_RESPONSE_MAX_SIZE (CRYPTO_PUBLIC_KEY_SIZE + 1 + CRYPTO_SHA256_SIZE +\
        TIMED_AUTH_SIZE + 1 + 1 + MAX_PACKED_NODE_SIZE * MAX_SENT_NODES)

typedef struct Lookup_Route {
    Node_format nodes[MAX_ROUTE_LENGTH];

    /* number of nodes after first */
    uint16_t chain_length;
} Lookup_Route;

non_null()
const Node_format *route_destination(const Lookup_Route *route);
non_null()
const uint8_t *route_destination_pk(const Lookup_Route *route);

typedef struct Lookup_Node {
    bool exists;
    Lookup_Route route;

    uint8_t last_search_response_data[DATA_SEARCH_RESPONSE_MAX_SIZE];
    uint16_t last_search_response_size;
    uint8_t last_search_response_hash[CRYPTO_SHA256_SIZE];

    uint16_t sent_no_response_times;
    uint64_t sent_no_response_last;
    uint64_t retry_after;

    uint64_t last_search_response_time;

    uint32_t ping_backoff;

    uint32_t stored_timeout;
    uint64_t stored_since;
    uint64_t unix_time;
} Lookup_Node;

typedef struct Pending_Response {
    uint8_t public_key[CRYPTO_PUBLIC_KEY_SIZE];
    uint64_t ping_id;
    uint64_t timestamp;
} Pending_Response;

typedef struct Lookup {
    uint8_t data_public_key[CRYPTO_PUBLIC_KEY_SIZE];
    uint16_t width;
    void *userdata;
    void (*on_delete)(void *userdata);

    Lookup_Node *nodes;
    Pending_Response *pending;

    uint8_t next_ping_i;
    uint64_t last_ping;

    uint64_t last_iteration;
} Lookup;

non_null()
void lookup_kill(Lookup *lookup);

non_null()
Lookup_Node *lookup_find_node(const Lookup *lookup, const uint8_t *public_key);

non_null()
uint16_t num_lookup_nodes(const Lookup *lookup);

/** Add node with route `route` if its public key is not `self_public_key` and
 * if `lookup` does not already contain the node and if `lookup` is not full
 * or if the new node is closer to `lookup->data_public_key` than the furthest
 * existing node, which is removed to make room.
 *
 * Invalidates references returned by `lookup_find_node`.
 *
 * Return true if node is added, false otherwise.
 */
non_null(1, 2) nullable(3)
bool lookup_add_node(Lookup *lookup, const Lookup_Route *route, const uint8_t *self_public_key);

/** Returns the same truth value as `lookup_add_node` would, but has no effect.
 */
non_null(1, 2) nullable(3)
bool lookup_could_add_node(Lookup *lookup, const Lookup_Route *route, const uint8_t *self_public_key);

/** Remove node from lookup.
 */
non_null()
void delete_lookup_node(Lookup_Node *lookup_node);

/** Adjust routes in light of validity of `route`:
 * Replace routes in `lookup` with initial segments of `route` where this does
 * not increase route lengths.
 */
non_null()
void lookup_route_valid(Lookup *lookup, const Lookup_Route *route);

/** Write the routes of nodes in `lookup` with shortest length to `routes`.
 * Write the number of these shortest routes to `num_routes`.
 * Return length of shortest routes, or `(MAX_ROUTE_LENGTH + 1)` if none.
 */
non_null()
uint16_t get_shortest_routes(const Lookup *lookup, Lookup_Route *routes, uint16_t *num_routes);

/** Add entry to pending response set, possibly displacing a timed out or more
 * distant entry.
 * Return true if the key could be added, false otherwise.
 */
non_null()
bool add_pending(Lookup *lookup, const uint8_t *public_key, uint64_t ping_id, const Mono_Time *mono_time);

non_null()
void delete_pending(Lookup *lookup, uint64_t ping_id);

typedef struct Lookups {
    Lookup **lookups;
    uint32_t num_lookups;
} Lookups;

/** Add `lookup` to `lookups`.
 * Fail if there is an existing lookup with this public key.
 * Return false on failure, true otherwise.
 */
non_null(1, 2) nullable(4, 5)
bool add_lookup(Lookups *lookups,
                const uint8_t *data_public_key, uint16_t width,
                void *userdata, void on_delete(void *userdata));

non_null()
Lookup *find_lookup(const Lookups *lookups, const uint8_t *data_public_key);

/** Delete lookup.
 * Return true if something was deleted, false otherwise.
 */
non_null()
bool delete_lookup(Lookups *lookups, const uint8_t *data_public_key);

non_null()
void free_lookups(Lookups *lookups);
#endif
