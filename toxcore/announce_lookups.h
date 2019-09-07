/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2020-2021 The TokTok team.
 */

/**
 * announce_lookups : supporting data structures for announce_client
 */

#ifndef C_TOXCORE_TOXCORE_ANNOUNCE_LOOKUPS_H
#define C_TOXCORE_TOXCORE_ANNOUNCE_LOOKUPS_H

#include "DHT.h"
#include "attributes.h"
#include "crypto_core.h"
#include "forwarding.h"
#include "mem.h"
#include "mono_time.h"
#include "timed_auth.h"

#ifdef __cplusplus
extern "C" {
#endif

#define PENDING_TIMEOUT 3

#define MAX_ROUTE_LENGTH (MAX_FORWARD_CHAIN_LENGTH + 1)

#define MAX_PACKED_NODE_SIZE (MAX_PACKED_IPPORT_SIZE + CRYPTO_PUBLIC_KEY_SIZE)
#define DATA_SEARCH_RESPONSE_MAX_SIZE (CRYPTO_PUBLIC_KEY_SIZE + 1 + CRYPTO_SHA256_SIZE +\
        TIMED_AUTH_SIZE + 1 + 1 + MAX_PACKED_NODE_SIZE * MAX_SENT_NODES)

typedef struct Lookup_Route {
    Node_format nodes[MAX_ROUTE_LENGTH];

    /* number of nodes after first */
    uint8_t chain_length;
} Lookup_Route;

const Node_format *_Nonnull route_destination(const Lookup_Route *_Nonnull route);
const uint8_t *_Nonnull route_destination_pk(const Lookup_Route *_Nonnull route);

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

typedef void on_delete_cb(void *_Nullable userdata);

typedef struct Lookup {
    uint8_t data_public_key[CRYPTO_PUBLIC_KEY_SIZE];
    uint16_t width;
    void *_Nullable userdata;
    on_delete_cb *_Nullable on_delete;

    Lookup_Node *_Nullable nodes;
    Pending_Response *_Nullable pending;

    uint8_t next_ping_i;
    uint64_t last_ping;

    uint64_t last_iteration;
} Lookup;

Lookup *_Nullable lookup_new(const Memory *_Nonnull mem, const uint8_t *_Nonnull data_public_key, uint16_t width,
                             void *_Nullable userdata, on_delete_cb *_Nullable on_delete);

void lookup_kill(const Memory *_Nonnull mem, Lookup *_Nonnull lookup);

Lookup_Node *_Nullable lookup_find_node(const Lookup *_Nonnull lookup, const uint8_t *_Nonnull public_key);

uint16_t num_lookup_nodes(const Lookup *_Nonnull lookup);

/**
 * Add node with route `route` if its public key is not `self_public_key` and
 * if `lookup` does not already contain the node and if `lookup` is not full
 * or if the new node is closer to `lookup->data_public_key` than the furthest
 * existing node, which is removed to make room.
 *
 * Invalidates references returned by `lookup_find_node`.
 *
 * Return true if node is added, false otherwise.
 */
bool lookup_add_node(Lookup *_Nonnull lookup, const Lookup_Route *_Nonnull route, const uint8_t *_Nullable self_public_key);

/** Returns the same truth value as `lookup_add_node` would, but has no effect. */
bool lookup_could_add_node(Lookup *_Nonnull lookup, const Lookup_Route *_Nonnull route, const uint8_t *_Nullable self_public_key);

/** Remove node from lookup. */
void delete_lookup_node(Lookup_Node *_Nonnull lookup_node);

/**
 * Adjust routes in light of validity of `route`:
 * Replace routes in `lookup` with initial segments of `route` where this does
 * not increase route lengths.
 */
void lookup_route_valid(Lookup *_Nonnull lookup, const Lookup_Route *_Nonnull route);

/**
 * Write the routes of nodes in `lookup` with shortest length to `routes`.
 * Write the number of these shortest routes to `num_routes`.
 * Return length of shortest routes, or `(MAX_ROUTE_LENGTH + 1)` if none.
 */
uint16_t get_shortest_routes(const Lookup *_Nonnull lookup, Lookup_Route *_Nonnull routes, uint16_t *_Nonnull num_routes);

/**
 * Add entry to pending response set, possibly displacing a timed out or more
 * distant entry.
 * Return true if the key could be added, false otherwise.
 */
bool add_pending(Lookup *_Nonnull lookup, const uint8_t *_Nonnull public_key, uint64_t ping_id, const Mono_Time *_Nonnull mono_time);

void delete_pending(Lookup *_Nonnull lookup, uint64_t ping_id);

typedef struct Lookups {
    Lookup *_Nonnull *_Nullable lookups;
    uint32_t num_lookups;
} Lookups;

/**
 * Add `lookup` to `lookups`.
 * Replaces any existing lookup with this public key.
 * Return false on failure, true otherwise.
 */
bool add_lookup(Lookups *_Nonnull lookups, const Memory *_Nonnull mem,
                const uint8_t *_Nonnull data_public_key, uint16_t width,
                void *_Nullable userdata, on_delete_cb *_Nullable on_delete);

Lookup *_Nullable find_lookup(const Lookups *_Nonnull lookups, const uint8_t *_Nonnull data_public_key);

/**
 * Delete lookup.
 * Return true if something was deleted, false otherwise.
 */
bool delete_lookup(Lookups *_Nonnull lookups, const Memory *_Nonnull mem, const uint8_t *_Nonnull data_public_key);

void free_lookups(Lookups *_Nonnull lookups, const Memory *_Nonnull mem);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* C_TOXCORE_TOXCORE_ANNOUNCE_LOOKUPS_H */
