/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2020-2021 The TokTok team.
 */

#include "announce_lookups.h"

#include "ccompat.h"
#include "forwarding.h"
#include "util.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

const Node_format *route_destination(const Lookup_Route *route)
{
    return &route->nodes[route->chain_length];
}

const uint8_t *route_destination_pk(const Lookup_Route *route)
{
    return route_destination(route)->public_key;
}

non_null()
static const uint8_t *lookup_node_public_key(const Lookup_Node *lookup_node)
{
    return route_destination_pk(&lookup_node->route);
}

non_null(1) nullable(3, 4)
static Lookup *lookup_new(const uint8_t *data_public_key, uint16_t width,
                          void *userdata, void on_delete(void *userdata))
{
    Lookup *lookup = calloc(1, sizeof(Lookup));

    if (lookup == nullptr) {
        return nullptr;
    }

    memcpy(lookup->data_public_key, data_public_key, CRYPTO_PUBLIC_KEY_SIZE);
    lookup->width = width;
    lookup->userdata = userdata;
    lookup->on_delete = on_delete;
    lookup->nodes = calloc(width, sizeof(Lookup_Node));
    lookup->pending = calloc(width, sizeof(Pending_Response));

    if (lookup->nodes == nullptr || lookup->pending == nullptr) {
        lookup_kill(lookup);
        return nullptr;
    }

    return lookup;
}

void lookup_kill(Lookup *lookup)
{
    if (lookup->nodes != nullptr) {
        free(lookup->nodes);
    }

    if (lookup->pending != nullptr) {
        free(lookup->pending);
    }

    free(lookup);
}

Lookup_Node *lookup_find_node(const Lookup *lookup, const uint8_t *public_key)
{
    for (uint16_t i = 0; i < lookup->width; ++i) {
        Lookup_Node *lookup_node = &lookup->nodes[i];

        if (lookup_node->exists &&
                pk_equal(lookup_node_public_key(lookup_node), public_key)) {
            return lookup_node;
        }
    }

    return nullptr;
}

uint16_t num_lookup_nodes(const Lookup *lookup)
{
    uint16_t count = 0;

    for (uint16_t i = 0; i < lookup->width; ++i) {
        count += lookup->nodes[i].exists;
    }

    return count;
}

non_null(1, 2) nullable(3)
static bool lookup_add_node_opt(Lookup *lookup, const Lookup_Route *route,
                                const uint8_t *self_public_key, bool pretend)
{
    const uint8_t *new_public_key = route_destination(route)->public_key;

    if (self_public_key != nullptr && pk_equal(new_public_key, self_public_key)) {
        return false;
    }

    Lookup_Node *slot = nullptr;

    for (uint16_t i = 0; i < lookup->width; ++i) {
        Lookup_Node *lookup_node = &lookup->nodes[i];

        if (!lookup_node->exists) {
            slot = lookup_node;
            continue;
        }

        const uint8_t *public_key = lookup_node_public_key(lookup_node);

        if (pk_equal(new_public_key, public_key)) {
            return false;
        }

        if (slot != nullptr && !slot->exists) {
            continue;
        }

        if (id_closest(lookup->data_public_key, public_key,
                       slot == nullptr ? new_public_key : lookup_node_public_key(slot)) == 2) {
            slot = lookup_node;
        }
    }

    if (slot == nullptr) {
        return false;
    }

    if (!pretend) {
        memset(slot, 0, sizeof(Lookup_Node));
        slot->route = *route;
        slot->exists = true;
    }

    return true;
}

bool lookup_add_node(Lookup *lookup, const Lookup_Route *route, const uint8_t *self_public_key)
{
    return lookup_add_node_opt(lookup, route, self_public_key, false);
}

bool lookup_could_add_node(Lookup *lookup, const Lookup_Route *route, const uint8_t *self_public_key)
{
    return lookup_add_node_opt(lookup, route, self_public_key, true);
}

void delete_lookup_node(Lookup_Node *lookup_node)
{
    memset(lookup_node, 0, sizeof(Lookup_Node));
}

void lookup_route_valid(Lookup *lookup, const Lookup_Route *route)
{
    for (uint16_t i = 0; i < route->chain_length + 1; ++i) {
        Lookup_Node *lookup_node = lookup_find_node(lookup, route->nodes[i].public_key);

        if (lookup_node != nullptr &&
                lookup_node->route.chain_length >= i) {
            lookup_node->route = *route;
            lookup_node->route.chain_length = i;
        }
    }
}

uint16_t get_shortest_routes(const Lookup *lookup, Lookup_Route *routes, uint16_t *num_routes)
{
    uint16_t min_route_length = MAX_ROUTE_LENGTH + 1;
    *num_routes = 0;

    for (uint16_t i = 0; i < lookup->width; ++i) {
        const Lookup_Node *const lookup_node = &lookup->nodes[i];

        if (!lookup_node->exists) {
            continue;
        }

        const uint16_t route_length = lookup_node->route.chain_length + 1;

        if (route_length > min_route_length) {
            continue;
        }

        if (route_length < min_route_length) {
            min_route_length = route_length;
            *num_routes = 0;
        }

        routes[*num_routes] = lookup_node->route;
        ++(*num_routes);
    }

    return min_route_length;
}


bool add_pending(Lookup *lookup, const uint8_t *public_key, uint64_t ping_id, const Mono_Time *mono_time)
{
    Pending_Response *slot = nullptr;
    bool found_empty = false;

    for (uint16_t i = 0; i < lookup->width; ++i) {
        Pending_Response *pending = &lookup->pending[i];

        if (mono_time_is_timeout(mono_time, pending->timestamp, PENDING_TIMEOUT)) {
            slot = pending;
            found_empty = true;
        } else if (pk_equal(public_key, pending->public_key)) {
            return false;
        }

        if (!found_empty &&
                id_closest(lookup->data_public_key, pending->public_key,
                           slot == nullptr ? public_key : slot->public_key) == 2) {
            slot = pending;
        }
    }

    if (slot == nullptr) {
        return false;
    }

    memcpy(slot->public_key, public_key, CRYPTO_PUBLIC_KEY_SIZE);
    slot->ping_id = ping_id;
    slot->timestamp = mono_time_get(mono_time);

    return true;
}

void delete_pending(Lookup *lookup, uint64_t ping_id)
{
    for (uint16_t i = 0; i < lookup->width; ++i) {
        if (lookup->pending[i].ping_id == ping_id) {
            lookup->pending[i].timestamp = 0;
            break;
        }
    }
}


bool add_lookup(Lookups *lookups,
                const uint8_t *data_public_key, uint16_t width,
                void *userdata, void on_delete(void *userdata))
{
    if (find_lookup(lookups, data_public_key) != nullptr) {
        return false;
    }

    if (lookups->num_lookups == UINT32_MAX) {
        return false;
    }

    Lookup *const lookup = lookup_new(data_public_key, width, userdata, on_delete);

    if (lookup == nullptr) {
        return false;
    }

    Lookup **const temp = (lookups->num_lookups == 0) ?
                          (Lookup **)malloc(sizeof(Lookup *)) :
                          (Lookup **)realloc(lookups->lookups,
                                  sizeof(Lookup *) * (lookups->num_lookups + 1));

    if (temp == nullptr) {
        lookup_kill(lookup);
        return false;
    }

    lookups->lookups = temp;
    lookups->lookups[lookups->num_lookups] = lookup;
    ++lookups->num_lookups;

    return true;
}

Lookup *find_lookup(const Lookups *lookups, const uint8_t *data_public_key)
{
    for (uint32_t i = 0; i < lookups->num_lookups; ++i) {
        if (pk_equal(data_public_key, lookups->lookups[i]->data_public_key)) {
            return lookups->lookups[i];
        }
    }

    return nullptr;
}


bool delete_lookup(Lookups *lookups, const uint8_t *data_public_key)
{
    for (uint32_t i = 0; i < lookups->num_lookups; ++i) {
        Lookup *const lookup = lookups->lookups[i];

        if (pk_equal(data_public_key, lookup->data_public_key)) {
            --lookups->num_lookups;

            if (lookups->num_lookups == 0) {
                free(lookups->lookups);
                lookups->lookups = nullptr;
            } else {
                lookups->lookups[i] = lookups->lookups[lookups->num_lookups];

                Lookup **const temp = (Lookup **)realloc(lookups->lookups,
                                      sizeof(Lookup *) * (lookups->num_lookups));

                if (temp != nullptr) {
                    lookups->lookups = temp;
                }
            }

            if (lookup->on_delete != nullptr) {
                lookup->on_delete(lookup->userdata);
            }

            lookup_kill(lookup);

            return true;
        }
    }

    return false;
}

void free_lookups(Lookups *lookups)
{
    while (lookups->num_lookups > 0) {
        delete_lookup(lookups, lookups->lookups[0]->data_public_key);
    }
}
