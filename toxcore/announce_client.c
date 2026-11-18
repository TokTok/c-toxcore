/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2020-2021 The TokTok team.
 */

#include "announce_client.h"

#include <assert.h>
#include <string.h>

#include "DHT.h"
#include "announce.h"
#include "announce_lookups.h"
#include "attributes.h"
#include "ccompat.h"
#include "crypto_core.h"
#include "forwarding.h"
#include "logger.h"
#include "mem.h"
#include "mono_time.h"
#include "net.h"
#include "net_crypto.h"
#include "network.h"
#include "ping_array.h"
#include "rng.h"
#include "timed_auth.h"
#include "util.h"

#define MAX_LOOKUP_WIDTH 8

#define ANNOUNCEMENT_TIMEOUT 300

#define MAX_LOOKUP_NODE_RETRIES 3
#define LOOKUP_NODE_RETRY_TIMEOUT 3
#define LOOKUP_ITERATE_TIMEOUT 3
#define RETRY_NEWLY_ADDED_TIMEOUT 6

#define REANNOUNCE_AFTER 120
#define REANNOUNCE_BEFORE_TIMEOUT 10
#define MAX_ANNOUNCE_PING_TIMEOUT 120
#define ANNOUNCE_PING_BACKOFF_FACTOR 3

#define MAX_SEARCH_PING_TIMEOUT 600
#define MIN_SEARCH_PING_TIMEOUT 15
#define SEARCH_PING_BACKOFF_RATIO 4

typedef struct Lookup_Data {
    const Memory *_Nonnull mem;

    uint8_t *_Nullable announce_data; /* nullptr if this is not an announcement */
    uint32_t announce_length;
    uint8_t announce_hash[CRYPTO_SHA256_SIZE];
    uint8_t data_secret_key[CRYPTO_SECRET_KEY_SIZE];

    should_retrieve_cb *_Nullable should_retrieve_callback; /* nullptr if this is not a search */
    announce_on_retrieve_cb *_Nullable on_retrieve_callback;
    uint64_t search_started_time;
    void *_Nullable callbacks_object;
} Lookup_Data;

static bool lookup_data_is_announce(const Lookup_Data *_Nonnull lookup_data)
{
    return lookup_data->announce_data != nullptr;
}

static void kill_lookup_data(void *_Nullable userdata)
{
    Lookup_Data *lookup_data = (Lookup_Data *)userdata;

    if (lookup_data == nullptr) {
        return;
    }

    const Memory *mem = lookup_data->mem;

    mem_delete(mem, lookup_data->announce_data);
    mem_delete(mem, lookup_data);
}

static Lookup_Data *_Nullable new_announce(const Memory *_Nonnull mem, const uint8_t *_Nonnull data_secret_key,
        const uint8_t *_Nonnull data, uint16_t length)
{
    Lookup_Data *announce = (Lookup_Data *)mem_alloc(mem, sizeof(Lookup_Data));

    if (announce == nullptr) {
        return nullptr;
    }

    announce->mem = mem;

    uint8_t *const announce_data = (uint8_t *)mem_balloc(mem, length);

    if (announce_data == nullptr) {
        kill_lookup_data(announce);
        return nullptr;
    }

    memcpy(announce_data, data, length);
    announce->announce_data = announce_data;
    announce->announce_length = length;
    crypto_sha256(announce->announce_hash, data, length);
    memcpy(announce->data_secret_key, data_secret_key, CRYPTO_SECRET_KEY_SIZE);

    announce->should_retrieve_callback = nullptr;
    announce->on_retrieve_callback = nullptr;

    return announce;
}

static Lookup_Data *_Nullable new_search(const Memory *_Nonnull mem, should_retrieve_cb *_Nullable should_retrieve_callback,
        announce_on_retrieve_cb *_Nullable on_retrieve_callback,
        uint64_t search_started_time,
        void *_Nullable callbacks_object)
{
    Lookup_Data *search = (Lookup_Data *)mem_alloc(mem, sizeof(Lookup_Data));

    if (search == nullptr) {
        return nullptr;
    }

    search->mem = mem;

    search->should_retrieve_callback = should_retrieve_callback;
    search->on_retrieve_callback = on_retrieve_callback;
    search->callbacks_object = callbacks_object;
    search->search_started_time = search_started_time;

    search->announce_data = nullptr;

    return search;
}

static const Lookup_Data *_Nonnull get_lookup_data(const Lookup *_Nonnull lookup)
{
    const Lookup_Data *lookup_data = (const Lookup_Data *)lookup->userdata;
    assert(lookup_data != nullptr);
    return lookup_data;
}

static bool is_announced(const Mono_Time *_Nonnull mono_time, const Lookup *_Nonnull lookup)
{
    const Lookup_Data *lookup_data = get_lookup_data(lookup);

    if (lookup_data->announce_data == nullptr) {
        return false;
    }

    const uint64_t time = mono_time_get(mono_time);
    uint16_t count = 0;

    for (uint16_t i = 0; i < lookup->width; ++i) {
        if (lookup->nodes[i].exists &&
                lookup->nodes[i].stored_since > 0 &&
                lookup->nodes[i].stored_since + lookup->nodes[i].stored_timeout > time) {
            ++count;
        }
    }

    return count >= lookup->width / 2;
}

#define ANNOUNCE_CLIENT_PING_ARRAY_SIZE 512
#define ANNOUNCE_CLIENT_PING_TIMEOUT 15

#define PACKED_ROUTE_SIZE (1 + MAX_ROUTE_LENGTH * PACKED_NODE_SIZE_IP6)
#define ANNOUNCE_CLIENT_PING_DATA_SIZE (1 + PACKED_ROUTE_SIZE + CRYPTO_PUBLIC_KEY_SIZE + 1 + CRYPTO_SHA256_SIZE)

/** Write `route` to the `PACKED_ROUTE_SIZE` bytes at `data`. */
static bool pack_route(const Logger *_Nonnull log, uint8_t *_Nonnull data, const Lookup_Route *_Nonnull route)
{
    if (route->chain_length >= MAX_ROUTE_LENGTH) {
        return false;
    }

    data[0] = route->chain_length;

    return pack_nodes(log, data + 1, PACKED_ROUTE_SIZE - 1, route->nodes, route->chain_length + 1) != -1;
}

/** Read `route` from the `PACKED_ROUTE_SIZE` bytes at `data`. */
static bool unpack_route(Lookup_Route *_Nonnull route, const uint8_t *_Nonnull data)
{
    const uint16_t chain_length = data[0];

    if (chain_length >= MAX_ROUTE_LENGTH) {
        return false;
    }

    route->chain_length = chain_length;

    return unpack_nodes(route->nodes, chain_length + 1, nullptr, data + 1, PACKED_ROUTE_SIZE - 1, false) == chain_length + 1;
}

struct Announce_Client {
    const Logger *_Nonnull log;
    const Memory *_Nonnull mem;
    const Random *_Nonnull rng;
    Mono_Time *_Nonnull mono_time;
    Forwarding *_Nonnull forwarding;
    DHT *_Nonnull dht;
    Networking_Core *_Nonnull net;
    Net_Crypto *_Nonnull c;
    const Announcements *_Nullable announcements;
    const uint8_t *_Nonnull public_key;

    Ping_Array *_Nullable ping_array;

    Lookups lookups;
};

bool announce_client_add_announce(Announce_Client *announce_client,
                                  const uint8_t *data_public_key, uint16_t width,
                                  const uint8_t *data_secret_key, const uint8_t *data, uint16_t length)
{
    if (length > MAX_ANNOUNCEMENT_SIZE || width == 0 || width > MAX_LOOKUP_WIDTH) {
        return false;
    }

    Lookup_Data *announce = new_announce(announce_client->mem, data_secret_key, data, length);

    if (announce == nullptr) {
        return false;
    }

    if (!add_lookup(&announce_client->lookups, announce_client->mem, data_public_key, width, announce, kill_lookup_data)) {
        kill_lookup_data(announce);
        return false;
    }

    return true;
}

bool announce_client_add_search(Announce_Client *announce_client,
                                const uint8_t *data_public_key, uint16_t width,
                                should_retrieve_cb *should_retrieve_callback,
                                announce_on_retrieve_cb *on_retrieve_callback,
                                uint64_t search_started_time,
                                void *callbacks_object)
{
    if (width == 0 || width > MAX_LOOKUP_WIDTH) {
        return false;
    }

    Lookup_Data *search = new_search(announce_client->mem, should_retrieve_callback, on_retrieve_callback,
                                     search_started_time, callbacks_object);

    if (search == nullptr) {
        return false;
    }

    if (!add_lookup(&announce_client->lookups, announce_client->mem, data_public_key, width, search, kill_lookup_data)) {
        kill_lookup_data(search);
        return false;
    }

    return true;
}

bool announce_client_delete(Announce_Client *announce_client, const uint8_t *data_public_key)
{
    return delete_lookup(&announce_client->lookups, announce_client->mem, data_public_key);
}

bool announce_client_is_announced(const Announce_Client *announce_client, const uint8_t *data_public_key)
{
    const Lookup *lookup = find_lookup(&announce_client->lookups, data_public_key);

    return lookup != nullptr && is_announced(announce_client->mono_time, lookup);
}

static bool send_via_route(const Announce_Client *_Nonnull announce_client, const Lookup_Route *_Nonnull route,
                           const uint8_t *_Nonnull data, uint16_t length)
{
    // TODO(zugz): tcp

    if (pk_equal(route_destination_pk(route), announce_client->public_key)) {
        return false;
    }

    // TODO(zugz): treat lan destinations correctly

    if (route->chain_length == 0) {
        return sendpacket(announce_client->net, &route->nodes[0].ip_port, data, length) == length;
    }

    VLA(uint8_t, chain_keys, CRYPTO_PUBLIC_KEY_SIZE * route->chain_length);

    for (uint16_t i = 0; i < route->chain_length; ++i) {
        memcpy(chain_keys + CRYPTO_PUBLIC_KEY_SIZE * i,
               route->nodes[i + 1].public_key, CRYPTO_PUBLIC_KEY_SIZE);
    }

    return send_forward_request(announce_client->net, &route->nodes[0].ip_port,
                                chain_keys, route->chain_length, data, length);
}

/* Write ping_id to last `sizeof(uint64_t)` bytes of `data`, then encrypt and
 * send along `route`.
 */
static bool send_plain_request(const Announce_Client *_Nonnull announce_client,
                               Lookup *_Nonnull lookup, const Lookup_Route *_Nonnull route,
                               uint8_t type, const uint8_t *_Nullable previous_hash, bool check_pending,
                               uint8_t *_Nonnull data, uint16_t length)
{
    uint8_t ping_data[ANNOUNCE_CLIENT_PING_DATA_SIZE] = {0};
    uint8_t *p = ping_data;

    *p = announce_response_of_request_type(type);
    ++p;

    if (!pack_route(announce_client->log, p, route)) {
        return false;
    }

    p += PACKED_ROUTE_SIZE;

    memcpy(p, lookup->data_public_key, CRYPTO_PUBLIC_KEY_SIZE);
    p += CRYPTO_PUBLIC_KEY_SIZE;

    *p = previous_hash != nullptr ? 1 : 0;
    ++p;

    if (previous_hash != nullptr) {
        memcpy(p, previous_hash, CRYPTO_SHA256_SIZE);
    }

    const uint64_t ping_id = ping_array_add(announce_client->ping_array,
                                            announce_client->mono_time, announce_client->rng,
                                            ping_data, sizeof(ping_data));

    if (ping_id == 0) {
        return false;
    }

    if (check_pending && !add_pending(lookup, route_destination_pk(route),
                                      ping_id, announce_client->mono_time)) {
        return false;
    }

    if (length < sizeof(uint64_t)) {
        return false;
    }

    memcpy(data + (length - sizeof(uint64_t)), &ping_id, sizeof(ping_id));

    const uint8_t *shared_key = dht_get_shared_key_sent(announce_client->dht, route_destination_pk(route));

    if (shared_key == nullptr) {
        return false;
    }

    const uint16_t request_size = length + 1 + CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_NONCE_SIZE + CRYPTO_MAC_SIZE;
    VLA(uint8_t, request, request_size);

    if (dht_create_packet(announce_client->mem, announce_client->rng, announce_client->public_key, shared_key, type,
                          data, length, request, request_size) != request_size) {
        return false;
    }

    return send_via_route(announce_client, route, request, request_size);
}

static bool send_data_search_request(const Announce_Client *_Nonnull announce_client, Lookup *_Nonnull lookup,
                                     const Lookup_Route *_Nonnull route)
{
    const uint8_t *previous_hash = nullptr;
    Lookup_Node *lookup_node = lookup_find_node(lookup, route_destination_pk(route));

    if (lookup_node != nullptr &&
            lookup_node->last_search_response_size >= CRYPTO_PUBLIC_KEY_SIZE &&
            pk_equal(lookup->data_public_key, lookup_node->last_search_response_data)) {
        previous_hash = lookup_node->last_search_response_hash;
    }

    const uint16_t request_len = CRYPTO_PUBLIC_KEY_SIZE +
                                 (previous_hash == nullptr ? 0 : CRYPTO_SHA256_SIZE) +
                                 sizeof(uint64_t);
    VLA(uint8_t, request, request_len);
    memcpy(request, lookup->data_public_key, CRYPTO_PUBLIC_KEY_SIZE);

    if (previous_hash != nullptr) {
        memcpy(request + CRYPTO_PUBLIC_KEY_SIZE, previous_hash, CRYPTO_SHA256_SIZE);
    }

    const bool sent = send_plain_request(announce_client, lookup, route,
                                         NET_PACKET_DATA_SEARCH_REQUEST, previous_hash, true,
                                         request, request_len);

    if (sent && lookup_node != nullptr) {
        ++lookup_node->ping_backoff;
        ++lookup_node->sent_no_response_times;
        lookup_node->sent_no_response_last = mono_time_get(announce_client->mono_time);
        lookup_node->retry_after = 0;
    }

    return sent;
}

static bool send_announce_store_request(Announce_Client *_Nonnull announce_client,
                                        Lookup *_Nonnull lookup, const Lookup_Route *_Nonnull route,
                                        const uint8_t *_Nonnull timed_auth, bool reannounce)
{
    const Lookup_Data *const lookup_data = get_lookup_data(lookup);
    assert(lookup_data->announce_data != nullptr);

    const uint16_t plain_size = TIMED_AUTH_SIZE + sizeof(uint32_t) + 1 +
                                (reannounce ? CRYPTO_SHA256_SIZE : lookup_data->announce_length);
    VLA(uint8_t, plain, plain_size);
    uint8_t *p = plain;

    memcpy(p, timed_auth, TIMED_AUTH_SIZE);
    p += TIMED_AUTH_SIZE;

    net_pack_u32(p, ANNOUNCEMENT_TIMEOUT);
    p += sizeof(uint32_t);

    *p = reannounce ? 1 : 0;
    ++p;

    if (reannounce) {
        memcpy(p, lookup_data->announce_hash, CRYPTO_SHA256_SIZE);
    } else {
        memcpy(p, lookup_data->announce_data, lookup_data->announce_length);
    }

    const uint16_t request_size = CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_NONCE_SIZE +
                                  plain_size + CRYPTO_MAC_SIZE + sizeof(uint64_t);
    VLA(uint8_t, request, request_size);
    p = request;

    memcpy(p, lookup->data_public_key, CRYPTO_PUBLIC_KEY_SIZE);
    p += CRYPTO_PUBLIC_KEY_SIZE;

    random_nonce(announce_client->rng, p);
    const uint8_t *const nonce = p;
    p += CRYPTO_NONCE_SIZE;

    uint8_t shared_key[CRYPTO_SHARED_KEY_SIZE];
    encrypt_precompute(route_destination_pk(route), lookup_data->data_secret_key, shared_key);

    const int32_t encrypted_size = encrypt_data_symmetric(announce_client->mem, shared_key, nonce, plain, plain_size, p);
    crypto_memzero(shared_key, sizeof(shared_key));

    if (encrypted_size != plain_size + CRYPTO_MAC_SIZE) {
        return false;
    }

    return send_plain_request(announce_client, lookup, route,
                              NET_PACKET_STORE_ANNOUNCE_REQUEST, nullptr, false,
                              request, request_size);
}

static bool send_data_retrieve_request(const Announce_Client *_Nonnull announce_client,
                                       Lookup *_Nonnull lookup, const Lookup_Route *_Nonnull route,
                                       const uint8_t *_Nonnull timed_auth)
{
    uint8_t request[CRYPTO_PUBLIC_KEY_SIZE + 1 + TIMED_AUTH_SIZE + sizeof(uint64_t)];
    uint8_t *p = request;

    memcpy(p, lookup->data_public_key, CRYPTO_PUBLIC_KEY_SIZE);
    p += CRYPTO_PUBLIC_KEY_SIZE;

    *p = 0;
    ++p;

    memcpy(p, timed_auth, TIMED_AUTH_SIZE);

    return send_plain_request(announce_client, lookup, route,
                              NET_PACKET_DATA_RETRIEVE_REQUEST, nullptr, false,
                              request, sizeof(request));
}

static void do_lookup(Announce_Client *_Nonnull announce_client, Lookup *_Nonnull lookup)
{
    if (lookup->width == 0) {
        // Nothing to look up with, and the times below are divided by the width.
        return;
    }

    if (!mono_time_is_timeout(announce_client->mono_time,
                              lookup->last_iteration, LOOKUP_ITERATE_TIMEOUT)) {
        return;
    }

    const uint64_t time = mono_time_get(announce_client->mono_time);
    lookup->last_iteration = time;

    const Lookup_Data *const lookup_data = get_lookup_data(lookup);
    const bool is_announce = lookup_data_is_announce(lookup_data);

    if (lookup_data->on_retrieve_callback != nullptr
            && announce_client->announcements != nullptr) {
        // We may be storing an announcement we're searching for
        announce_on_stored(announce_client->announcements, lookup->data_public_key,
                           lookup_data->on_retrieve_callback, lookup_data->callbacks_object);
    }

    for (uint16_t i = 0; i < lookup->width; ++i) {
        Lookup_Node *lookup_node = &lookup->nodes[i];

        if (lookup_node->exists) {
            if (lookup_node->sent_no_response_times > 0) {
                if (time < lookup_node->sent_no_response_last + LOOKUP_NODE_RETRY_TIMEOUT) {
                    continue;
                }

                if (lookup_node->sent_no_response_times == MAX_LOOKUP_NODE_RETRIES) {
                    delete_lookup_node(lookup_node);
                }
            } else {
                if (!((lookup_node->retry_after > 0 && time >= lookup_node->retry_after)
                        || (lookup_node->stored_since > 0 &&
                            (time >= lookup_node->stored_since + REANNOUNCE_AFTER ||
                             time >= lookup_node->stored_since +
                             lookup_node->stored_timeout - REANNOUNCE_BEFORE_TIMEOUT))
                        || (is_announce && lookup_node->stored_since == 0 &&
                            time >= lookup_node->last_search_response_time +
                            min_u64(MAX_ANNOUNCE_PING_TIMEOUT,
                                    ANNOUNCE_PING_BACKOFF_FACTOR * (lookup_node->ping_backoff + 1))))) {
                    continue;
                }
            }
        }

        if (lookup_node->exists) {
            send_data_search_request(announce_client, lookup, &lookup_node->route);
        } else {
            Node_format node;

            if (!random_node(announce_client->dht, &node, net_family_unspec(), true)) {
                // TODO(zugz): use random connected tcp relay instead
                continue;
            }

            Lookup_Route route;
            route.nodes[0] = node;
            route.chain_length = 0;
            send_data_search_request(announce_client, lookup, &route);
        }
    }

    if (!is_announce) {
        const uint64_t ping_timeout = min_u64(MAX_SEARCH_PING_TIMEOUT, max_u64(MIN_SEARCH_PING_TIMEOUT,
                                              (time - lookup_data->search_started_time) /
                                              SEARCH_PING_BACKOFF_RATIO));

        // FIXME: meant to reset search backoff when announcement seen

        if (time >= lookup->last_ping + ping_timeout / lookup->width) {
            Lookup_Node *lookup_node = &lookup->nodes[lookup->next_ping_i % lookup->width];
            lookup->next_ping_i = (lookup->next_ping_i + 1) % lookup->width;

            if (lookup_node->exists) {
                send_data_search_request(announce_client, lookup, &lookup_node->route);
                lookup->last_ping = time;
            }
        }
    }
}

void do_announce_client(Announce_Client *announce_client)
{
    for (uint32_t i = 0; i < announce_client->lookups.num_lookups; ++i) {
        do_lookup(announce_client, announce_client->lookups.lookups[i]);
    }
}

static void process_data_search_response(Announce_Client *_Nonnull announce_client,
        Lookup *_Nonnull lookup, const Lookup_Route *_Nonnull route, Lookup_Node *_Nullable responder_lookup_node,
        const uint8_t *_Nullable data_hash, const uint8_t *_Nonnull timed_auth,
        bool would_accept, const Node_format *_Nonnull nodes, uint16_t num_nodes)
{
#ifdef CHECK_ANNOUNCE_NODE
    set_announce_node(announce_client->dht, route_destination_pk(route));
#endif /* CHECK_ANNOUNCE_NODE */

    const Lookup_Data *const lookup_data = get_lookup_data(lookup);
    Lookup_Route base_routes[MAX_LOOKUP_WIDTH];
    uint16_t num_base_routes = 0;
    bool added = false;
    bool do_announce = lookup_data->announce_length > 0 && would_accept;

    if (responder_lookup_node == nullptr) {
        added = lookup_add_node(lookup, route, announce_client->public_key);
        base_routes[0].nodes[0] = *route_destination(route);
        base_routes[0].chain_length = 0;
        num_base_routes = 1;
    } else {
        responder_lookup_node->sent_no_response_times = 0;

        if (data_hash == nullptr &&
                responder_lookup_node->stored_since > 0) {
            responder_lookup_node->stored_since = 0;
            responder_lookup_node->ping_backoff = 0;
        }

        if (responder_lookup_node->route.chain_length < MAX_FORWARD_CHAIN_LENGTH) {
            base_routes[0] = responder_lookup_node->route;
            num_base_routes = 1;
        } else {
            const uint16_t min_route_length = get_shortest_routes(lookup,
                                              base_routes, &num_base_routes);

            if (min_route_length > MAX_FORWARD_CHAIN_LENGTH) {
                delete_lookup_node(responder_lookup_node);
                responder_lookup_node = nullptr;
                num_base_routes = 0;
                do_announce = false;
            }
        }
    }

    uint16_t sent = 0;

    for (uint16_t i = 0; i < num_nodes; ++i) {
        Lookup_Route new_route;

        if (num_base_routes == 0) {
            new_route.chain_length = 0;
        } else {
            new_route = base_routes[random_range_u32(announce_client->rng, num_base_routes)];
            ++new_route.chain_length;
        }

        new_route.nodes[new_route.chain_length] = nodes[i];

        if (lookup_could_add_node(lookup, &new_route, announce_client->public_key)) {
            if (send_data_search_request(announce_client, lookup, &new_route)) {
                ++sent;

                do_announce &= !(added && (id_closest(lookup->data_public_key,
                                                      route_destination_pk(route), nodes[i].public_key) == 2));
            }
        }
    }

    if (added && route->chain_length > 0) {
        if (sent == 0) {
            send_data_search_request(announce_client, lookup, &base_routes[0]);
        } else {
            Lookup_Node *lookup_node = lookup_find_node(lookup, route_destination_pk(route));
            assert(lookup_node != nullptr);
            lookup_node->retry_after =
                mono_time_get(announce_client->mono_time) + RETRY_NEWLY_ADDED_TIMEOUT;
        }
    }

    if (do_announce) {
        const bool reannounce = data_hash != nullptr &&
                                crypto_sha256_eq(data_hash, lookup_data->announce_hash);
        send_announce_store_request(announce_client, lookup, route,
                                    timed_auth, reannounce);
    }

    if (data_hash != nullptr &&
            lookup_data->should_retrieve_callback != nullptr &&
            lookup_data->should_retrieve_callback(lookup_data->callbacks_object, data_hash)) {
        send_data_retrieve_request(announce_client, lookup, route, timed_auth);
    }
}

static bool process_announce_response_plain(Announce_Client *_Nonnull announce_client,
        uint8_t type, const Lookup_Route *_Nonnull route, uint64_t ping_id,
        const uint8_t *_Nullable old_hash, const uint8_t *_Nonnull data_public_key,
        const uint8_t *_Nonnull data, uint16_t length)
{
    const uint8_t *p = data;

    if (length < CRYPTO_PUBLIC_KEY_SIZE ||
            !pk_equal(data_public_key, data)) {
        return false;
    }

    p += CRYPTO_PUBLIC_KEY_SIZE;

    Lookup *const lookup = find_lookup(&announce_client->lookups, data_public_key);

    if (lookup == nullptr) {
        return false;
    }

    delete_pending(lookup, ping_id);

    lookup_route_valid(lookup, route);

    const uint8_t *responder_public_key = route_destination_pk(route);
    Lookup_Node *responder_lookup_node = lookup_find_node(lookup, responder_public_key);

    switch (type) {
        case NET_PACKET_DATA_SEARCH_RESPONSE: {
            bool repeating_old = false;

            if (length == CRYPTO_PUBLIC_KEY_SIZE) {
                if (responder_lookup_node == nullptr || old_hash == nullptr ||
                        !crypto_sha256_eq(old_hash, responder_lookup_node->last_search_response_hash)) {
                    return false;
                }

                repeating_old = true;
                data = responder_lookup_node->last_search_response_data;
                p = data + CRYPTO_PUBLIC_KEY_SIZE;
                length = responder_lookup_node->last_search_response_size;
            }

            const bool stored = *p != 0;
            ++p;
            const int32_t nodes_size = (int32_t)length - (CRYPTO_PUBLIC_KEY_SIZE + 1 +
                                       (stored ? CRYPTO_SHA256_SIZE : 0) +
                                       TIMED_AUTH_SIZE + 1 + 1);

            if (nodes_size < 0) {
                return false;
            }

            const uint8_t *data_hash = nullptr;

            if (stored) {
                data_hash = p;
                p += CRYPTO_SHA256_SIZE;
            }

            const uint8_t *timed_auth = p;
            p += TIMED_AUTH_SIZE;

            const bool would_accept = (*p & 1) != 0;
            ++p;

            const uint8_t num_nodes = *p;
            ++p;

            Node_format nodes[MAX_SENT_NODES];

            if (unpack_nodes(nodes, MAX_SENT_NODES, nullptr, p, nodes_size, false) != num_nodes) {
                return false;
            }

            process_data_search_response(announce_client, lookup, route,
                                         responder_lookup_node, data_hash, timed_auth, would_accept, nodes, num_nodes);

            Lookup_Node *const lookup_node_final = lookup_find_node(lookup, responder_public_key);

            if (lookup_node_final != nullptr) {
                lookup_node_final->last_search_response_time = mono_time_get(announce_client->mono_time);

                if (!repeating_old) {
                    memcpy(lookup_node_final->last_search_response_data, data, length);
                    lookup_node_final->last_search_response_size = length;
                    crypto_sha256(lookup_node_final->last_search_response_hash, data, length);
                }
            }
            break;
        }

        case NET_PACKET_DATA_RETRIEVE_RESPONSE: {
            const int32_t data_length = (int32_t)length - (CRYPTO_PUBLIC_KEY_SIZE + 1);

            if (data_length < 0) {
                return false;
            }

            if (*p != 1) {
                return false;
            }

            ++p;

            const Lookup_Data *const lookup_data = get_lookup_data(lookup);

            if (lookup_data->on_retrieve_callback != nullptr) {
                lookup_data->on_retrieve_callback(lookup_data->callbacks_object, p, data_length);
            }
            break;
        }

        case NET_PACKET_STORE_ANNOUNCE_RESPONSE: {
            if (length < CRYPTO_PUBLIC_KEY_SIZE + sizeof(uint32_t) + sizeof(uint64_t)) {
                return false;
            }

            uint32_t timeout;
            net_unpack_u32(p, &timeout);
            p += sizeof(uint32_t);

            uint64_t unix_time;
            net_unpack_u64(p, &unix_time);

            if (responder_lookup_node != nullptr) {
                responder_lookup_node->stored_since = mono_time_get(announce_client->mono_time);
                responder_lookup_node->stored_timeout = timeout;
                responder_lookup_node->unix_time = unix_time;
                // TODO(zugz): callback if we now consider ourselves announced?
                // We consider an announcement to be announced if it is stored on
                // at least half of the nodes in the list.
                //
                // TODO(zugz): clock_synch
            }
            break;
        }

        default: {
            return false;
        }
    }

    return true;
}

static bool process_announce_response(Announce_Client *_Nonnull announce_client,
                                      const uint8_t *_Nonnull data, uint16_t length)
{
    const int32_t plain_len = (int32_t)length - (1 + CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_NONCE_SIZE + CRYPTO_MAC_SIZE);

    if (plain_len < (int32_t)(CRYPTO_PUBLIC_KEY_SIZE + sizeof(uint64_t))) {
        return false;
    }

    VLA(uint8_t, plain, plain_len);
    const uint8_t *shared_key = dht_get_shared_key_recv(announce_client->dht, data + 1);

    if (shared_key == nullptr) {
        return false;
    }

    if (decrypt_data_symmetric(announce_client->mem, shared_key,
                               data + 1 + CRYPTO_PUBLIC_KEY_SIZE,
                               data + 1 + CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_NONCE_SIZE,
                               plain_len + CRYPTO_MAC_SIZE,
                               plain) != plain_len) {
        return false;
    }

    uint64_t ping_id;
    memcpy(&ping_id, plain + (plain_len - sizeof(uint64_t)), sizeof(uint64_t));

    uint8_t ping_data[ANNOUNCE_CLIENT_PING_DATA_SIZE];

    if (ping_array_check(announce_client->ping_array,
                         announce_client->mono_time, ping_data,
                         sizeof(ping_data), ping_id) != sizeof(ping_data)) {
        return false;
    }

    uint8_t *p = ping_data;

    if (*p != data[0]) {
        return false;
    }

    ++p;

    Lookup_Route route;

    if (!unpack_route(&route, p)) {
        return false;
    }

    p += PACKED_ROUTE_SIZE;

    if (!pk_equal(route_destination_pk(&route), data + 1)) {
        return false;
    }

    const uint8_t *data_public_key = p;
    p += CRYPTO_PUBLIC_KEY_SIZE;

    const uint8_t *const old_hash = *p > 0 ? p + 1 : nullptr;

    return process_announce_response_plain(announce_client, data[0], &route,
                                           ping_id, old_hash, data_public_key,
                                           plain, plain_len - sizeof(uint64_t));
}

static void forwarded_response_callback(void *_Nullable object,
                                        const uint8_t *_Nonnull data, uint16_t length, void *_Nullable userdata)
{
    Announce_Client *announce_client = (Announce_Client *) object;

    process_announce_response(announce_client, data, length);
}

static int handle_dht_announce_response(void *_Nullable object, const IP_Port *_Nonnull source,
                                        const uint8_t *_Nonnull packet, uint16_t length, void *_Nullable userdata)
{
    Announce_Client *announce_client = (Announce_Client *) object;

    return process_announce_response(announce_client, packet, length) ? 0 : -1;
}

Announce_Client *new_announce_client(const Logger *log, const Memory *mem, const Random *rng,
                                     Mono_Time *mono_time, Forwarding *forwarding,
                                     DHT *dht, Networking_Core *net,
                                     Net_Crypto *c, const Announcements *announcements)
{
    Announce_Client *announce_client = (Announce_Client *)mem_alloc(mem, sizeof(Announce_Client));

    if (announce_client == nullptr) {
        return nullptr;
    }

    announce_client->log = log;
    announce_client->mem = mem;
    announce_client->rng = rng;
    announce_client->mono_time = mono_time;
    announce_client->forwarding = forwarding;
    announce_client->c = c;
    announce_client->dht = dht;
    announce_client->net = net;
    announce_client->public_key = dht_get_self_public_key(announce_client->dht);

    announce_client->announcements = announcements; // Allowed to be nullptr

    announce_client->ping_array = ping_array_new(mem, ANNOUNCE_CLIENT_PING_ARRAY_SIZE, ANNOUNCE_CLIENT_PING_TIMEOUT);

    if (announce_client->ping_array == nullptr) {
        kill_announce_client(announce_client);
        return nullptr;
    }

    set_callback_forwarded_response(forwarding, forwarded_response_callback, announce_client);
    networking_registerhandler(announce_client->net, NET_PACKET_DATA_SEARCH_RESPONSE, handle_dht_announce_response,
                               announce_client);
    networking_registerhandler(announce_client->net, NET_PACKET_DATA_RETRIEVE_RESPONSE, handle_dht_announce_response,
                               announce_client);
    networking_registerhandler(announce_client->net, NET_PACKET_STORE_ANNOUNCE_RESPONSE, handle_dht_announce_response,
                               announce_client);

    return announce_client;
}

void kill_announce_client(Announce_Client *announce_client)
{
    if (announce_client == nullptr) {
        return;
    }

    ping_array_kill(announce_client->ping_array);

    set_callback_forwarded_response(announce_client->forwarding, nullptr, nullptr);
    networking_registerhandler(announce_client->net, NET_PACKET_DATA_SEARCH_RESPONSE, nullptr, nullptr);
    networking_registerhandler(announce_client->net, NET_PACKET_DATA_RETRIEVE_RESPONSE, nullptr, nullptr);
    networking_registerhandler(announce_client->net, NET_PACKET_STORE_ANNOUNCE_RESPONSE, nullptr, nullptr);

    free_lookups(&announce_client->lookups, announce_client->mem);

    mem_delete(announce_client->mem, announce_client);
}
