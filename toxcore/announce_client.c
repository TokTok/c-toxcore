/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2020-2021 The TokTok team.
 */

#include "announce_client.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "announce_lookups.h"
#include "ccompat.h"
#include "DHT.h"
#include "ping_array.h"
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
    uint8_t *announce_data; /* nullptr if this is not an announcement */
    uint32_t announce_length;
    uint8_t announce_hash[CRYPTO_SHA256_SIZE];
    uint8_t data_secret_key[CRYPTO_SECRET_KEY_SIZE];

    should_retrieve_cb *should_retrieve_callback; /* nullptr if this is not a search */
    on_retrieve_cb *on_retrieve_callback;
    uint64_t search_started_time;
    void *callbacks_object;
} Lookup_Data;

non_null()
static bool lookup_data_is_announce(const Lookup_Data *lookup_data)
{
    return lookup_data->announce_data != nullptr;
}

non_null()
static void kill_lookup_data(void *userdata)
{
    Lookup_Data *lookup_data = (Lookup_Data *)userdata;

    if (lookup_data == nullptr) {
        return;
    }

    if (lookup_data->announce_data != nullptr) {
        free(lookup_data->announce_data);
    }

    free(lookup_data);
}

non_null()
static Lookup_Data *new_announce(const uint8_t *data_secret_key,
                                 const uint8_t *data, uint16_t length)
{
    Lookup_Data *announce = calloc(1, sizeof(Lookup_Data));

    if (announce == nullptr) {
        return nullptr;
    }

    announce->announce_data = malloc(length);

    if (announce->announce_data == nullptr) {
        kill_lookup_data(announce);
        return nullptr;
    }

    memcpy(announce->announce_data, data, length);
    announce->announce_length = length;
    crypto_sha256(announce->announce_hash, data, length);
    memcpy(announce->data_secret_key, data_secret_key, CRYPTO_SECRET_KEY_SIZE);

    announce->should_retrieve_callback = nullptr;
    announce->on_retrieve_callback = nullptr;

    return announce;
}

nullable(1, 2, 4)
static Lookup_Data *new_search(should_retrieve_cb *should_retrieve_callback,
                               on_retrieve_cb *on_retrieve_callback,
                               uint64_t search_started_time,
                               void *callbacks_object)
{
    Lookup_Data *search = calloc(1, sizeof(Lookup_Data));

    if (search == nullptr) {
        return nullptr;
    }

    search->should_retrieve_callback = should_retrieve_callback;
    search->on_retrieve_callback = on_retrieve_callback;
    search->callbacks_object = callbacks_object;
    search->search_started_time = search_started_time;

    search->announce_data = nullptr;

    return search;
}

non_null()
static const Lookup_Data *get_lookup_data(const Lookup *lookup)
{
    return (Lookup_Data *)lookup->userdata;
}

non_null()
static bool is_announced(const Mono_Time *mono_time, const Lookup *lookup)
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

struct Announce_Client {
    Mono_Time *mono_time;
    Forwarding *forwarding;
    DHT *dht;
    Networking_Core *net;
    Net_Crypto *c;
    const Announcements *announcements;
    const uint8_t *public_key;

    Ping_Array *ping_array;
    Shared_Keys shared_keys;

    Lookups lookups;
};

bool add_announce(Announce_Client *announce_client,
                  const uint8_t *data_public_key, uint16_t width,
                  const uint8_t *data_secret_key, const uint8_t *data, uint16_t length)
{
    if (length > MAX_ANNOUNCEMENT_SIZE || width > MAX_LOOKUP_WIDTH) {
        return false;
    }

    Lookup_Data *announce = new_announce(data_secret_key, data, length);

    if (announce == nullptr) {
        return false;
    }

    if (!add_lookup(&announce_client->lookups, data_public_key, width, announce, kill_lookup_data)) {
        kill_lookup_data(announce);
        return false;
    }

    return true;
}

bool add_search(Announce_Client *announce_client,
                const uint8_t *data_public_key, uint16_t width,
                should_retrieve_cb *should_retrieve_callback,
                on_retrieve_cb *on_retrieve_callback,
                uint64_t search_started_time,
                void *callbacks_object)
{
    if (width > MAX_LOOKUP_WIDTH) {
        return false;
    }

    Lookup_Data *search = new_search(should_retrieve_callback, on_retrieve_callback,
                                     search_started_time, callbacks_object);

    if (search == nullptr) {
        return false;
    }

    if (!add_lookup(&announce_client->lookups, data_public_key, width, search, kill_lookup_data)) {
        kill_lookup_data(search);
        return false;
    }

    return true;
}

bool delete_search_or_announce(Announce_Client *announce_client, const uint8_t *data_public_key)
{
    return delete_lookup(&announce_client->lookups, data_public_key);
}

non_null()
static bool send_via_route(const Announce_Client *announce_client, const Lookup_Route *route,
                           const uint8_t *data, uint16_t length)
{
    // TODO: tcp

    if (pk_equal(route_destination_pk(route), announce_client->public_key)) {
        return false;
    }

    // TODO: treat lan destinations correctly

    if (route->chain_length == 0) {
        return (sendpacket(announce_client->net, &route->nodes[0].ip_port, data, length)
                == length);
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
non_null(1, 2, 3, 7) nullable(5)
static bool send_plain_request(const Announce_Client *announce_client,
                               Lookup *lookup, const Lookup_Route *route,
                               uint8_t type, const uint8_t *previous_hash, bool check_pending,
                               uint8_t *data, uint16_t length)
{
    uint8_t ping_data[1 + sizeof(Lookup_Route) + CRYPTO_PUBLIC_KEY_SIZE + 1 + CRYPTO_SHA256_SIZE];
    uint8_t *p = ping_data;

    *p = response_of_request_type(type);
    ++p;

    memcpy(p, route, sizeof(Lookup_Route));
    p += sizeof(Lookup_Route);

    memcpy(p, lookup->data_public_key, CRYPTO_PUBLIC_KEY_SIZE);
    p += CRYPTO_PUBLIC_KEY_SIZE;

    *p = (previous_hash != nullptr);
    ++p;

    if (previous_hash != nullptr) {
        memcpy(p, previous_hash, CRYPTO_SHA256_SIZE);
    }

    const uint64_t ping_id = ping_array_add(announce_client->ping_array,
                                            announce_client->mono_time,
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

    uint8_t shared_key[CRYPTO_SHARED_KEY_SIZE];
    dht_get_shared_key_sent(announce_client->dht, shared_key, route_destination_pk(route));

    VLA(uint8_t, request, length + 1 + CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_NONCE_SIZE + CRYPTO_MAC_SIZE);

    if (dht_create_packet(announce_client->public_key, shared_key, type,
                          data, length, request, SIZEOF_VLA(request)) != SIZEOF_VLA(request)) {
        return false;
    }

    return send_via_route(announce_client, route, request, SIZEOF_VLA(request));
}

non_null()
static bool send_data_search_request(const Announce_Client *announce_client, Lookup *lookup,
                                     const Lookup_Route *route)
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

non_null()
static bool send_announce_store_request(Announce_Client *announce_client,
                                        Lookup *lookup, const Lookup_Route *route,
                                        const uint8_t *timed_auth, bool reannounce)
{
    const Lookup_Data *const lookup_data = get_lookup_data(lookup);
    assert(lookup_data->announce_data != nullptr);

    VLA(uint8_t, plain, TIMED_AUTH_SIZE + sizeof(uint32_t) + 1 +
        (reannounce ? CRYPTO_SHA256_SIZE : lookup_data->announce_length));
    uint8_t *p = plain;

    memcpy(p, timed_auth, TIMED_AUTH_SIZE);
    p += TIMED_AUTH_SIZE;

    net_pack_u32(p, ANNOUNCEMENT_TIMEOUT);
    p += sizeof(uint32_t);

    *p = reannounce;
    ++p;

    if (reannounce) {
        memcpy(p, lookup_data->announce_hash, CRYPTO_SHA256_SIZE);
    } else {
        memcpy(p, lookup_data->announce_data, lookup_data->announce_length);
    }

    VLA(uint8_t, request, CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_NONCE_SIZE +
        sizeof(plain) + CRYPTO_MAC_SIZE + sizeof(uint64_t));
    p = request;

    memcpy(p, lookup->data_public_key, CRYPTO_PUBLIC_KEY_SIZE);
    p += CRYPTO_PUBLIC_KEY_SIZE;

    random_nonce(p);
    const uint8_t *const nonce = p;
    p += CRYPTO_NONCE_SIZE;

    uint8_t shared_key[CRYPTO_SHARED_KEY_SIZE];
    get_shared_key(announce_client->mono_time, &announce_client->shared_keys, shared_key,
                   lookup_data->data_secret_key, route_destination_pk(route));

    if (encrypt_data_symmetric(shared_key, nonce, plain, sizeof(plain), p) !=
            sizeof(plain) + CRYPTO_MAC_SIZE) {
        return false;
    }

    return send_plain_request(announce_client, lookup, route,
                              NET_PACKET_STORE_ANNOUNCE_REQUEST, nullptr, false,
                              request, SIZEOF_VLA(request));
}

non_null()
static bool send_data_retrieve_request(const Announce_Client *announce_client,
                                       Lookup *lookup, const Lookup_Route *route,
                                       const uint8_t *timed_auth)
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

non_null()
static void do_lookup(Announce_Client *announce_client, Lookup *lookup)
{
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
        on_stored(announce_client->announcements, lookup->data_public_key,
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

            if (!random_node(announce_client->dht, &node, net_family_unspec, true)) {
                // TODO: use random connected tcp relay instead
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

non_null(1, 2, 3, 6, 8) nullable(4, 5)
static void process_data_search_response(Announce_Client *announce_client,
        Lookup *lookup, const Lookup_Route *route, Lookup_Node *responder_lookup_node,
        const uint8_t *data_hash, const uint8_t *timed_auth,
        bool would_accept, Node_format *nodes, uint16_t num_nodes)
{
#ifdef CHECK_ANNOUNCE_NODE
    set_announce_node(announce_client->dht, route_destination_pk(route));
#endif

    const Lookup_Data *const lookup_data = get_lookup_data(lookup);
    Lookup_Route base_routes[MAX_LOOKUP_WIDTH];
    uint16_t num_base_routes = 0;
    bool added = false;
    bool do_announce = (lookup_data->announce_length > 0 && would_accept);

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
            new_route = base_routes[random_u16() % num_base_routes];
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

non_null(1, 3, 6, 7) nullable(5)
static bool process_announce_response_plain(Announce_Client *announce_client,
        uint8_t type, const Lookup_Route *route, uint64_t ping_id,
        const uint8_t *old_hash, const uint8_t *data_public_key,
        const uint8_t *data, uint16_t length)
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

    if (type == NET_PACKET_DATA_SEARCH_RESPONSE) {
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

        const bool stored = *p;
        ++p;
        int32_t nodes_size = (int32_t)length - (CRYPTO_PUBLIC_KEY_SIZE + 1 +
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

        const bool would_accept = *p & 1;
        ++p;

        const uint8_t num_nodes = *p;
        ++p;

        Node_format nodes[MAX_SENT_NODES];

        if (unpack_nodes(nodes, MAX_SENT_NODES, nullptr, p, nodes_size, 0) != num_nodes) {
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
    } else if (type == NET_PACKET_DATA_RETRIEVE_RESPONSE) {
        int32_t data_length = (int32_t)length - (CRYPTO_PUBLIC_KEY_SIZE + 1);

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
    } else if (type == NET_PACKET_STORE_ANNOUNCE_RESPONSE) {
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
            // TODO: callback if we now consider ourselves announced?
            // We consider an announcement to be announced if it is stored on
            // at least half of the nodes in the list.
            //
            // TODO: clock_synch
        }
    } else {
        return false;
    }

    return true;
}

non_null()
static bool process_announce_response(Announce_Client *announce_client,
                                      const uint8_t *data, uint16_t length)
{
    const int32_t plain_len = (int32_t)length - (1 + CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_NONCE_SIZE + CRYPTO_MAC_SIZE);

    if (plain_len < CRYPTO_PUBLIC_KEY_SIZE + sizeof(uint64_t)) {
        return false;
    }

    VLA(uint8_t, plain, plain_len);
    uint8_t shared_key[CRYPTO_SHARED_KEY_SIZE];
    dht_get_shared_key_recv(announce_client->dht, shared_key, data + 1);

    if (decrypt_data_symmetric(shared_key,
                               data + 1 + CRYPTO_PUBLIC_KEY_SIZE,
                               data + 1 + CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_NONCE_SIZE,
                               plain_len + CRYPTO_MAC_SIZE,
                               plain) != plain_len) {
        return false;
    }

    uint64_t ping_id;
    memcpy(&ping_id, plain + (plain_len - sizeof(uint64_t)), sizeof(uint64_t));

    uint8_t ping_data[1 + sizeof(Lookup_Route) + CRYPTO_PUBLIC_KEY_SIZE + 1 + CRYPTO_SHA256_SIZE];

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
    memcpy(&route, p, sizeof(Lookup_Route));
    p += sizeof(Lookup_Route);

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

non_null(1, 2) nullable(4)
static void forwarded_response_callback(void *object,
                                        const uint8_t *data, uint16_t length, void *userdata)
{
    Announce_Client *announce_client = (Announce_Client *) object;

    process_announce_response(announce_client, data, length);
}

non_null(1, 2, 3) nullable(5)
static int handle_dht_announce_response(void *object, const IP_Port *source,
                                    const uint8_t *data, uint16_t length, void *userdata)
{
    Announce_Client *announce_client = (Announce_Client *) object;

    return (process_announce_response(announce_client, data, length) ? 0 : -1);
}

Announce_Client *new_announce_client(Mono_Time *mono_time, Forwarding *forwarding,
                                     Net_Crypto *c, const Announcements *announcements)
{
    if (mono_time == nullptr || forwarding == nullptr || c == nullptr) {
        return nullptr;
    }

    Announce_Client *announce_client = (Announce_Client *)calloc(1, sizeof(Announce_Client));

    if (announce_client == nullptr) {
        return nullptr;
    }

    announce_client->mono_time = mono_time;
    announce_client->forwarding = forwarding;
    announce_client->c = c;
    announce_client->dht = forwarding_get_dht(forwarding);
    announce_client->net = dht_get_net(announce_client->dht);
    announce_client->public_key = dht_get_self_public_key(announce_client->dht);

    announce_client->announcements = announcements; // Allowed to be nullptr

    announce_client->ping_array = ping_array_new(ANNOUNCE_CLIENT_PING_ARRAY_SIZE, ANNOUNCE_CLIENT_PING_TIMEOUT);

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

    crypto_memzero(&announce_client->shared_keys, sizeof(Shared_Keys));

    free_lookups(&announce_client->lookups);

    free(announce_client);
}
