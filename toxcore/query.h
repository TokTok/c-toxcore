/** query.h
 *
 * Makes requests for information using the DHT or Onion as appropriate.
 */

#ifndef TOX_QUERY_H
#define TOX_QUERY_H

#include "network.h"
#include "tox.h"

#define QUERY_TIMEOUT 500

typedef struct {
    IP_Port  ipp;
    uint8_t  key[TOX_PUBLIC_KEY_SIZE];
    uint8_t  name[TOX_QUERY_MAX_NAME_SIZE];
    size_t  length;

    uint64_t query_nonce;

    uint8_t  tries_remaining;
    uint64_t next_timeout;
} P_QUERY;

typedef struct {
    size_t size;
    size_t count;
    P_QUERY *query_list;

    tox_query_response_cb *query_response;
    void *query_response_object;

} PENDING_QUERIES;

/** query_send_request
 *
 */
int query_send_request(Tox *tox, const char *address, uint16_t port, const uint8_t *key,
                       const uint8_t *name, size_t length);

int query_handle_toxid_response(void *object, IP_Port source, const uint8_t *pkt, uint16_t length, void *userdata);

/**
 * Generate a new query object
 */
PENDING_QUERIES *query_new(Networking_Core *net);

/**
 * Process/iterate pending queries.
 *
 * void *object should always be a DHT *object. but I'm unablet to include DHT.h in this file
 *              because the DHT sturct must contain a PENDING_QUERIES struct.
 */
void query_iterate(void *object);

#endif