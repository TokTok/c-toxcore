/** query.h
 *
 * Makes requests for information using the DHT or Onion as appropriate.
 */

#ifndef QUERY_H
#define QUERY_H

#include "network.h"
#include "crypto_core.h"


#define QUERY_TIMEOUT 500
#define QUERY_MAX_NAME_SIZE 255

typedef struct {
    IP_Port  ipp;
    uint8_t  key[crypto_box_PUBLICKEYBYTES];
    uint8_t  name[QUERY_MAX_NAME_SIZE];
    size_t  length;

    uint64_t query_nonce;

    uint8_t  tries_remaining;
    uint64_t next_timeout;
} Query;

typedef struct {
    size_t size;
    size_t count;
    Query *query_list;

    void (*query_response)(void *tox, const uint8_t *request, size_t length, const uint8_t *tox_id,
                                   void *user_data) ;
    void *query_response_object;

} Pending_Queries;

/** query_send_request
 *
 */
int query_send_request(void *tox, const char *address, uint16_t port, const uint8_t *key,
                       const uint8_t *name, size_t length);

int query_handle_toxid_response(void *object, IP_Port source, const uint8_t *pkt, uint16_t length, void *userdata);

/**
 * Generate a new query object
 */
Pending_Queries *query_new(Networking_Core *net);

/**
 * Process/iterate pending queries.
 *
 * void *object should always be a DHT *object. but I'm unablet to include DHT.h in this file
 *              because the DHT sturct must contain a Pending_Queries struct.
 */
void query_iterate(void *object);

#endif
