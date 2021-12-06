/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2020 The TokTok team.
 * Copyright © 2015 Tox project.
 */

/*
 * Similar to ping.h, but designed for group chat purposes
 */
#ifndef GROUP_ANNOUNCE_H
#define GROUP_ANNOUNCE_H

#include "DHT.h"
#include "stdbool.h"

/* The maximum number of announces to save for a particular group chat. */
#define GCA_MAX_SAVED_ANNOUNCES_PER_GC 16

/* Maximum number of TCP relays that can be in an annoucne. */
#define GCA_MAX_ANNOUNCED_TCP_RELAYS 1

/* Maximum number of announces we can send in an announce response. */
#define GCA_MAX_SENT_ANNOUNCES 4

/* Maximum size of an announce. */
#define GCA_ANNOUNCE_MAX_SIZE sizeof(GC_Announce)

/* Maximum size of a public announce. */
#define GCA_PUBLIC_ANNOUNCE_MAX_SIZE sizeof(GC_Public_Announce)

typedef struct GC_Announce GC_Announce;
typedef struct GC_Peer_Announce GC_Peer_Announce;
typedef struct GC_Announces GC_Announces;
typedef struct GC_Announces_List GC_Announces_List;
typedef struct GC_Public_Announce GC_Public_Announce;

/* Base announce. */
struct GC_Announce {
    Node_format tcp_relays[GCA_MAX_ANNOUNCED_TCP_RELAYS];
    uint8_t tcp_relays_count;
    uint8_t ip_port_is_set;
    IP_Port ip_port;
    uint8_t peer_public_key[ENC_PUBLIC_KEY_SIZE];
};

/* Peer announce for specific group. */
struct GC_Peer_Announce {
    GC_Announce base_announce;
    uint64_t timestamp;
};

/* Used for announces in public groups. */
struct GC_Public_Announce {
    GC_Announce base_announce;
    uint8_t chat_public_key[ENC_PUBLIC_KEY_SIZE];
};

/* A linked list that holds all announces for a particular group. */
struct GC_Announces {
    uint8_t chat_id[CHAT_ID_SIZE];
    uint64_t index;
    uint64_t last_announce_received_timestamp;

    GC_Peer_Announce announces[GCA_MAX_SAVED_ANNOUNCES_PER_GC];

    GC_Announces *next_announce;
    GC_Announces *prev_announce;
};

/* A list of all announces. */
struct GC_Announces_List {
    GC_Announces *announces;
    size_t announces_count;
    uint64_t last_timeout_check;
};


/**
 * Returns a new group announces list.
 */
GC_Announces_List *new_gca_list(void);

/**
 * Frees all dynamically allocated memroy associated with `announces_list`.
 */
void kill_gca(GC_Announces_List *announces_list);

/**
 * Main loop for group announcements.
 */
void do_gca(const Mono_Time *mono_time, GC_Announces_List *gc_announces_list);

/**
 * Frees all dynamically allocated memory for the entry in `gc_announces_list` designated by `chat_id`.
 */
void cleanup_gca(GC_Announces_List *gc_announces_list, const uint8_t *chat_id);

/**
 * Adds a maximum of `max_nodes` announces to `gc_announces` for the group associated with `chat_id`.
 *
 * Announces from the peer designated by `except_public_key` are ignored.
 *
 * Returns the number of added nodes on success.
 * Returns -1 on failure.
 */
int gca_get_announces(const GC_Announces_List *gc_announces_list, GC_Announce *gc_announces, uint8_t max_nodes,
                      const uint8_t *chat_id, const uint8_t *except_public_key);

/**
 * Adds `public_announce` to list of announces for a group.
 *
 * Returns the peer announce on success.
 * Returns null on failure.
 */
GC_Peer_Announce *gca_add_announce(const Mono_Time *mono_time, GC_Announces_List *gc_announces_list,
                                   const GC_Public_Announce *public_announce);

/**
 * Packs `announce` into `data` buffer of size `length`.
 *
 * Returns the size of the packed data on success.
 * Returns -1 on failure.
 */
int gca_pack_announce(uint8_t *data, uint16_t length, const GC_Announce *announce);

/**
 * Unpacks `announce` into `data` buffer of size `length`.
 *
 * Returns the size of the unpacked data on success.
 * Returns -1 on failure.
 */
int gca_unpack_announce(const uint8_t *data, uint16_t length, GC_Announce *announce);

/**
 * Packs `announces_count` announces from `announces` array into `data` buffer of size `length`.
 *
 * The size of the packed data is put in `processed`.
 *
 * Returns the number of packed announces on success.
 * Returns -1 on failure.
 */
int gca_pack_announces_list(uint8_t *data, uint16_t length, const GC_Announce *announces, uint8_t announces_count,
                            size_t *processed);

/**
 * Unpacks a maximum of `max_count` announces from `data` buffer of size `length` and puts them in `annoucnes`.
 *
 * The size of the unpacked data is put in `processed`.
 *
 * Returns the number of unpacked announces on success.
 * Returns -1 on failure.
 */
int gca_unpack_announces_list(const Logger *logger, const uint8_t *data, uint16_t length, GC_Announce *announces,
                              uint8_t max_count, size_t *processed);

/**
 * Packs `public_announce` into `data` buffer of size `length`.
 *
 * Returns the size of the packed data on success.
 * Returns -1 on failure.
 */
int gca_pack_public_announce(uint8_t *data, uint16_t length, const GC_Public_Announce *public_announce);

/**
 * Unpacks a public announce from `data` buffer of size `length` into `public_announce`.
 *
 * Returns the size of the unpacked data on success.
 * Returns -1 on failure.
 */
int gca_unpack_public_announce(const uint8_t *data, uint16_t length, GC_Public_Announce *public_announce);

/**
 * Return true if `announce` is valid.
 *
 * An announce is considered valid if either there is at least one TCP relay, or the ip_port is set.
 */
bool gca_is_valid_announce(const GC_Announce *announce);

#endif /* GROUP_ANNOUNCE_H */
