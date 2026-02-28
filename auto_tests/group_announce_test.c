/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2026 The TokTok team.
 */

/**
 * Tests GCA (group chat announce) response size bounds.
 *
 * Sends a GCA announce request to a server that has a full DHT node list and
 * a full GCA announce list, then verifies that the response fits within
 * GCA_ANNOUNCE_RESPONSE_MAX_SIZE.
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "../toxcore/DHT.h"
#include "../toxcore/crypto_core.h"
#include "../toxcore/group_announce.h"
#include "../toxcore/group_onion_announce.h"
#include "../toxcore/logger.h"
#include "../toxcore/mono_time.h"
#include "../toxcore/net.h"
#include "../toxcore/network.h"
#include "../toxcore/onion.h"
#include "../toxcore/onion_announce.h"
#include "../toxcore/os_memory.h"
#include "../toxcore/os_random.h"
#include "auto_test_support.h"
#include "check_compat.h"

#ifndef USE_IPV6
#define USE_IPV6 1
#endif

static inline IP get_loopback(void)
{
    IP ip;
#if USE_IPV6
    ip.family = net_family_ipv6();
    ip.ip.v6 = get_ip6_loopback();
#else
    ip.family = net_family_ipv4();
    ip.ip.v4 = get_ip4_loopback();
#endif
    return ip;
}

typedef struct {
    bool     received;
    uint16_t length;
} Recv3_State;

static int handle_recv_3(void *object, const IP_Port *source, const uint8_t *packet,
                         uint16_t length, void *userdata)
{
    Recv3_State *state = (Recv3_State *)object;
    state->received = true;
    state->length   = length;
    return 0;
}

/** Fill @p ann with a maximum-size IPv6 announce (IPv6 ip_port + IPv6 TCP relay). */
static void fill_max_public_announce(const Random *rng, GC_Public_Announce *ann,
                                     const uint8_t *chat_pk)
{
    memcpy(ann->chat_public_key, chat_pk, ENC_PUBLIC_KEY_SIZE);
    random_bytes(rng, ann->base_announce.peer_public_key, ENC_PUBLIC_KEY_SIZE);

    ann->base_announce.ip_port.ip.family = net_family_ipv6();
    random_bytes(rng, ann->base_announce.ip_port.ip.ip.v6.uint8,
                 sizeof(ann->base_announce.ip_port.ip.ip.v6.uint8));
    ann->base_announce.ip_port.port   = net_htons(33445);
    ann->base_announce.ip_port_is_set = true;

    ann->base_announce.tcp_relays_count = GCA_MAX_ANNOUNCED_TCP_RELAYS;
    random_bytes(rng, ann->base_announce.tcp_relays[0].public_key,
                 CRYPTO_PUBLIC_KEY_SIZE);
    ann->base_announce.tcp_relays[0].ip_port.ip.family = net_family_tcp_ipv6();
    random_bytes(rng, ann->base_announce.tcp_relays[0].ip_port.ip.ip.v6.uint8,
                 sizeof(ann->base_announce.tcp_relays[0].ip_port.ip.ip.v6.uint8));
    ann->base_announce.tcp_relays[0].ip_port.port = net_htons(33445);
}

/** Fill @p ann with a small IPv4-only announce (fits within GCA_ANNOUNCE_MAX_SIZE). */
static void fill_small_public_announce(const Random *rng, GC_Public_Announce *ann,
                                       const uint8_t *chat_pk)
{
    memcpy(ann->chat_public_key, chat_pk, ENC_PUBLIC_KEY_SIZE);
    random_bytes(rng, ann->base_announce.peer_public_key, ENC_PUBLIC_KEY_SIZE);

    ann->base_announce.ip_port.ip.family = net_family_ipv4();
    ann->base_announce.ip_port.ip.ip.v4  = get_ip4_loopback();
    ann->base_announce.ip_port.port       = net_htons(33445);
    ann->base_announce.ip_port_is_set     = true;
    ann->base_announce.tcp_relays_count   = 0;
}

static void test_gca_announce_response_size(void)
{
    const Memory  *mem = os_memory();
    ck_assert(mem != nullptr);
    const Random  *rng = os_random();
    ck_assert(rng != nullptr);
    const Network *ns  = os_network();
    ck_assert(ns != nullptr);

    /* ------------------------------------------------------------------ */
    /* Server node: Onion_Announce with GCA callback registered.          */
    /* ------------------------------------------------------------------ */
    uint32_t srv_idx = 1;
    uint32_t cli_idx = 2;

    Logger *srv_log = logger_new(mem);
    ck_assert(srv_log != nullptr);
    logger_callback_log(srv_log, print_debug_logger, nullptr, &srv_idx);

    Mono_Time *srv_mono = mono_time_new(mem, nullptr, nullptr);
    ck_assert(srv_mono != nullptr);
    mono_time_update(srv_mono);

    IP ip = get_loopback();

    Networking_Core *srv_net = new_networking_ex(
                                   srv_log, mem, ns, &ip, 36700,
                                   36700 + (TOX_PORTRANGE_TO - TOX_PORTRANGE_FROM), nullptr);
    ck_assert(srv_net != nullptr);

    DHT *srv_dht = new_dht(srv_log, mem, rng, ns, srv_mono, srv_net, true, false);
    ck_assert(srv_dht != nullptr);

    Onion *srv_onion = new_onion(srv_log, mem, srv_mono, rng, srv_dht, srv_net);
    ck_assert(srv_onion != nullptr);

    Onion_Announce *srv_onion_a = new_onion_announce(
                                      srv_log, mem, rng, srv_mono, srv_dht, srv_net);
    ck_assert(srv_onion_a != nullptr);

    GC_Announces_List *gca_list = new_gca_list(mem);
    ck_assert(gca_list != nullptr);

    gca_onion_init(gca_list, srv_onion_a);

    /* Pre-fill the GCA list with GCA_MAX_SENT_ANNOUNCES full-size IPv6
     * announces so the server returns a maximally-populated response. */
    uint8_t chat_pk[ENC_PUBLIC_KEY_SIZE];
    random_bytes(rng, chat_pk, sizeof(chat_pk));

    for (uint32_t i = 0; i < GCA_MAX_SENT_ANNOUNCES; ++i) {
        GC_Public_Announce ann;
        fill_max_public_announce(rng, &ann, chat_pk);
        mono_time_update(srv_mono);
        GC_Peer_Announce *peer_ann = gca_add_announce(mem, srv_mono, gca_list, &ann);
        ck_assert_msg(peer_ann != nullptr, "Failed to add pre-filled GCA announce %u", i);
    }

    /* Inject MAX_SENT_NODES fake LAN entries so get_close_nodes() returns
     * a full node list alongside the GCA announces. */
    for (uint32_t i = 0; i < MAX_SENT_NODES; ++i) {
        uint8_t fake_pk[CRYPTO_PUBLIC_KEY_SIZE];
        random_bytes(rng, fake_pk, sizeof(fake_pk));
        IP_Port fake_ipp;
        fake_ipp.ip.family         = net_family_ipv4();
        fake_ipp.ip.ip.v4.uint8[0] = 10;
        fake_ipp.ip.ip.v4.uint8[1] = 0;
        fake_ipp.ip.ip.v4.uint8[2] = 0;
        fake_ipp.ip.ip.v4.uint8[3] = (uint8_t)(i + 1);
        fake_ipp.port              = net_htons(33445 + i);
        addto_lists(srv_dht, &fake_ipp, fake_pk);
    }

    /* ------------------------------------------------------------------ */
    /* Client node: raw Networking_Core with a RECV_3 capture handler.    */
    /* ------------------------------------------------------------------ */
    Logger *cli_log = logger_new(mem);
    ck_assert(cli_log != nullptr);
    logger_callback_log(cli_log, print_debug_logger, nullptr, &cli_idx);

    Mono_Time *cli_mono = mono_time_new(mem, nullptr, nullptr);
    ck_assert(cli_mono != nullptr);

    Networking_Core *cli_net = new_networking_ex(
                                   cli_log, mem, ns, &ip, 36701,
                                   36701 + (TOX_PORTRANGE_TO - TOX_PORTRANGE_FROM), nullptr);
    ck_assert(cli_net != nullptr);

    Recv3_State state = {false, 0};
    networking_registerhandler(cli_net, NET_PACKET_ONION_RECV_3,
                               handle_recv_3, &state);

    /* ------------------------------------------------------------------ */
    /* Build a GCA announce request and send it directly to the server.   */
    /* ------------------------------------------------------------------ */

    /* Use a small IPv4-only public announce as the gc_data payload so that
     * gc_data_length fits within the GCA_ANNOUNCE_MAX_SIZE limit. */
    GC_Public_Announce my_ann;
    fill_small_public_announce(rng, &my_ann, chat_pk);

    uint8_t gc_data[GCA_PUBLIC_ANNOUNCE_MAX_SIZE];
    const int gc_data_len = gca_pack_public_announce(
                                srv_log, gc_data, sizeof(gc_data), &my_ann);
    ck_assert_msg(gc_data_len > 0, "Failed to pack public announce");
    ck_assert_msg((uint16_t)gc_data_len <= GCA_ANNOUNCE_MAX_SIZE,
                  "gc_data_len %d exceeds GCA_ANNOUNCE_MAX_SIZE", gc_data_len);

    uint8_t cli_pk[CRYPTO_PUBLIC_KEY_SIZE];
    uint8_t cli_sk[CRYPTO_SECRET_KEY_SIZE];
    crypto_new_keypair(rng, cli_pk, cli_sk);

    uint8_t data_pk[CRYPTO_PUBLIC_KEY_SIZE];
    uint8_t data_sk[CRYPTO_SECRET_KEY_SIZE];
    crypto_new_keypair(rng, data_pk, data_sk);

    const uint8_t zeroes[ONION_PING_ID_SIZE] = {0};
    const uint64_t sendback = 0x0102030405060708ULL;

    /* The request buffer must also hold ONION_RETURN_3 return-path bytes
     * at the tail, as required by the announce request handler. */
    const uint16_t req_cap = ONION_ANNOUNCE_REQUEST_MAX_SIZE + ONION_RETURN_3;
    uint8_t *req_buf = (uint8_t *)malloc(req_cap);
    ck_assert(req_buf != nullptr);

    const int req_len = create_gca_announce_request(
                            mem, rng, req_buf, ONION_ANNOUNCE_REQUEST_MAX_SIZE,
                            dht_get_self_public_key(srv_dht),
                            cli_pk, cli_sk,
                            zeroes, cli_pk, data_pk, sendback,
                            gc_data, (uint16_t)gc_data_len);
    ck_assert_msg(req_len > 0, "Failed to create GCA announce request");

    memset(req_buf + req_len, 0, ONION_RETURN_3);
    const uint16_t total_len = (uint16_t)(req_len + ONION_RETURN_3);

    const IP_Port srv_ipp = {ip, net_port(srv_net)};
    ck_assert_msg(sendpacket(cli_net, &srv_ipp, req_buf, total_len) == total_len,
                  "Failed to send GCA announce request");
    free(req_buf);

    /* ------------------------------------------------------------------ */
    /* Poll until response received or 1-second timeout (200 × 5 ms).    */
    /* ------------------------------------------------------------------ */
    for (int i = 0; i < 200 && !state.received; ++i) {
        mono_time_update(srv_mono);
        mono_time_update(cli_mono);
        networking_poll(srv_net, nullptr);
        networking_poll(cli_net, nullptr);
        c_sleep(5);
    }

    ck_assert_msg(state.received, "No GCA announce response received within timeout");

    /* The ONION_RECV_3 packet layout:
     *   [1 byte type] [ONION_RETURN_3 bytes return path] [payload bytes] */
    ck_assert_msg(state.length > (uint16_t)(1 + ONION_RETURN_3),
                  "RECV_3 packet too short to contain any payload: %u", state.length);

    const uint16_t resp_len = state.length - (uint16_t)(1 + ONION_RETURN_3);

    ck_assert_msg(resp_len >= ONION_ANNOUNCE_RESPONSE_MIN_SIZE,
                  "announce response too small: %u (min %u)",
                  resp_len, (unsigned int)ONION_ANNOUNCE_RESPONSE_MIN_SIZE);

    ck_assert_msg(resp_len <= GCA_ANNOUNCE_RESPONSE_MAX_SIZE,
                  "announce response too large: %u (max %u)",
                  resp_len, (unsigned int)GCA_ANNOUNCE_RESPONSE_MAX_SIZE);

    printf("GCA announce response payload: %u bytes "
           "(min: %u, max: %u)\n",
           resp_len,
           (unsigned int)ONION_ANNOUNCE_RESPONSE_MIN_SIZE,
           (unsigned int)GCA_ANNOUNCE_RESPONSE_MAX_SIZE);

    /* ------------------------------------------------------------------ */
    /* Cleanup (reverse order of creation).                               */
    /* ------------------------------------------------------------------ */
    networking_registerhandler(cli_net, NET_PACKET_ONION_RECV_3, nullptr, nullptr);
    kill_networking(cli_net);
    mono_time_free(mem, cli_mono);
    logger_kill(cli_log);

    kill_gca(gca_list);
    kill_onion_announce(srv_onion_a);
    kill_onion(srv_onion);
    kill_dht(srv_dht);
    kill_networking(srv_net);
    mono_time_free(mem, srv_mono);
    logger_kill(srv_log);
}

static void basic_gca_announce_tests(void)
{
    test_gca_announce_response_size();
}

int main(void)
{
    setvbuf(stdout, nullptr, _IONBF, 0);

    basic_gca_announce_tests();
    return 0;
}
