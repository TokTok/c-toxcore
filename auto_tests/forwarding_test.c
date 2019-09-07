/*
 * Copyright © 2019 The TokTok team.
 *
 * This file is part of Tox, the free peer to peer instant messenger.
 *
 * Tox is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Tox is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Tox.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <assert.h>
#include <stdlib.h>
#include <string.h>

#include "../toxcore/tox.h"
#include "../testing/misc_tools.h"
#include "../toxcore/mono_time.h"
#include "../toxcore/forwarding.h"
#include "../toxcore/net_crypto.h"
#include "../toxcore/util.h"
#include "auto_test_support.h"
#include "check_compat.h"

#ifndef USE_IPV6
#define USE_IPV6 1
#endif

static inline IP get_loopback(void)
{
    IP ip;
#if USE_IPV6
    ip.family = net_family_ipv6;
    ip.ip.v6 = get_ip6_loopback();
#else
    ip.family = net_family_ipv4;
    ip.ip.v4 = get_ip4_loopback();
#endif
    return ip;
}

#define NUM_FORWARDER 20
#define NUM_FORWARDER_TCP 5
#define NUM_FORWARDER_DHT (NUM_FORWARDER - NUM_FORWARDER_TCP)
#define NUM_FORWARDING_ITERATIONS 1
#define FORWARD_SEND_INTERVAL 2
#define FORWARDER_TCP_RELAY_PORT 36570
#define FORWARDING_BASE_PORT 36571

typedef struct Test_Data {
    Networking_Core *net;
    uint32_t send_back;
    uint64_t sent;
    bool returned;
} Test_Data;

static void test_forwarded_request_cb(void *object, const IP_Port *forwarder,
                                      const uint8_t *sendback, uint16_t sendback_length,
                                      const uint8_t *data, uint16_t length, void *userdata)
{
    Test_Data *test_data = (Test_Data *)object;
    uint8_t *index = (uint8_t *)userdata;

    if (length != 12 || memcmp("hello:  ", data, 8) != 0) {
        printf("[%u] got unexpected data of length %d\n", *index, length);
        return;
    }

    uint8_t reply[12];
    memcpy(reply, "reply:  ", 8);
    memcpy(reply + 8, data + 8, 4);
    ck_assert_msg(forward_reply(test_data->net, forwarder, sendback, sendback_length, reply, 12),
                  "[%u] forward_reply failed", *index);
}

static void test_forwarded_response_cb(void *object,
                                       const uint8_t *data, uint16_t length, void *userdata)
{
    Test_Data *test_data = (Test_Data *)object;
    uint8_t *index = (uint8_t *)userdata;

    if (length != 12 || memcmp("reply:  ", data, 8) != 0) {
        printf("[%u] got unexpected data of length %d\n", *index, length);
        return;
    }

    if (memcmp(&test_data->send_back, data + 8, 4) == 0) {
        test_data->returned = true;
    }
}

static bool all_returned(Test_Data *test_data)
{
    for (uint32_t i = 0; i < NUM_FORWARDER; ++i) {
        if (!test_data[i].returned) {
            return false;
        }
    }

    return true;
}

static void test_forwarding(void)
{
    assert(sizeof(char) == 1);

    uint32_t index[NUM_FORWARDER];
    Logger *logs[NUM_FORWARDER];
    Mono_Time *mono_times[NUM_FORWARDER];
    Networking_Core *nets[NUM_FORWARDER];
    DHT *dhts[NUM_FORWARDER];
    Net_Crypto *cs[NUM_FORWARDER];
    Forwarding *forwardings[NUM_FORWARDER];

    Test_Data test_data[NUM_FORWARDER];

    IP ip = get_loopback();
    TCP_Proxy_Info inf = {{{{0}}}};

    for (uint32_t i = 0; i < NUM_FORWARDER; ++i) {
        index[i] = i + 1;
        logs[i] = logger_new();
        logger_callback_log(logs[i], (logger_cb *)print_debug_log, nullptr, &index[i]);
        mono_times[i] = mono_time_new();

        if (i < NUM_FORWARDER_TCP) {
            nets[i] = new_networking_no_udp(logs[i]);
        } else {
            const uint16_t port = FORWARDING_BASE_PORT + i;
            nets[i] = new_networking_ex(logs[i], &ip, port, port, nullptr);
        }

        dhts[i] = new_dht(logs[i], mono_times[i], nets[i], true, true);
        cs[i] = new_net_crypto(logs[i], mono_times[i], dhts[i], &inf);
        forwardings[i] = new_forwarding(logs[i], mono_times[i], dhts[i]);
        ck_assert_msg((forwardings[i] != nullptr), "Forwarding failed initializing.");

        test_data[i].net = nets[i];
        test_data[i].send_back = 0;
        test_data[i].sent = 0;
        test_data[i].returned = false;
        set_callback_forwarded_request(forwardings[i], test_forwarded_request_cb, &test_data[i]);
        set_callback_forwarded_response(forwardings[i], test_forwarded_response_cb, &test_data[i]);
        set_forwarding_packet_tcp_connection_callback(nc_get_tcp_c(cs[i]), test_forwarded_response_cb, &test_data[i]);
    }

    printf("testing forwarding via tcp relays and dht\n");

    struct Tox_Options *opts = tox_options_new(nullptr);
    tox_options_set_tcp_port(opts, FORWARDER_TCP_RELAY_PORT);
    IP_Port relay_ipport_tcp = {ip, net_htons(FORWARDER_TCP_RELAY_PORT)};
    Tox *relay = tox_new_log(opts, nullptr, nullptr);
    tox_options_free(opts);
    ck_assert_msg(relay != nullptr, "Failed to create TCP relay");

    uint8_t dpk[TOX_PUBLIC_KEY_SIZE];
    tox_self_get_dht_id(relay, dpk);

    printf("1-%d connected only to TCP server; %d-%d connected only to DHT\n",
           NUM_FORWARDER_TCP, NUM_FORWARDER_TCP + 1, NUM_FORWARDER);

    for (uint32_t i = 0; i < NUM_FORWARDER_TCP; ++i) {
        set_tcp_onion_status(nc_get_tcp_c(cs[i]), 1);
        ck_assert_msg(add_tcp_relay(cs[i], &relay_ipport_tcp, dpk) == 0,
                      "Failed to add TCP relay");
    };

    IP_Port relay_ipport_udp = {ip, net_htons(tox_self_get_udp_port(relay, nullptr))};

    for (uint32_t i = NUM_FORWARDER_TCP; i < NUM_FORWARDER; ++i) {
        dht_bootstrap(dhts[i], &relay_ipport_udp, dpk);
    }

    printf("allowing DHT to populate\n");
    uint16_t dht_establish_iterations = NUM_FORWARDER * 5;

    for (uint32_t n = 0; n < NUM_FORWARDING_ITERATIONS; ++n) {
        for (uint32_t i = 0; i < NUM_FORWARDER; ++i) {
            test_data[i].sent = 0;
            test_data[i].returned = false;
        }

        do {
            for (uint32_t i = 0; i < NUM_FORWARDER; ++i) {
                mono_time_update(mono_times[i]);
                networking_poll(nets[i], &index[i]);
                do_net_crypto(cs[i], &index[i]);
                do_dht(dhts[i]);

                if (dht_establish_iterations ||
                        test_data[i].returned ||
                        !mono_time_is_timeout(mono_times[i], test_data[i].sent, FORWARD_SEND_INTERVAL)) {
                    continue;
                }

                printf("%u", i + 1);

                if (i < NUM_FORWARDER_TCP) {
                    printf(" --> TCPRelay");
                }

                const uint16_t chain_length = i < NUM_FORWARDER_TCP ? i % 5 : i % 4 + 1;
                uint8_t chain_keys[4 * CRYPTO_PUBLIC_KEY_SIZE];

                uint32_t chain_i = NUM_FORWARDER_TCP + (random_u32() % NUM_FORWARDER_DHT);
                const IP_Port first_ipp = {ip, net_htons(FORWARDING_BASE_PORT + chain_i)};

                printf(" --> %u", chain_i + 1);

                for (uint16_t j = 0; j < chain_length; ++j) {
                    // pick random different dht node:
                    chain_i += 1 + random_u32() % (NUM_FORWARDER_DHT - 1);
                    chain_i = NUM_FORWARDER_TCP + (chain_i - NUM_FORWARDER_TCP) % NUM_FORWARDER_DHT;

                    const uint8_t *dest_pubkey = dht_get_self_public_key(dhts[chain_i]);

                    memcpy(chain_keys + j * CRYPTO_PUBLIC_KEY_SIZE, dest_pubkey, CRYPTO_PUBLIC_KEY_SIZE);
                    printf(" --> %u", chain_i + 1);
                }

                printf("\n");

                const uint16_t length = 12;
                uint8_t data[12];

                memcpy(data, "hello:  ", 8);
                test_data[i].send_back = random_u32();
                *(uint32_t *)(data + 8) = test_data[i].send_back;

                if (i < NUM_FORWARDER_TCP) {
                    IP_Port tcp_forwarder;

                    if (!get_random_tcp_conn_ip_port(cs[i], &tcp_forwarder)) {
                        continue;
                    }

                    if (send_tcp_forward_request(logs[i], cs[i], &tcp_forwarder, &first_ipp,
                                                 chain_keys, chain_length, data, length) == 0) {
                        test_data[i].sent = mono_time_get(mono_times[i]);
                    }
                } else {
                    if (send_forward_request(nets[i], &first_ipp,
                                             chain_keys, chain_length, data, length)) {
                        test_data[i].sent = mono_time_get(mono_times[i]);
                    }
                }
            }

            tox_iterate(relay, nullptr);

            if (dht_establish_iterations) {
                --dht_establish_iterations;

                if (!dht_establish_iterations) {
                    printf("making forward requests and expecting replies\n");
                }
            }

            c_sleep(50);
        } while (!all_returned(test_data));
    }


    for (uint32_t i = 0; i < NUM_FORWARDER; ++i) {
        kill_forwarding(forwardings[i]);
        kill_net_crypto(cs[i]);
        kill_dht(dhts[i]);
        kill_networking(nets[i]);
        mono_time_free(mono_times[i]);
        logger_kill(logs[i]);
    }

    tox_kill(relay);
}


int main(void)
{
    setvbuf(stdout, nullptr, _IONBF, 0);

    test_forwarding();

    return 0;
}
