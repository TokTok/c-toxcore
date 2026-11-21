#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../toxcore/DHT.h"
#include "../toxcore/announce.h"
#include "../toxcore/announce_client.h"
#include "../toxcore/forwarding.h"
#include "../toxcore/logger.h"
#include "../toxcore/mono_time.h"
#include "../toxcore/net_crypto.h"
#include "../toxcore/net_profile.h"
#include "../toxcore/network.h"
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

static bool should_retrieve_callback(void *object, const uint8_t *hash)
{
    return true;
}

static void on_retrieve_callback(void *object, const uint8_t *data, uint16_t length)
{
    bool *retrieved = (bool *)object;

    if (length == 5 && memcmp(data, "hello", length) == 0) {
        *retrieved = true;
    }
}

typedef struct Digraph {
    uint32_t n;
    bool **edge;
} Digraph;

static Digraph *new_digraph(uint32_t n)
{
    Digraph *digraph = (Digraph *)calloc(1, sizeof(Digraph));
    assert(digraph != nullptr);
    digraph->n = n;
    digraph->edge = (bool **)calloc(n, sizeof(bool *));
    assert(digraph->edge != nullptr);

    for (uint32_t i = 0; i < n; ++i) {
        digraph->edge[i] = (bool *)calloc(n, sizeof(bool));
        assert(digraph->edge[i] != nullptr);
    }

    return digraph;
}
static void free_digraph(Digraph *digraph)
{
    for (uint32_t i = 0; i < digraph->n; ++i) {
        free(digraph->edge[i]);
    }

    free(digraph->edge);
    free(digraph);
}

static Digraph *new_complete_digraph(uint32_t n)
{
    Digraph *digraph = new_digraph(n);

    for (uint32_t i = 0; i < n - 1; ++i) {
        for (uint32_t j = 0; j < n - 1; ++j) {
            if (i != j) {
                digraph->edge[i][j] = true;
            }
        }
    }

    return digraph;
}

static Digraph *new_linear_digraph(uint32_t n)
{
    Digraph *digraph = new_digraph(n);

    for (uint32_t i = 0; i < n - 1; ++i) {
        digraph->edge[i][i + 1] = true;
    }

    return digraph;
}

static Digraph *new_vee_digraph(uint32_t len)
{
    Digraph *digraph = new_digraph(2 * len + 1);

    for (uint32_t i = 0; i < len; ++i) {
        digraph->edge[i][i + 1] = true;
    }

    for (uint32_t i = 0; i < len; ++i) {
        digraph->edge[len + i + 1][len + i] = true;
    }

    return digraph;
}


/* Outside the ports the Tox instances of other tests use. */
#define ANNOUNCE_TEST_BASE_PORT 36900

static void add_dht_to_close(DHT *dht, const DHT *to_add, uint32_t to_add_index)
{
    const IP_Port ipport = { get_loopback(), net_htons(ANNOUNCE_TEST_BASE_PORT + to_add_index) };
    addto_lists(dht, &ipport, dht_get_self_public_key(to_add));
    set_announce_node(dht, dht_get_self_public_key(to_add));
}

static void connect_dhts(const Digraph *digraph, DHT **dhts)
{
    for (uint32_t i = 0; i < digraph->n; ++i) {
        for (uint32_t j = 0; j < digraph->n; ++j) {
            if (i != j && digraph->edge[i][j]) {
                add_dht_to_close(dhts[i], dhts[j], j);
            }
        }
    }
}

static void on_stored_callback(void *object, const uint8_t *data, uint16_t length)
{
}

static void lookup_graph_test(const Digraph *digraph, uint32_t announcer, uint32_t target, uint32_t searcher,
                              uint32_t width)
{
    const uint32_t n = digraph->n;

    const Memory *mem = os_memory();
    ck_assert(mem != nullptr);
    const Random *rng = os_random();
    ck_assert(rng != nullptr);
    const Network *ns = os_network();
    ck_assert(ns != nullptr);

    Logger *log = logger_new(mem);
    ck_assert(log != nullptr);
    logger_callback_log(log, print_debug_logger, nullptr, nullptr);

    Mono_Time **mono_time = (Mono_Time **)calloc(n, sizeof(Mono_Time *));
    Networking_Core **net = (Networking_Core **)calloc(n, sizeof(Networking_Core *));
    Net_Profile **tcp_np = (Net_Profile **)calloc(n, sizeof(Net_Profile *));
    DHT **dht = (DHT **)calloc(n, sizeof(DHT *));
    Net_Crypto **net_c = (Net_Crypto **)calloc(n, sizeof(Net_Crypto *));
    Forwarding **forwarding = (Forwarding **)calloc(n, sizeof(Forwarding *));
    Announcements **announce = (Announcements **)calloc(n, sizeof(Announcements *));
    Announce_Client **announce_client = (Announce_Client **)calloc(n, sizeof(Announce_Client *));
    ck_assert(mono_time != nullptr && net != nullptr && tcp_np != nullptr && dht != nullptr && net_c != nullptr
              && forwarding != nullptr && announce != nullptr && announce_client != nullptr);

    const IP ip = get_loopback();
    const TCP_Proxy_Info inf = {{{{0}}}};

    for (uint32_t i = 0; i < n; ++i) {
        mono_time[i] = mono_time_new(mem, nullptr, nullptr);
        ck_assert(mono_time[i] != nullptr);
        const uint16_t port = ANNOUNCE_TEST_BASE_PORT + i;
        net[i] = new_networking_ex(log, mem, ns, &ip, port, port, nullptr);
        ck_assert(net[i] != nullptr);
        dht[i] = new_dht(log, mem, rng, ns, mono_time[i], net[i], true, true);
        ck_assert(dht[i] != nullptr);
        tcp_np[i] = netprof_new(log, mem);
        ck_assert(tcp_np[i] != nullptr);
        net_c[i] = new_net_crypto(log, mem, rng, ns, mono_time[i], net[i], dht[i], &auto_test_dht_funcs, &inf, tcp_np[i]);
        ck_assert(net_c[i] != nullptr);
        forwarding[i] = new_forwarding(log, mem, rng, mono_time[i], dht[i], net[i]);
        ck_assert(forwarding[i] != nullptr);
        announce[i] = new_announcements(log, mem, rng, mono_time[i], forwarding[i], dht[i], net[i]);
        ck_assert(announce[i] != nullptr);
        announce_client[i] = new_announce_client(log, mem, rng, mono_time[i], forwarding[i], dht[i], net[i], net_c[i], announce[i]);
        ck_assert(announce_client[i] != nullptr);
    }

    connect_dhts(digraph, dht);

    const uint8_t *const pk = dht_get_self_public_key(dht[target]);
    const uint8_t *const sk = dht_get_self_secret_key(dht[target]);

    uint8_t test_data[5];
    memcpy(test_data, "hello", 5);
    // A lookup needs at least 1 node.
    ck_assert(!announce_client_add_announce(announce_client[announcer], pk, 0, sk, test_data, sizeof(test_data)));
    ck_assert(announce_client_add_announce(announce_client[announcer], pk, width, sk, test_data, sizeof(test_data)));

    printf("announcing\n");

    do_announce_client(announce_client[announcer]);

    for (uint32_t iterations = 0;
            iterations < n * n && !announce_on_stored(announce[target], pk, on_stored_callback, nullptr);
            ++iterations) {
        for (uint32_t i = 0; i < n; ++i) {
            mono_time_update(mono_time[i]);
            networking_poll(net[i], nullptr);
        }
    }

    ck_assert(announce_on_stored(announce[target], pk, on_stored_callback, nullptr));

    // last pass to process search responses from announce before search
    for (uint32_t i = 0; i < n; ++i) {
        networking_poll(net[i], nullptr);
    }

    ck_assert(announce_client_delete(announce_client[announcer], pk));

    bool retrieved = false;

    ck_assert(announce_client_add_search(announce_client[searcher], pk, width,
                         should_retrieve_callback, on_retrieve_callback,
                         mono_time_get(mono_time[searcher]), &retrieved));

    printf("searching\n");

    do_announce_client(announce_client[searcher]);

    for (uint32_t iterations = 0;
            iterations < n * n && !retrieved;
            ++iterations) {
        for (uint32_t i = 0; i < n; ++i) {
            mono_time_update(mono_time[i]);
            networking_poll(net[i], nullptr);
        }
    }

    ck_assert(retrieved);

    for (uint32_t i = 0; i < n; ++i) {
        kill_announce_client(announce_client[i]);
        kill_announcements(announce[i]);
        kill_forwarding(forwarding[i]);
        kill_net_crypto(net_c[i]);
        netprof_kill(mem, tcp_np[i]);
        kill_dht(dht[i]);
        kill_networking(net[i]);
        mono_time_free(mem, mono_time[i]);
    }

    free(announce_client);
    free(announce);
    free(forwarding);
    free(net_c);
    free(dht);
    free(tcp_np);
    free(net);
    free(mono_time);

    logger_kill(log);
}

static void vee_test(uint32_t length)
{
    printf("A > * ... > * > T < * < ... < S; %u nodes\n", 2 * length + 1);
    Digraph *digraph = new_vee_digraph(length);
    lookup_graph_test(digraph, 0, length, 2 * length, length);
    free_digraph(digraph);
}

static void line_test(uint32_t length)
{
    printf("A=S > * ... > * > T; %u nodes\n", length);
    Digraph *digraph = new_linear_digraph(length);
    lookup_graph_test(digraph, 0, length - 1, 0, length);
    free_digraph(digraph);
}


static void just_two_test(void)
{
    printf("A=S > T\n");
    Digraph *digraph = new_linear_digraph(2);
    lookup_graph_test(digraph, 0, 1, 0, 2);
    free_digraph(digraph);
}

static void complete_graph_test(uint32_t size)
{
    printf("A <> T <> S <> ...; complete graph; %u nodes\n", size);
    Digraph *digraph = new_complete_digraph(size);
    assert(size >= 3);
    lookup_graph_test(digraph, 0, 1, 2, 4);
    free_digraph(digraph);
}

int main(void)
{
    setvbuf(stdout, nullptr, _IONBF, 0);

    just_two_test();

    line_test(4);

    vee_test(4);

    complete_graph_test(5);
    complete_graph_test(15);
    complete_graph_test(25);
    return 0;
}
