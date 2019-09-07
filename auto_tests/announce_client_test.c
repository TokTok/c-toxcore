#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <stdint.h>

#include "../toxcore/announce.c"
#include "../toxcore/announce_client.c"
#include "../toxcore/DHT.c"

#include "../toxcore/tox.h"
#include "../testing/misc_tools.h"
#include "../toxcore/mono_time.h"
#include "../toxcore/forwarding.h"
#include "../toxcore/net_crypto.h"
#include "../toxcore/util.h"
#include "auto_test_support.h"
#include "check_compat.h"

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

static void basic_lookup_test(const uint32_t num_toxes, bool advance_time,
                              AutoTox *autotoxes)
{
    Announcements *announcements[num_toxes];
    Announce_Client *announce_client[num_toxes];
    Forwarding *forwarding[num_toxes];
    Mono_Time *mono_time[num_toxes];

    for (uint32_t i = 0; i < num_toxes; ++i) {
        // TODO(iphydf): Don't rely on toxcore internals.
        Messenger *m = *(Messenger **)autotoxes[i].tox;
        forwarding[i] = new_forwarding(m->log, m->mono_time, m->dht);
        ck_assert(forwarding[i] != nullptr);
        mono_time[i] = m->mono_time;

        announcements[i] = new_announcements(m->log, m->mono_time, forwarding[i]);
        ck_assert(announcements != nullptr);

        announce_client[i] = new_announce_client(
                                 m->mono_time, forwarding[i],
                                 m->net_crypto, announcements[i]);
        ck_assert(announce_client != nullptr);

    }

    uint8_t pk[CRYPTO_PUBLIC_KEY_SIZE];
    uint8_t sk[CRYPTO_SECRET_KEY_SIZE];
    crypto_new_keypair(pk, sk);

    const uint16_t width = 2;
    uint8_t test_data[5];
    memcpy(test_data, "hello", 5);
    ck_assert(add_announce(announce_client[0], pk, width, sk, test_data, sizeof(test_data)));
    const Lookup *announce_lookup = find_lookup(&announce_client[0]->lookups, pk);
    ck_assert(announce_lookup != nullptr);

    do {
        iterate_all_wait(autotoxes, num_toxes, advance_time ? ITERATION_INTERVAL : 0);
        do_announce_client(announce_client[0]);
    } while (!is_announced(mono_time[0], announce_lookup));

    bool retrieved[num_toxes];
    memset(retrieved, 0, sizeof(retrieved));

    for (uint32_t i = 1; i < num_toxes; ++i) {
        ck_assert(add_search(announce_client[i], pk, width, should_retrieve_callback, on_retrieve_callback,
                             mono_time_get(mono_time[i]), &retrieved[i]));
    }

    bool all_retrieved;

    do {
        iterate_all_wait(autotoxes, num_toxes, advance_time ? ITERATION_INTERVAL : 0);
        all_retrieved = true;

        for (uint32_t i = 0; i < num_toxes; ++i) {
            do_announce_client(announce_client[i]);
            all_retrieved &= i == 0 || retrieved[i];
        }
    } while (!all_retrieved);

    for (uint32_t i = 0; i < num_toxes; ++i) {
        kill_announce_client(announce_client[i]);
        kill_announcements(announcements[i]);
        kill_forwarding(forwarding[i]);
    }
}

static void basic_lookup_test_two(AutoTox *autotoxes)
{
    /* A simple announce and lookup with 2 nodes and perfect network
     * conditions should reliably succeed with no timeouts needing to be
     * triggered, so we do not advance time when iterating. */

    basic_lookup_test(2, false, autotoxes);
}

#define NUM_LOOKUP_MANY_TOXES 20

static void basic_lookup_test_many(AutoTox *autotoxes)
{
    basic_lookup_test(NUM_LOOKUP_MANY_TOXES, true, autotoxes);
}

typedef struct Digraph {
    uint32_t n;
    bool **edge;
} Digraph;

static Digraph *new_digraph(uint32_t n)
{
    Digraph *digraph = calloc(1, sizeof(Digraph));
    assert(digraph != nullptr);
    digraph->n = n;
    digraph->edge = calloc(n, sizeof(bool *));
    assert(digraph->edge != nullptr);

    for (uint32_t i = 0; i < n; ++i) {
        digraph->edge[i] = calloc(n, sizeof(bool));
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


#define ANNOUNCE_TEST_BASE_PORT 33500

static void add_dht_to_close(DHT *dht, const DHT *to_add, uint32_t to_add_index)
{
    IP_Port ipport = { get_loopback(), net_htons(ANNOUNCE_TEST_BASE_PORT + to_add_index) };
    add_to_close(dht, dht_get_self_public_key(to_add), &ipport, false);
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

static void lookup_graph_test(const Digraph *digraph, uint32_t announcer, uint32_t target, uint32_t searcher,
                              uint32_t width)
{
    const uint32_t n = digraph->n;

    Logger *log = logger_new();
    logger_callback_log(log, (logger_cb *)print_debug_log, nullptr, nullptr);

    Mono_Time *mono_time[n];
    Networking_Core *net[n];
    DHT *dht[n];
    Net_Crypto *net_c[n];
    Forwarding *forwarding[n];
    Announcements *announce[n];
    Announce_Client *announce_client[n];

    const IP ip = get_loopback();
    TCP_Proxy_Info inf = {{{{0}}}};

    for (uint32_t i = 0; i < digraph->n; ++i) {
        mono_time[i] = mono_time_new();
        const uint16_t port = ANNOUNCE_TEST_BASE_PORT + i;
        net[i] = new_networking_ex(log, &ip, port, port, nullptr);
        dht[i] = new_dht(log, mono_time[i], net[i], true, true);
        net_c[i] = new_net_crypto(log, mono_time[i], dht[i], &inf);
        forwarding[i] = new_forwarding(log, mono_time[i], dht[i]);
        announce[i] = new_announcements(log, mono_time[i], forwarding[i]);
        announce_client[i] = new_announce_client(mono_time[i], forwarding[i], net_c[i], announce[i]);
    }

    connect_dhts(digraph, dht);

    const uint8_t *const pk = dht_get_self_public_key(dht[target]);
    const uint8_t *const sk = dht_get_self_secret_key(dht[target]);

    uint8_t test_data[5];
    memcpy(test_data, "hello", 5);
    ck_assert(add_announce(announce_client[announcer], pk, width, sk, test_data, sizeof(test_data)));
    const Lookup *announce_lookup = find_lookup(&announce_client[announcer]->lookups, pk);
    ck_assert(announce_lookup != nullptr);

    printf("announcing\n");

    do_announce_client(announce_client[announcer]);

    for (uint32_t iterations = 0;
            iterations < n * n && nullptr == get_stored(announce[target], pk);
            ++iterations) {
        for (uint32_t i = 0; i < n; ++i) {
            mono_time_update(mono_time[i]);
            networking_poll(net[i], nullptr);
        }
    }

    ck_assert(get_stored(announce[target], pk));

    // last pass to process search responses from announce before search
    for (uint32_t i = 0; i < n; ++i) {
        networking_poll(net[i], nullptr);
    }

    ck_assert(delete_search_or_announce(announce_client[announcer], pk));

    bool retrieved = false;

    ck_assert(add_search(announce_client[searcher], pk, width,
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
        kill_dht(dht[i]);
        kill_networking(net[i]);
        mono_time_free(mono_time[i]);
    }

    logger_kill(log);
}

static void vee_test(uint32_t length)
{
    printf("A > * ... > * > T < * < ... < S; %d nodes\n", 2 * length + 1);
    Digraph *digraph = new_vee_digraph(length);
    lookup_graph_test(digraph, 0, length, 2 * length, length);
    free_digraph(digraph);
}

static void line_test(uint32_t length)
{
    printf("A=S > * ... > * > T; %d nodes\n", length);
    Digraph *digraph = new_linear_digraph(length);
    lookup_graph_test(digraph, 0, length - 1, 0, length);
    free_digraph(digraph);
}


static void just_two_test()
{
    printf("A=S > T\n");
    Digraph *digraph = new_linear_digraph(2);
    lookup_graph_test(digraph, 0, 1, 0, 2);
    free_digraph(digraph);
}

static void complete_graph_test(uint32_t size)
{
    printf("A <> T <> S <> ...; complete graph; %d nodes\n", size);
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

    Run_Auto_Options options = default_run_auto_options;
    run_auto_test(nullptr, 2, basic_lookup_test_two, 0, &options);

    run_auto_test(nullptr, NUM_LOOKUP_MANY_TOXES, basic_lookup_test_many, 0, &options);
    return 0;
}
