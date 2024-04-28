/** Auto Tests: basic network profile functionality test (UDP only)
 * TODO(JFreegman): test TCP packets as well
 */

#include <stdint.h>
#include <stdio.h>

#include "../toxcore/tox_private.h"
#include "../toxcore/util.h"

#include "auto_test_support.h"
#include "check_compat.h"

#define NUM_TOXES 2

static void test_netprof(AutoTox *autotoxes)
{
    // Send some messages to create fake traffic
    for (size_t i = 0; i < 256; ++i) {
        for (uint32_t j = 0; j < NUM_TOXES; ++j) {
            tox_friend_send_message(autotoxes[j].tox, 0, TOX_MESSAGE_TYPE_NORMAL, (const uint8_t *)"test", 4, nullptr);
        }

        iterate_all_wait(autotoxes, NUM_TOXES, ITERATION_INTERVAL);
    }

    // idle traffic for a while
    for (size_t i = 0; i < 100; ++i) {
        iterate_all_wait(autotoxes, NUM_TOXES, ITERATION_INTERVAL);
    }

    const Tox *tox1 = autotoxes[0].tox;

    const unsigned long long UDP_count_sent1 = tox_netprof_get_packet_total_count(tox1, TOX_NETPROF_PACKET_TYPE_UDP,
            TOX_NETPROF_DIRECTION_SENT);
    const unsigned long long UDP_count_recv1 = tox_netprof_get_packet_total_count(tox1, TOX_NETPROF_PACKET_TYPE_UDP,
            TOX_NETPROF_DIRECTION_RECV);
    const unsigned long long TCP_count_sent1 = tox_netprof_get_packet_total_count(tox1, TOX_NETPROF_PACKET_TYPE_TCP,
            TOX_NETPROF_DIRECTION_SENT);
    const unsigned long long TCP_count_recv1 = tox_netprof_get_packet_total_count(tox1, TOX_NETPROF_PACKET_TYPE_TCP,
            TOX_NETPROF_DIRECTION_RECV);

    const unsigned long long UDP_bytes_sent1 = tox_netprof_get_packet_total_bytes(tox1, TOX_NETPROF_PACKET_TYPE_UDP,
            TOX_NETPROF_DIRECTION_SENT);
    const unsigned long long UDP_bytes_recv1 = tox_netprof_get_packet_total_bytes(tox1, TOX_NETPROF_PACKET_TYPE_UDP,
            TOX_NETPROF_DIRECTION_RECV);
    const unsigned long long TCP_bytes_sent1 = tox_netprof_get_packet_total_bytes(tox1, TOX_NETPROF_PACKET_TYPE_TCP,
            TOX_NETPROF_DIRECTION_SENT);
    const unsigned long long TCP_bytes_recv1 = tox_netprof_get_packet_total_bytes(tox1, TOX_NETPROF_PACKET_TYPE_TCP,
            TOX_NETPROF_DIRECTION_RECV);

    ck_assert(UDP_count_recv1 > 0 && UDP_count_sent1 > 0);
    ck_assert(UDP_bytes_recv1 > 0 && UDP_bytes_sent1 > 0);

    (void)TCP_count_sent1;
    (void)TCP_bytes_sent1;
    (void)TCP_bytes_recv1;
    (void)TCP_count_recv1;

    unsigned long long total_sent_count = 0;
    unsigned long long total_recv_count = 0;
    unsigned long long total_sent_bytes = 0;
    unsigned long long total_recv_bytes = 0;

    // tox1 makes sure the sum value of all packet ID's is equal to the totals
    for (size_t i = 0; i < 256; ++i) {
        // this id isn't valid for UDP packets but we still want to call the
        // functions and make sure they return some non-zero value
        if (i == TOX_NETPROF_PACKET_ID_TCP_DATA) {
            ck_assert(tox_netprof_get_packet_id_count(tox1, TOX_NETPROF_PACKET_TYPE_UDP, i,
                      TOX_NETPROF_DIRECTION_SENT) > 0);
            ck_assert(tox_netprof_get_packet_id_bytes(tox1, TOX_NETPROF_PACKET_TYPE_UDP, i,
                      TOX_NETPROF_DIRECTION_SENT) > 0);
            ck_assert(tox_netprof_get_packet_id_bytes(tox1, TOX_NETPROF_PACKET_TYPE_UDP, i,
                      TOX_NETPROF_DIRECTION_SENT) > 0);
            ck_assert(tox_netprof_get_packet_id_bytes(tox1, TOX_NETPROF_PACKET_TYPE_UDP, i,
                      TOX_NETPROF_DIRECTION_RECV) > 0);
            continue;
        }

        total_sent_count += tox_netprof_get_packet_id_count(tox1, TOX_NETPROF_PACKET_TYPE_UDP, i,
                            TOX_NETPROF_DIRECTION_SENT);
        total_recv_count += tox_netprof_get_packet_id_count(tox1, TOX_NETPROF_PACKET_TYPE_UDP, i,
                            TOX_NETPROF_DIRECTION_RECV);

        total_sent_bytes += tox_netprof_get_packet_id_bytes(tox1, TOX_NETPROF_PACKET_TYPE_UDP, i,
                            TOX_NETPROF_DIRECTION_SENT);
        total_recv_bytes += tox_netprof_get_packet_id_bytes(tox1, TOX_NETPROF_PACKET_TYPE_UDP, i,
                            TOX_NETPROF_DIRECTION_RECV);
    }

    const unsigned long long total_packets = total_sent_count + total_recv_count;
    ck_assert_msg(total_packets == UDP_count_sent1 + UDP_count_recv1,
                  "%llu does not match %llu\n", total_packets, UDP_count_sent1 + UDP_count_recv1);

    ck_assert_msg(total_sent_count == UDP_count_sent1, "%llu does not match %llu\n", total_sent_count, UDP_count_sent1);
    ck_assert_msg(total_recv_count == UDP_count_recv1, "%llu does not match %llu\n", total_recv_count, UDP_count_recv1);


    const unsigned long long total_bytes = total_sent_bytes + total_recv_bytes;
    ck_assert_msg(total_bytes == UDP_bytes_sent1 + UDP_bytes_recv1,
                  "%llu does not match %llu\n", total_bytes, UDP_bytes_sent1 + UDP_bytes_recv1);

    ck_assert_msg(total_sent_bytes == UDP_bytes_sent1, "%llu does not match %llu\n", total_sent_bytes, UDP_bytes_sent1);
    ck_assert_msg(total_recv_bytes == UDP_bytes_recv1, "%llu does not match %llu\n", total_recv_bytes, UDP_bytes_recv1);
}

int main(void)
{
    setvbuf(stdout, nullptr, _IONBF, 0);

    Run_Auto_Options autotox_opts = default_run_auto_options();
    autotox_opts.graph = GRAPH_COMPLETE;

    run_auto_test(nullptr, NUM_TOXES, test_netprof, 0, &autotox_opts);

    return 0;
}

#undef NUM_TOXES
