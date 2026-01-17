#include "TCP_common.h"

#include <gtest/gtest.h>

#include <cstddef>
#include <cstring>

#include "../testing/support/doubles/fake_memory.hh"
#include "../testing/support/doubles/fake_network_stack.hh"
#include "../testing/support/doubles/network_universe.hh"
#include "logger.h"
#include "network.h"
#include "os_memory.h"
#include "os_random.h"

namespace {

TEST(TCP_common, PriorityQueueOrderingAndIntegrity)
{
    constexpr Network_Funcs mock_funcs = {
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        // Mock net_send to simulate a full buffer (returns 0)
        // This forces packets into the priority queue.
        [](void *obj, Socket sock, const uint8_t *buf, std::size_t len) {
            (void)obj;
            (void)sock;
            (void)buf;
            (void)len;
            return 0;
        },
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
    };

    TCP_Connection con;
    memset(&con, 0, sizeof(con));
    con.mem = os_memory();
    con.rng = os_random();
    Network ns = {&mock_funcs, nullptr};
    con.ns = &ns;

    Logger *logger = logger_new(con.mem);
    ASSERT_NE(logger, nullptr);

    // Minimal initialization to make write_packet_tcp_secure_connection happy
    // It calls encrypt_data_symmetric which needs shared_key and sent_nonce
    memset(con.shared_key, 0x42, sizeof(con.shared_key));
    memset(con.sent_nonce, 0x12, sizeof(con.sent_nonce));

    uint8_t data1[] = "packet1";
    uint8_t data2[] = "packet2";
    uint8_t data3[] = "packet3";

    // First packet: will fail net_send (mocked to 0) and go to add_priority
    // Queue: [packet1]
    int ret1 = write_packet_tcp_secure_connection(logger, &con, data1, sizeof(data1), true);
    ASSERT_EQ(ret1, 1);
    ASSERT_NE(con.priority_queue_start, nullptr);
    ASSERT_EQ(con.priority_queue_start, con.priority_queue_end);

    // Second packet: will go to add_priority
    // Queue: [packet1] -> [packet2]
    int ret2 = write_packet_tcp_secure_connection(logger, &con, data2, sizeof(data2), true);
    ASSERT_EQ(ret2, 1);
    ASSERT_NE(con.priority_queue_start->next, nullptr);
    ASSERT_EQ(con.priority_queue_start->next, con.priority_queue_end);

    // Third packet: will go to add_priority
    // WITH BUG: Queue becomes [packet1] -> [packet3], packet2 is LOST
    // WITHOUT BUG: Queue: [packet1] -> [packet2] -> [packet3]
    int ret3 = write_packet_tcp_secure_connection(logger, &con, data3, sizeof(data3), true);
    ASSERT_EQ(ret3, 1);

    // Verify integrity
    TCP_Priority_List *p = con.priority_queue_start;
    int count = 0;
    while (p) {
        count++;
        p = p->next;
    }

    // This is where it will fail if the change in
    // https://github.com/TokTok/c-toxcore/pull/2387 is applied.
    // The count will be 2 instead of 3.
    EXPECT_EQ(count, 3)
        << "Priority queue lost packets! (likely due to incorrect tail pointer usage)";

    // Clean up
    wipe_priority_list(con.mem, con.priority_queue_start);
    logger_kill(logger);
}

TEST(TCP_common, PriorityQueueIsBoundedUntilDrained)
{
    constexpr Network_Funcs mock_funcs = {
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        // `send`: nothing goes out until the test makes the socket writable.
        [](void *obj, Socket sock, const uint8_t *buf, std::size_t len) {
            (void)sock;
            (void)buf;
            return *static_cast<const bool *>(obj) ? static_cast<int>(len) : 0;
        },
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
        nullptr,
    };

    bool writable = false;
    TCP_Connection con;
    memset(&con, 0, sizeof(con));
    con.mem = os_memory();
    con.rng = os_random();
    Network ns = {&mock_funcs, &writable};
    con.ns = &ns;

    Logger *logger = logger_new(con.mem);
    ASSERT_NE(logger, nullptr);

    memset(con.shared_key, 0x42, sizeof(con.shared_key));
    memset(con.sent_nonce, 0x12, sizeof(con.sent_nonce));

    uint8_t data[] = "packet";

    for (uint32_t i = 0; i < TCP_MAX_PRIORITY_PACKETS; ++i) {
        ASSERT_EQ(write_packet_tcp_secure_connection(logger, &con, data, sizeof(data), true), 1);
    }

    uint8_t nonce[CRYPTO_NONCE_SIZE];
    memcpy(nonce, con.sent_nonce, sizeof(nonce));
    EXPECT_EQ(write_packet_tcp_secure_connection(logger, &con, data, sizeof(data), true), 0);
    EXPECT_EQ(memcmp(nonce, con.sent_nonce, sizeof(nonce)), 0);

    writable = true;
    EXPECT_EQ(send_pending_data(logger, &con), 0);
    EXPECT_EQ(con.priority_queue_length, 0u);

    writable = false;
    EXPECT_EQ(write_packet_tcp_secure_connection(logger, &con, data, sizeof(data), true), 1);

    wipe_priority_list(con.mem, con.priority_queue_start);
    logger_kill(logger);
}

// Bytes left in the socket would keep it readable, and an event loop that waits for readable
// sockets would never wait again until the rest of the packet arrived.
TEST(TCP_common, TakesTheStartOfAPacketOutOfTheSocket)
{
    tox::test::NetworkUniverse universe;
    IP ip;
    ip_init(&ip, false);
    ip.ip.v4.uint32 = net_htonl(0x7F000001);
    tox::test::FakeNetworkStack net_stack{universe, ip};
    Network ns = net_stack.c_network();
    tox::test::FakeMemory memory;
    Memory mem = memory.c_memory();
    Logger *logger = logger_new(&mem);
    ASSERT_NE(logger, nullptr);

    IP_Port server_addr;
    server_addr.ip = ip;
    server_addr.port = net_htons(8080);
    const Socket server = net_socket(&ns, net_family_ipv4(), TOX_SOCK_STREAM, TOX_PROTO_TCP);
    ASSERT_EQ(net_stack.bind(server, &server_addr), 0);
    ASSERT_EQ(net_stack.listen(server, 1), 0);
    const Socket sender = net_socket(&ns, net_family_ipv4(), TOX_SOCK_STREAM, TOX_PROTO_TCP);
    net_stack.connect(sender, &server_addr);
    for (int i = 0; i < 3; ++i) {
        universe.process_events(0);
    }

    TCP_Connection con = {nullptr};
    con.mem = &mem;
    con.ns = &ns;
    con.sock = net_stack.accept(server);
    con.ip_port = server_addr;

    const uint8_t packet[] = {1, 2, 3, 4, 5, 6, 7, 8};
    uint8_t received[sizeof(packet)] = {0};

    // Nothing has arrived: nothing to keep.
    EXPECT_EQ(read_tcp_packet(logger, &con, received, sizeof(received)), -1);
    EXPECT_EQ(con.recv_partial, nullptr);

    ASSERT_EQ(net_stack.send(sender, packet, 3), 3);
    universe.process_events(0);
    ASSERT_EQ(net_socket_data_recv_buffer(&ns, con.sock), 3);

    EXPECT_EQ(read_tcp_packet(logger, &con, received, sizeof(received)), -1);
    EXPECT_EQ(net_socket_data_recv_buffer(&ns, con.sock), 0);

    // The bytes of the next packet stay in the socket until it's asked for.
    const uint8_t next[] = {9, 10};
    ASSERT_EQ(net_stack.send(sender, packet + 3, sizeof(packet) - 3),
        static_cast<int>(sizeof(packet) - 3));
    ASSERT_EQ(net_stack.send(sender, next, sizeof(next)), static_cast<int>(sizeof(next)));
    universe.process_events(0);

    EXPECT_EQ(read_tcp_packet(logger, &con, received, sizeof(received)),
        static_cast<int>(sizeof(received)));
    EXPECT_EQ(std::memcmp(received, packet, sizeof(packet)), 0);
    EXPECT_EQ(net_socket_data_recv_buffer(&ns, con.sock), sizeof(next));
    EXPECT_EQ(con.recv_partial, nullptr);

    // A connection that is closed while it waits for the rest frees what it kept.
    uint8_t never[4];
    EXPECT_EQ(read_tcp_packet(logger, &con, never, sizeof(never)), -1);
    EXPECT_NE(con.recv_partial, nullptr);
    tcp_free_recv_partial(&con);
    EXPECT_EQ(con.recv_partial, nullptr);

    net_stack.close(con.sock);
    net_stack.close(sender);
    net_stack.close(server);
    logger_kill(logger);
}

}
