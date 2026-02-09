#include "fake_event.hh"

#include <gtest/gtest.h>

#ifdef _WIN32
#include <winsock2.h>
#else
#include <netinet/in.h>
#endif

#include "fake_network_stack.hh"
#include "network_universe.hh"

namespace tox::test {
namespace {

    class FakeEventTest : public ::testing::Test {
    protected:
        NetworkUniverse universe;
        IP ip;
        FakeNetworkStack net_stack{universe, ip};
        FakeEvent events{net_stack};

        FakeEventTest()
        {
            ip_init(&ip, false);
            ip.ip.v4.uint32 = net_htonl(0x7F000001);
        }
    };

    TEST_F(FakeEventTest, AddModDel)
    {
        Socket sock = net_stack.socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        int data = 123;

        EXPECT_TRUE(events.add(sock, EV_READ, &data));
        // Duplicate add should fail
        EXPECT_FALSE(events.add(sock, EV_READ, &data));

        EXPECT_TRUE(events.mod(sock, EV_WRITE, &data));
        // Modify non-existent should fail
        Socket invalid = net_socket_from_native(-1);
        EXPECT_FALSE(events.mod(invalid, EV_READ, &data));

        EXPECT_TRUE(events.del(sock));
        // Delete non-existent should fail
        EXPECT_FALSE(events.del(sock));

        net_stack.close(sock);
    }

    TEST_F(FakeEventTest, RunReadEvent)
    {
        Socket server = net_stack.socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        IP_Port addr;
        addr.ip = ip;
        addr.port = net_htons(12345);
        net_stack.bind(server, &addr);

        int user_data = 42;
        events.add(server, EV_READ, &user_data);

        Ev_Result results[1];
        // Initially no events
        EXPECT_EQ(events.run(results, 1, 0), 0);

        // Send packet to server
        Socket client = net_stack.socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        uint8_t msg[] = "ping";
        net_stack.sendto(client, msg, sizeof(msg), &addr);
        universe.process_events(0);

        // Now should have read event
        EXPECT_EQ(events.run(results, 1, 0), 1);
        EXPECT_EQ(results[0].sock.value, server.value);
        EXPECT_EQ(results[0].events, EV_READ);
        EXPECT_EQ(results[0].data, &user_data);

        net_stack.close(server);
        net_stack.close(client);
    }

    TEST_F(FakeEventTest, RunWriteEvent)
    {
        Socket tcp_sock = net_stack.socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        // Bind and connect to make it established (writable)
        IP_Port server_addr;
        server_addr.ip = ip;
        server_addr.port = net_htons(8080);

        Socket server = net_stack.socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        net_stack.bind(server, &server_addr);
        net_stack.listen(server, 1);

        net_stack.connect(tcp_sock, &server_addr);
        universe.process_events(0);  // SYN
        universe.process_events(0);  // SYN-ACK
        universe.process_events(0);  // ACK

        int user_data = 99;
        events.add(tcp_sock, EV_WRITE, &user_data);

        Ev_Result results[1];
        EXPECT_EQ(events.run(results, 1, 0), 1);
        EXPECT_EQ(results[0].sock.value, tcp_sock.value);
        EXPECT_TRUE(results[0].events & EV_WRITE);
        EXPECT_EQ(results[0].data, &user_data);

        net_stack.close(tcp_sock);
        net_stack.close(server);
    }

}  // namespace
}  // namespace tox::test
