#include "fake_event.hh"

#include <gtest/gtest.h>

#ifdef _WIN32
#include <winsock2.h>
#else
#include <netinet/in.h>
#endif

#include <vector>

#include "fake_memory.hh"
#include "fake_network_stack.hh"
#include "network_universe.hh"

namespace tox::test {
namespace {

    class FakeEventTest : public ::testing::Test {
    protected:
        struct Call {
            uint32_t key;
            Ev_Events events;

            bool operator==(const Call &other) const
            {
                return key == other.key && events == other.events;
            }
        };

        FakeEventTest()
        {
            ip_init(&ip, false);
            ip.ip.v4.uint32 = net_htonl(0x7F000001);
        }

        ~FakeEventTest() override { ev_kill(ev); }

        static void record(void *obj, uint32_t key, Ev_Events events)
        {
            static_cast<FakeEventTest *>(obj)->calls.push_back({key, events});
        }

        NetworkUniverse universe;
        IP ip;
        FakeNetworkStack net_stack{universe, ip};
        FakeMemory memory;
        Memory c_memory = memory.c_memory();
        Ev *ev = FakeEvent::create(net_stack, &c_memory);
        std::vector<Call> calls;
    };

    TEST_F(FakeEventTest, OnlyWatchesItsOwnSockets)
    {
        ASSERT_NE(ev, nullptr);
        Socket sock = net_stack.socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

        Ev_Watch *watch = ev_add(ev, sock, EV_READ, record, this, 1);
        EXPECT_NE(watch, nullptr);
        EXPECT_EQ(ev_add(ev, net_socket_from_native(-1), EV_READ, record, this, 2), nullptr);

        ev_del(ev, watch);
        net_stack.close(sock);
    }

    TEST_F(FakeEventTest, RunReadEvent)
    {
        ASSERT_NE(ev, nullptr);
        Socket server = net_stack.socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        IP_Port addr;
        addr.ip = ip;
        addr.port = net_htons(12345);
        net_stack.bind(server, &addr);

        Ev_Watch *watch = ev_add(ev, server, EV_READ, record, this, 42);

        // Initially no events
        EXPECT_EQ(ev_run(ev, 0), 0);

        // Send packet to server
        Socket client = net_stack.socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        uint8_t msg[] = "ping";
        net_stack.sendto(client, msg, sizeof(msg), &addr);
        universe.process_events(0);

        EXPECT_EQ(ev_run(ev, 0), 1);
        EXPECT_EQ(calls, (std::vector<Call>{{42, EV_READ}}));

        ev_del(ev, watch);
        net_stack.close(server);
        net_stack.close(client);
    }

    TEST_F(FakeEventTest, RunWriteEvent)
    {
        ASSERT_NE(ev, nullptr);
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

        Ev_Watch *watch = ev_add(ev, tcp_sock, EV_WRITE, record, this, 99);

        EXPECT_EQ(ev_run(ev, 0), 1);
        EXPECT_EQ(calls, (std::vector<Call>{{99, EV_WRITE}}));

        ev_del(ev, watch);
        net_stack.close(tcp_sock);
        net_stack.close(server);
    }

}  // namespace
}  // namespace tox::test
