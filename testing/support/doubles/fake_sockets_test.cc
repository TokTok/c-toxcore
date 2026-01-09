#include "fake_sockets.hh"

#include <gtest/gtest.h>

#include "network_universe.hh"

namespace tox::test {
namespace {

    class FakeTcpSocketTest : public ::testing::Test {
    public:
        ~FakeTcpSocketTest() override;

    protected:
        NetworkUniverse universe;
        FakeTcpSocket server{universe};
        FakeTcpSocket client{universe};
    };

    FakeTcpSocketTest::~FakeTcpSocketTest() = default;

    TEST_F(FakeTcpSocketTest, ConnectAndAccept)
    {
        IP_Port server_addr;
        ip_init(&server_addr.ip, false);
        server_addr.ip.ip.v4.uint32 = net_htonl(0x7F000001);
        server_addr.port = net_htons(8080);

        ASSERT_EQ(server.bind(&server_addr), 0);
        ASSERT_EQ(server.listen(5), 0);

        // Client connects
        ASSERT_EQ(client.connect(&server_addr), -1);
        ASSERT_EQ(errno, EINPROGRESS);

        // Process events (Client SYN -> Server)
        universe.process_events(0);

        // Server accepts (SYN-ACK -> Client)
        universe.process_events(0);

        // Client receives SYN-ACK, sends ACK (ACK -> Server)
        universe.process_events(0);

        // Server receives ACK, connection established
        IP_Port client_addr;
        auto accepted = server.accept(&client_addr);
        ASSERT_NE(accepted, nullptr);
        auto *accepted_tcp = static_cast<FakeTcpSocket *>(accepted.get());
        EXPECT_EQ(accepted_tcp->state(), FakeTcpSocket::ESTABLISHED);

        EXPECT_EQ(client.state(), FakeTcpSocket::ESTABLISHED);
    }

    TEST_F(FakeTcpSocketTest, DataTransfer)
    {
        IP_Port server_addr;
        ip_init(&server_addr.ip, false);
        server_addr.ip.ip.v4.uint32 = net_htonl(0x7F000001);
        server_addr.port = net_htons(8081);

        server.bind(&server_addr);
        server.listen(5);
        client.connect(&server_addr);

        // Handshake
        universe.process_events(0);  // SYN
        universe.process_events(0);  // SYN-ACK
        universe.process_events(0);  // ACK

        auto accepted = server.accept(nullptr);
        ASSERT_NE(accepted, nullptr);

        // Send data Client -> Server
        uint8_t send_buf[] = "Hello";
        ASSERT_EQ(client.send(send_buf, 5), 5);

        universe.process_events(0);  // Data packet

        uint8_t recv_buf[10];
        ASSERT_EQ(accepted->recv(recv_buf, 10), 5);
        EXPECT_EQ(std::string(reinterpret_cast<char *>(recv_buf), 5), "Hello");
    }

    class FakeUdpSocketTest : public ::testing::Test {
    public:
        ~FakeUdpSocketTest() override;

    protected:
        NetworkUniverse universe;
        FakeUdpSocket server{universe};
        FakeUdpSocket client{universe};
    };

    FakeUdpSocketTest::~FakeUdpSocketTest() = default;

    TEST_F(FakeUdpSocketTest, BindAndSendTo)
    {
        IP_Port server_addr;
        ip_init(&server_addr.ip, false);
        server_addr.ip.ip.v4.uint32 = net_htonl(0x7F000001);
        server_addr.port = net_htons(9000);

        ASSERT_EQ(server.bind(&server_addr), 0);

        const char *message = "UDP Packet";
        ASSERT_EQ(client.sendto(
                      reinterpret_cast<const uint8_t *>(message), strlen(message), &server_addr),
            strlen(message));

        universe.process_events(0);

        IP_Port sender_addr;
        uint8_t recv_buf[100];
        int len = server.recvfrom(recv_buf, sizeof(recv_buf), &sender_addr);

        ASSERT_GT(len, 0);
        EXPECT_EQ(std::string(reinterpret_cast<char *>(recv_buf), len), message);
        EXPECT_EQ(sender_addr.port, net_htons(client.local_port()));
    }

}  // namespace
}  // namespace tox::test

// end of file
