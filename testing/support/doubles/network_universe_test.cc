#include "network_universe.hh"

#include <gtest/gtest.h>

#include "fake_sockets.hh"

namespace tox::test {
namespace {

    class NetworkUniverseTest : public ::testing::Test {
    public:
        ~NetworkUniverseTest() override;

    protected:
        NetworkUniverse universe;
        FakeUdpSocket s1{universe};
        FakeUdpSocket s2{universe};
    };

    NetworkUniverseTest::~NetworkUniverseTest() = default;

    TEST_F(NetworkUniverseTest, LatencySimulation)
    {
        universe.set_latency(100);

        IP_Port s2_addr;
        ip_init(&s2_addr.ip, false);
        s2_addr.ip.ip.v4.uint32 = 0x7F000001;
        s2_addr.port = 9004;
        s2.bind(&s2_addr);

        uint8_t data[] = "Ping";
        s1.sendto(data, 4, &s2_addr);

        // Time 0: packet sent but delivery time is 100
        universe.process_events(0);
        IP_Port from;
        uint8_t buf[10];
        ASSERT_EQ(s2.recvfrom(buf, 10, &from), -1);

        // Time 50: still not delivered
        universe.process_events(50);
        ASSERT_EQ(s2.recvfrom(buf, 10, &from), -1);

        // Time 100: delivered
        universe.process_events(100);
        ASSERT_EQ(s2.recvfrom(buf, 10, &from), 4);
    }

}  // namespace
}  // namespace tox::test
