// clang-format off
#include "../testing/support/public/simulated_environment.hh"
#include "network.h"
// clang-format on

#include <gtest/gtest.h>

#include <cstring>

#include "network_test_util.hh"

namespace {

TEST(SimulatedEnvironment, ProducesNonNullNetwork)
{
    tox::test::SimulatedEnvironment env{12345};
    auto node = env.create_node(0);
    struct Network net = node->c_network;
    EXPECT_NE(net.funcs, nullptr);
    EXPECT_NE(net.obj, nullptr);
}

TEST(IpNtoa, DoesntWriteOutOfBounds)
{
    Ip_Ntoa ip_str;
    IP ip;
    ip.type = IP_TYPE_V6;
    ip.value.v6.uint64[0] = -1;
    ip.value.v6.uint64[1] = -1;

    net_ip_ntoa(&ip, &ip_str);

    EXPECT_EQ(std::string(ip_str.buf), "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff");
    EXPECT_LT(std::string(ip_str.buf).length(), IP_NTOA_LEN);
}

TEST(IpNtoa, ReportsInvalidIpFamily)
{
    Ip_Ntoa ip_str;
    IP ip;
    ip.type = static_cast<IP_Type>(3);
    ip.value.v4.uint32 = 0;

    net_ip_ntoa(&ip, &ip_str);

    EXPECT_EQ(std::string(ip_str.buf), "(IP invalid, type 3)");
}

TEST(IpNtoa, FormatsIPv4)
{
    Ip_Ntoa ip_str;
    IP ip;
    ip.type = IP_TYPE_V4;
    ip.value.v4.uint8[0] = 192;
    ip.value.v4.uint8[1] = 168;
    ip.value.v4.uint8[2] = 0;
    ip.value.v4.uint8[3] = 13;

    net_ip_ntoa(&ip, &ip_str);

    EXPECT_EQ(std::string(ip_str.buf), "192.168.0.13");
}

TEST(IpParseAddr, FormatsIPv4)
{
    char ip_str[IP_NTOA_LEN];
    IP ip;
    ip.type = IP_TYPE_V4;
    ip.value.v4.uint8[0] = 192;
    ip.value.v4.uint8[1] = 168;
    ip.value.v4.uint8[2] = 0;
    ip.value.v4.uint8[3] = 13;

    ip_parse_addr(&ip, ip_str, sizeof(ip_str));

    EXPECT_EQ(std::string(ip_str), "192.168.0.13");
}

TEST(IpParseAddr, FormatsIPv6)
{
    char ip_str[IP_NTOA_LEN];
    IP ip;
    ip.type = IP_TYPE_V6;
    ip.value.v6.uint64[0] = -1;
    ip.value.v6.uint64[1] = -1;

    ip_parse_addr(&ip, ip_str, sizeof(ip_str));

    EXPECT_EQ(std::string(ip_str), "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff");
}

TEST(IpportCmp, BehavesLikeMemcmp)
{
    auto cmp_val = [](int val) { return val < 0 ? -1 : val > 0 ? 1 : 0; };

    IP_Port a = {};
    IP_Port b = {};

    a.ip.type = IP_TYPE_V4;
    b.ip.type = IP_TYPE_V4;

    a.port = 10;
    b.port = 20;

    EXPECT_EQ(  //
        ipport_cmp_handler(&a, &b, sizeof(IP_Port)), -1)
        << "a=" << a << "\n"
        << "b=" << b;
    EXPECT_EQ(  //
        ipport_cmp_handler(&a, &b, sizeof(IP_Port)),  //
        cmp_val(std::memcmp(&a, &b, sizeof(IP_Port))))
        << "a=" << a << "\n"
        << "b=" << b;

    a.ip.value.v4.uint8[0] = 192;
    b.ip.value.v4.uint8[0] = 10;

    EXPECT_EQ(  //
        ipport_cmp_handler(&a, &b, sizeof(IP_Port)), 1)
        << "a=" << a << "\n"
        << "b=" << b;
    EXPECT_EQ(  //
        ipport_cmp_handler(&a, &b, sizeof(IP_Port)),  //
        cmp_val(std::memcmp(&a, &b, sizeof(IP_Port))))
        << "a=" << a << "\n"
        << "b=" << b;
}

TEST(IpportCmp, Ipv6BeginAndEndCompareCorrectly)
{
    IP_Port a = {};
    IP_Port b = {};

    a.ip.type = IP_TYPE_V6;
    b.ip.type = IP_TYPE_V6;

    a.ip.value.v6.uint8[0] = 0xab;
    b.ip.value.v6.uint8[0] = 0xba;

    EXPECT_EQ(ipport_cmp_handler(&a, &b, sizeof(IP_Port)), -1);

    a.ip.value.v6.uint8[0] = 0;
    b.ip.value.v6.uint8[0] = 0;

    a.ip.value.v6.uint8[15] = 0xba;

    EXPECT_EQ(ipport_cmp_handler(&a, &b, sizeof(IP_Port)), 1);
}

TEST(IpportCmp, UnspecAlwaysComparesEqual)
{
    IP_Port a = {};
    IP_Port b = {};

    a.ip.type = IP_TYPE_UNSPEC;
    b.ip.type = IP_TYPE_UNSPEC;

    a.ip.value.v4.uint8[0] = 0xab;
    b.ip.value.v4.uint8[0] = 0xba;

    EXPECT_EQ(ipport_cmp_handler(&a, &b, sizeof(IP_Port)), 0);
}

TEST(IpportCmp, InvalidAlwaysComparesEqual)
{
    IP_Port a = {};
    IP_Port b = {};

    a.ip.type = static_cast<IP_Type>(3);
    b.ip.type = static_cast<IP_Type>(3);

    a.ip.value.v4.uint8[0] = 0xab;
    b.ip.value.v4.uint8[0] = 0xba;

    EXPECT_EQ(ipport_cmp_handler(&a, &b, sizeof(IP_Port)), 0);
}

}  // namespace
