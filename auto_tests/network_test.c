#include <string.h>

#include "../toxcore/network.h"
#include "../toxcore/os_memory.h"
#include "check_compat.h"

#ifndef USE_IPV6
#define USE_IPV6 1
#endif

static void test_addr_resolv_localhost(void)
{
#ifdef __CYGWIN__
    /* force initialization of network stack
     * normally this should happen automatically
     * cygwin doesn't do it for every network related function though
     * e.g. not for getaddrinfo... */
    net_socket(0, 0, 0);
    errno = 0;
#endif

    const Network *ns = os_network();
    ck_assert(ns != nullptr);

    const Memory *mem = os_memory();
    ck_assert(mem != nullptr);

    const char localhost[] = "localhost";

    IP ip;
    ip_init(&ip, 0); // ipv6enabled = 0

    bool res = addr_resolve_or_parse_ip(ns, mem, localhost, &ip, nullptr, true);

    int error = net_error();
    Net_Strerror error_str;
    ck_assert_msg(res, "Resolver failed: %d, %s", error, net_strerror(error, &error_str));

    Ip_Ntoa ip_str;
    ck_assert_msg(ip.type == IP_TYPE_V4, "Expected IP_TYPE_V4, got %u.", (unsigned)ip.type);
    const uint32_t loopback = get_ip4_loopback().uint32;
    ck_assert_msg(ip.value.v4.uint32 == loopback, "Expected 127.0.0.1, got %s.",
                  net_ip_ntoa(&ip, &ip_str));

    ip_init(&ip, 1); // ipv6enabled = 1
    res = addr_resolve_or_parse_ip(ns, mem, localhost, &ip, nullptr, true);

#if USE_IPV6

    int localhost_split = 0;

    if (ip.type != IP_TYPE_V6) {
        res = addr_resolve_or_parse_ip(ns, mem, "ip6-localhost", &ip, nullptr, true);
        localhost_split = 1;
    }

    error = net_error();
    ck_assert_msg(res, "Resolver failed: %d, %s", error, net_strerror(error, &error_str));

    ck_assert_msg(ip.type == IP_TYPE_V6, "Expected IP_TYPE_V6, got %u.",
                  (unsigned)ip.type);
    IP6 ip6_loopback = get_ip6_loopback();
    ck_assert_msg(!memcmp(&ip.value.v6, &ip6_loopback, sizeof(IP6)), "Expected ::1, got %s.",
                  net_ip_ntoa(&ip, &ip_str));

    if (localhost_split) {
        printf("Localhost seems to be split in two.\n");
        return;
    }

#endif

    ip_init(&ip, 1); // ipv6enabled = 1
    ip.type = IP_TYPE_UNSPEC;
    IP extra;
    ip_reset(&extra);
    res = addr_resolve_or_parse_ip(ns, mem, localhost, &ip, &extra, true);
    error = net_error();
    ck_assert_msg(res, "Resolver failed: %d, %s", error, net_strerror(error, &error_str));

#if USE_IPV6
    ck_assert_msg(ip.type == IP_TYPE_V6, "Expected IP_TYPE_V6, got %u.",
                  (unsigned)ip.type);
    ck_assert_msg(!memcmp(&ip.value.v6, &ip6_loopback, sizeof(IP6)), "Expected ::1, got %s.",
                  net_ip_ntoa(&ip, &ip_str));

    ck_assert_msg(extra.type == IP_TYPE_V4, "Expected IP_TYPE_V4, got %u.",
                  (unsigned)extra.type);
    ck_assert_msg(extra.value.v4.uint32 == loopback, "Expected 127.0.0.1, got %s.",
                  net_ip_ntoa(&ip, &ip_str));
#elif 0
    // TODO(iphydf): Fix this to work on IPv6-supporting systems.
    ck_assert_msg(ip.type == IP_TYPE_V4, "Expected IP_TYPE_V4, got %u.", (unsigned)ip.type);
    ck_assert_msg(ip.value.v4.uint32 == loopback, "Expected 127.0.0.1, got %s.",
                  net_ip_ntoa(&ip, &ip_str));
#endif
}

static void test_ip_equal(void)
{
    int res;
    IP ip1, ip2;
    ip_reset(&ip1);
    ip_reset(&ip2);

    res = ip_equal(nullptr, nullptr);
    ck_assert_msg(res == 0, "ip_equal(NULL, NULL): expected result 0, got %d.", res);

    res = ip_equal(&ip1, nullptr);
    ck_assert_msg(res == 0, "ip_equal(PTR, NULL): expected result 0, got %d.", res);

    res = ip_equal(nullptr, &ip1);
    ck_assert_msg(res == 0, "ip_equal(NULL, PTR): expected result 0, got %d.", res);

    ip1.type = IP_TYPE_V4;
    ip1.value.v4.uint32 = net_htonl(0x7F000001);

    res = ip_equal(&ip1, &ip2);
    ck_assert_msg(res == 0, "ip_equal( {TOX_AF_INET, 127.0.0.1}, {TOX_AF_UNSPEC, 0} ): "
                  "expected result 0, got %d.", res);

    ip2.type = IP_TYPE_V4;
    ip2.value.v4.uint32 = net_htonl(0x7F000001);

    res = ip_equal(&ip1, &ip2);
    ck_assert_msg(res != 0, "ip_equal( {TOX_AF_INET, 127.0.0.1}, {TOX_AF_INET, 127.0.0.1} ): "
                  "expected result != 0, got 0.");

    ip2.value.v4.uint32 = net_htonl(0x7F000002);

    res = ip_equal(&ip1, &ip2);
    ck_assert_msg(res == 0, "ip_equal( {TOX_AF_INET, 127.0.0.1}, {TOX_AF_INET, 127.0.0.2} ): "
                  "expected result 0, got %d.", res);

    ip2.type = IP_TYPE_V6;
    ip2.value.v6.uint32[0] = 0;
    ip2.value.v6.uint32[1] = 0;
    ip2.value.v6.uint32[2] = net_htonl(0xFFFF);
    ip2.value.v6.uint32[3] = net_htonl(0x7F000001);

    ck_assert_msg(ipv6_ipv4_in_v6(&ip2.value.v6) != 0,
                  "ipv6_ipv4_in_v6(::ffff:127.0.0.1): expected != 0, got 0.");

    res = ip_equal(&ip1, &ip2);
    ck_assert_msg(res != 0, "ip_equal( {TOX_AF_INET, 127.0.0.1}, {TOX_AF_INET6, ::ffff:127.0.0.1} ): "
                  "expected result != 0, got 0.");

    IP6 ip6_loopback = get_ip6_loopback();
    memcpy(&ip2.value.v6, &ip6_loopback, sizeof(IP6));
    res = ip_equal(&ip1, &ip2);
    ck_assert_msg(res == 0, "ip_equal( {TOX_AF_INET, 127.0.0.1}, {TOX_AF_INET6, ::1} ): expected result 0, got %d.", res);

    memcpy(&ip1, &ip2, sizeof(IP));
    res = ip_equal(&ip1, &ip2);
    ck_assert_msg(res != 0, "ip_equal( {TOX_AF_INET6, ::1}, {TOX_AF_INET6, ::1} ): expected result != 0, got 0.");

    ip2.value.v6.uint8[15]++;
    res = ip_equal(&ip1, &ip2);
    ck_assert_msg(res == 0, "ip_equal( {TOX_AF_INET6, ::1}, {TOX_AF_INET6, ::2} ): expected result 0, got %d.", res);
}

static void test_unpack_ip_port_bounds(void)
{
    IP_Port ipp;
    ipport_reset(&ipp);

    const uint8_t dummy_v4[7] = {TOX_AF_INET, 192, 168, 1, 1, 0x12, 0x34};
    ck_assert_int_eq(unpack_ip_port(&ipp, dummy_v4, 0), -1);

    for (uint16_t len = 1; len < (uint16_t)sizeof(dummy_v4); ++len) {
        ck_assert_int_eq(unpack_ip_port(&ipp, dummy_v4, len), -1);
    }

    ck_assert_int_eq(unpack_ip_port(&ipp, dummy_v4, sizeof(dummy_v4)), (int)sizeof(dummy_v4));
    ck_assert(ipp.ip.type == IP_TYPE_V4);

    uint8_t dummy_v6[19];
    memset(dummy_v6, 0, sizeof(dummy_v6));
    dummy_v6[0] = TOX_AF_INET6;
    for (uint16_t len = 1; len < (uint16_t)sizeof(dummy_v6); ++len) {
        ck_assert_int_eq(unpack_ip_port(&ipp, dummy_v6, len), -1);
    }

    ck_assert_int_eq(unpack_ip_port(&ipp, dummy_v6, sizeof(dummy_v6)), (int)sizeof(dummy_v6));
    ck_assert(ipp.ip.type == IP_TYPE_V6);

    const uint8_t invalid_family[7] = {0xFF, 1, 2, 3, 4, 5, 6};
    ck_assert_int_eq(unpack_ip_port(&ipp, invalid_family, sizeof(invalid_family)), -1);
}

int main(void)
{
    setvbuf(stdout, nullptr, _IONBF, 0);

    test_addr_resolv_localhost();
    test_ip_equal();
    test_unpack_ip_port_bounds();

    return 0;
}
