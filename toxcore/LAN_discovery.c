/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2025 The TokTok team.
 * Copyright © 2013 Tox project.
 */

/**
 * LAN discovery implementation.
 */
#include "LAN_discovery.h"

#if defined(_WIN32) || defined(__WIN32__) || defined(WIN32)
// The mingw32/64 Windows library warns about including winsock2.h after
// windows.h even though with the above it's a valid thing to do. So, to make
// mingw32 headers happy, we include winsock2.h first.
#include <winsock2.h>

#include <windows.h>
#include <ws2tcpip.h>

#include <iphlpapi.h>
#endif /* WIN32 */

#if defined(__linux__) || defined(__FreeBSD__) || defined(__DragonFly__)
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#endif /* Linux/BSD */

#ifdef __linux__
#include <linux/if.h>
#endif /* Linux */

#if defined(__FreeBSD__) || defined(__DragonFly__)
#include <net/if.h>
#endif /* BSD */

#include "attributes.h"
#include "ccompat.h"
#include "crypto_core.h"
#include "mem.h"
#include "network.h"

#define MAX_INTERFACES 16

struct Broadcast_Info {
    const Memory *mem;

    uint32_t count;
    IP ips[MAX_INTERFACES];
};

#if defined(_WIN32) || defined(__WIN32__) || defined(WIN32)

static Broadcast_Info *fetch_broadcast_info(const Memory *_Nonnull mem, const Network *_Nonnull ns)
{
    Broadcast_Info *broadcast = (Broadcast_Info *)mem_alloc(mem, sizeof(Broadcast_Info));

    if (broadcast == nullptr) {
        return nullptr;
    }

    broadcast->mem = mem;

    IP_ADAPTER_INFO *adapter_info = (IP_ADAPTER_INFO *)mem_balloc(mem, sizeof(IP_ADAPTER_INFO));

    if (adapter_info == nullptr) {
        mem_delete(mem, broadcast);
        return nullptr;
    }

    unsigned long out_buf_len = sizeof(IP_ADAPTER_INFO);

    if (GetAdaptersInfo(adapter_info, &out_buf_len) == ERROR_BUFFER_OVERFLOW) {
        mem_delete(mem, adapter_info);
        IP_ADAPTER_INFO *new_adapter_info = (IP_ADAPTER_INFO *)mem_balloc(mem, out_buf_len);

        if (new_adapter_info == nullptr) {
            mem_delete(mem, broadcast);
            return nullptr;
        }

        adapter_info = new_adapter_info;
    }

    const int ret = GetAdaptersInfo(adapter_info, &out_buf_len);

    if (ret == NO_ERROR) {
        IP_ADAPTER_INFO *adapter = adapter_info;

        while (adapter != nullptr) {
            IP gateway = {0};
            IP subnet_mask = {0};

            if (addr_parse_ip(adapter->IpAddressList.IpMask.String, &subnet_mask)
                    && addr_parse_ip(adapter->GatewayList.IpAddress.String, &gateway)) {
                if (net_family_is_ipv4(gateway.family) && net_family_is_ipv4(subnet_mask.family)) {
                    IP *ip = &broadcast->ips[broadcast->count];
                    ip->family = net_family_ipv4();
                    const uint32_t gateway_ip = net_ntohl(gateway.ip.v4.uint32);
                    const uint32_t subnet_ip = net_ntohl(subnet_mask.ip.v4.uint32);
                    const uint32_t broadcast_ip = gateway_ip + ~subnet_ip - 1;
                    ip->ip.v4.uint32 = net_htonl(broadcast_ip);
                    ++broadcast->count;

                    if (broadcast->count >= MAX_INTERFACES) {
                        break;
                    }
                }
            }

            adapter = adapter->Next;
        }
    }

    if (adapter_info != nullptr) {
        mem_delete(mem, adapter_info);
    }

    return broadcast;
}

#elif !defined(FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION) && (defined(__linux__) || defined(__FreeBSD__) || defined(__DragonFly__))

static bool ip4_is_local(const IP4 *_Nonnull ip4);

static Broadcast_Info *fetch_broadcast_info(const Memory *_Nonnull mem, const Network *_Nonnull ns)
{
    Broadcast_Info *broadcast = (Broadcast_Info *)mem_alloc(mem, sizeof(Broadcast_Info));

    if (broadcast == nullptr) {
        return nullptr;
    }

    broadcast->mem = mem;

    /* Not sure how many platforms this will run on,
     * so it's wrapped in `__linux__` for now.
     * Definitely won't work like this on Windows...
     */
    const Socket sock = net_socket(ns, net_family_ipv4(), TOX_SOCK_STREAM, 0);

    if (!sock_valid(sock)) {
        mem_delete(mem, broadcast);
        return nullptr;
    }

    /* Configure ifconf for the ioctl call. */
    struct ifreq i_faces[MAX_INTERFACES] = {{{0}}};

    struct ifconf ifc;
    ifc.ifc_buf = (char *)i_faces;
    ifc.ifc_len = sizeof(i_faces);

    if (ioctl(net_socket_to_native(sock), SIOCGIFCONF, &ifc) < 0) {
        kill_sock(ns, sock);
        mem_delete(mem, broadcast);
        return nullptr;
    }

    /* `ifc.ifc_len` is set by the `ioctl()` to the actual length used.
     * On usage of the complete array the call should be repeated with
     * a larger array, not done (640kB and 16 interfaces shall be
     * enough, for everybody!)
     */
    const int n = ifc.ifc_len / sizeof(struct ifreq);

    for (int i = 0; i < n; ++i) {
        /* there are interfaces with are incapable of broadcast
         * on Linux, `lo` has no broadcast address, but this function returns `>=0` */
        if (ioctl(net_socket_to_native(sock), SIOCGIFBRDADDR, &i_faces[i]) < 0) {
            continue;
        }

        /* moot check: only AF_INET returned (backwards compat.) */
        if (i_faces[i].ifr_broadaddr.sa_family != AF_INET) {
            continue;
        }

        const struct sockaddr_in *broadaddr4 = (const struct sockaddr_in *)(void *)&i_faces[i].ifr_broadaddr;

        if (broadcast->count >= MAX_INTERFACES) {
            break;
        }

        IP *ip = &broadcast->ips[broadcast->count];
        ip->family = net_family_ipv4();
        ip->ip.v4.uint32 = broadaddr4->sin_addr.s_addr;

        // if no broadcast address
        if (ip->ip.v4.uint32 == 0) {
            if (ioctl(net_socket_to_native(sock), SIOCGIFADDR, &i_faces[i]) < 0) {
                continue;
            }

            const struct sockaddr_in *addr4 = (const struct sockaddr_in *)(void *)&i_faces[i].ifr_addr;


            IP4 ip4_staging;
            ip4_staging.uint32 = addr4->sin_addr.s_addr;

            if (ip4_is_local(&ip4_staging)) {
                // this is 127.x.x.x
                ip->ip.v4.uint32 = ip4_staging.uint32;
            } else {
                // give up.
                continue;
            }
        }

        ++broadcast->count;
    }

    kill_sock(ns, sock);

    return broadcast;
}

#else // TODO(irungentoo): Other platforms?

static Broadcast_Info *fetch_broadcast_info(const Memory *_Nonnull mem, const Network *_Nonnull ns)
{
    Broadcast_Info *broadcast = (Broadcast_Info *)mem_alloc(mem, sizeof(Broadcast_Info));

    if (broadcast == nullptr) {
        return nullptr;
    }

    broadcast->mem = mem;

    return broadcast;
}

#endif /* platforms */

/** @brief Send packet to all IPv4 broadcast addresses
 *
 * @retval true if sent to at least one broadcast target.
 * @retval false on failure to find any valid broadcast target.
 */
static bool send_broadcasts(const Networking_Core *_Nonnull net, const Broadcast_Info *_Nonnull broadcast, uint16_t port, const uint8_t *_Nonnull data, uint16_t length)
{
    if (broadcast->count == 0) {
        return false;
    }

    for (uint32_t i = 0; i < broadcast->count; ++i) {
        IP_Port ip_port;
        ip_port.ip = broadcast->ips[i];
        ip_port.port = port;
        sendpacket(net, &ip_port, data, length);
    }

    return true;
}

/** Return the broadcast ip. */
static IP broadcast_ip(Family family_socket, Family family_broadcast)
{
    IP ip;
    ip_reset(&ip);

    if (net_family_is_ipv6(family_socket)) {
        if (net_family_is_ipv6(family_broadcast)) {
            ip.family = net_family_ipv6();
            /* `FF02::1` is - according to RFC 4291 - multicast all-nodes link-local */
            /* `FE80::*:` MUST be exact, for that we would need to look over all
             * interfaces and check in which status they are */
            ip.ip.v6.uint8[0] = 0xFF;
            ip.ip.v6.uint8[1] = 0x02;
            ip.ip.v6.uint8[15] = 0x01;
        } else if (net_family_is_ipv4(family_broadcast)) {
            ip.family = net_family_ipv6();
            ip.ip.v6 = get_ip6_broadcast();
        }
    } else if (net_family_is_ipv4(family_socket) && net_family_is_ipv4(family_broadcast)) {
        ip.family = net_family_ipv4();
        ip.ip.v4 = get_ip4_broadcast();
    }

    return ip;
}

static bool ip4_is_local(const IP4 *_Nonnull ip4)
{
    /* Loopback. */
    return ip4->uint8[0] == 127;
}

/**
 * Is IP a local ip or not.
 */
bool ip_is_local(const IP *ip)
{
    if (net_family_is_ipv4(ip->family)) {
        return ip4_is_local(&ip->ip.v4);
    }

    /* embedded IPv4-in-IPv6 */
    if (ipv6_ipv4_in_v6(&ip->ip.v6)) {
        IP4 ip4;
        ip4.uint32 = ip->ip.v6.uint32[3];
        return ip4_is_local(&ip4);
    }

    /* localhost in IPv6 (::1) */
    return ip->ip.v6.uint64[0] == 0 && ip->ip.v6.uint32[2] == 0 && ip->ip.v6.uint32[3] == net_htonl(1);
}

static bool ip4_is_lan(const IP4 *_Nonnull ip4)
{
    /* 10.0.0.0 to 10.255.255.255 range. */
    if (ip4->uint8[0] == 10) {
        return true;
    }

    /* 172.16.0.0 to 172.31.255.255 range. */
    if (ip4->uint8[0] == 172 && ip4->uint8[1] >= 16 && ip4->uint8[1] <= 31) {
        return true;
    }

    /* 192.168.0.0 to 192.168.255.255 range. */
    if (ip4->uint8[0] == 192 && ip4->uint8[1] == 168) {
        return true;
    }

    /* 169.254.1.0 to 169.254.254.255 range. */
    if (ip4->uint8[0] == 169 && ip4->uint8[1] == 254 && ip4->uint8[2] != 0
            && ip4->uint8[2] != 255) {
        return true;
    }

    /* RFC 6598: 100.64.0.0 to 100.127.255.255 (100.64.0.0/10)
     * (shared address space to stack another layer of NAT) */
    return (ip4->uint8[0] == 100) && ((ip4->uint8[1] & 0xC0) == 0x40);
}

bool ip_is_lan(const IP *ip)
{
    if (ip_is_local(ip)) {
        return true;
    }

    if (net_family_is_ipv4(ip->family)) {
        return ip4_is_lan(&ip->ip.v4);
    }

    if (net_family_is_ipv6(ip->family)) {
        /* autogenerated for each interface: `FE80::*` (up to `FEBF::*`)
         * `FF02::1` is - according to RFC 4291 - multicast all-nodes link-local */
        if (((ip->ip.v6.uint8[0] == 0xFF) && (ip->ip.v6.uint8[1] < 3) && (ip->ip.v6.uint8[15] == 1)) ||
                ((ip->ip.v6.uint8[0] == 0xFE) && ((ip->ip.v6.uint8[1] & 0xC0) == 0x80))) {
            return true;
        }

        /* embedded IPv4-in-IPv6 */
        if (ipv6_ipv4_in_v6(&ip->ip.v6)) {
            IP4 ip4;
            ip4.uint32 = ip->ip.v6.uint32[3];
            return ip4_is_lan(&ip4);
        }
    }

    return false;
}

bool lan_discovery_send(const Networking_Core *net, const Broadcast_Info *broadcast, const uint8_t *dht_pk,
                        uint16_t port)
{
    if (broadcast == nullptr) {
        return false;
    }

    uint8_t data[CRYPTO_PUBLIC_KEY_SIZE + 1];
    data[0] = NET_PACKET_LAN_DISCOVERY;
    pk_copy(data + 1, dht_pk);

    send_broadcasts(net, broadcast, port, data, 1 + CRYPTO_PUBLIC_KEY_SIZE);

    bool res = false;
    IP_Port ip_port;
    ip_port.port = port;

    /* IPv6 multicast */
    if (net_family_is_ipv6(net_family(net))) {
        ip_port.ip = broadcast_ip(net_family_ipv6(), net_family_ipv6());

        if (ip_isset(&ip_port.ip) && sendpacket(net, &ip_port, data, 1 + CRYPTO_PUBLIC_KEY_SIZE) > 0) {
            res = true;
        }
    }

    /* IPv4 broadcast (has to be IPv4-in-IPv6 mapping if socket is IPv6 */
    ip_port.ip = broadcast_ip(net_family(net), net_family_ipv4());

    if (ip_isset(&ip_port.ip) && sendpacket(net, &ip_port, data, 1 + CRYPTO_PUBLIC_KEY_SIZE) > 0) {
        res = true;
    }

    return res;
}

Broadcast_Info *lan_discovery_init(const Memory *mem, const Network *ns)
{
    return fetch_broadcast_info(mem, ns);
}

void lan_discovery_kill(Broadcast_Info *broadcast)
{
    if (broadcast == nullptr) {
        return;
    }

    mem_delete(broadcast->mem, broadcast);
}
