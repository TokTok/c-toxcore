/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2022-2025 The TokTok team.
 */
#ifdef __APPLE__
#define _DARWIN_C_SOURCE
#endif /* __APPLE__ */

// For Solaris.
#ifdef __sun
#define __EXTENSIONS__ 1
#endif /* __sun */

// For Linux (and some BSDs).
#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 700
#endif /* _XOPEN_SOURCE */

#if defined(_WIN32) && _WIN32_WINNT >= _WIN32_WINNT_WINXP
#undef _WIN32_WINNT
#define _WIN32_WINNT  0x501
#endif /* _WIN32 */

#if !defined(OS_WIN32) && (defined(_WIN32) || defined(__WIN32__) || defined(WIN32))
#define OS_WIN32
#endif /* OS_WIN32 */

#if defined(OS_WIN32) && !defined(WINVER)
// Windows XP
#define WINVER 0x0501
#endif /* OS_WIN32 */

#include "os_network.h"

#ifdef OS_WIN32 // Put win32 includes here
// The mingw32/64 Windows library warns about including winsock2.h after
// windows.h even though with the above it's a valid thing to do. So, to make
// mingw32 headers happy, we include winsock2.h first.
#include <winsock2.h>
// Comment line here to avoid reordering by source code formatters.
#include <windows.h>
#include <ws2tcpip.h>
#endif /* OS_WIN32 */

#if !defined(OS_WIN32)
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#ifdef __sun
#include <stropts.h>
#include <sys/filio.h>
#endif /* __sun */

#else
#ifndef IPV6_V6ONLY
#define IPV6_V6ONLY 27
#endif /* IPV6_V6ONLY */
#endif /* OS_WIN32 */

#include <assert.h>
#include <string.h>  // memcpy

#include "attributes.h"
#include "ccompat.h"
#include "mem.h"
#include "os_network_impl.h"
#include "tox_memory.h"
#include "tox_network.h"
#include "tox_network_impl.h"  // IWYU pragma: keep

// Disable MSG_NOSIGNAL on systems not supporting it, e.g. Windows, FreeBSD
#if !defined(MSG_NOSIGNAL)
#define MSG_NOSIGNAL 0
#endif /* MSG_NOSIGNAL */

non_null()
static int os_close(void *self, Socket sock)
{
#if defined(OS_WIN32)
    return closesocket(net_socket_to_native(sock));
#else  // !OS_WIN32
    return close(net_socket_to_native(sock));
#endif /* OS_WIN32 */
}

struct Network_Addr {
    struct sockaddr_storage addr;
    size_t size;
};

Network_Addr *net_addr_new(const void *data, size_t size, const Tox_Memory *mem)
{
    Network_Addr *addr = (Network_Addr *)tox_memory_malloc(mem, sizeof(Network_Addr));

    if (addr == nullptr) {
        return nullptr;
    }

    if (data != nullptr) {
        net_addr_set(addr, data, size);
    } else {
        addr->size = sizeof(struct sockaddr_storage);
    }

    return addr;
}

void net_addr_free(Network_Addr *addr, const Tox_Memory *mem)
{
    tox_memory_dealloc(mem, addr);
}

void net_addr_set(Network_Addr *addr, const void *data, size_t size)
{
    assert(size <= sizeof(struct sockaddr_storage));
    memcpy(&addr->addr, data, size);
    addr->size = size;
}

void *net_addr_mut_addr(Network_Addr *addr)
{
    return &addr->addr;
}

const void *net_addr_get_addr(const Network_Addr *addr)
{
    return &addr->addr;
}

void net_addr_set_size(Network_Addr *addr, size_t size)
{
    addr->size = size;
}

size_t net_addr_get_size(const Network_Addr *addr)
{
    return addr->size;
}

bool net_addr_is_ipv4(const Network_Addr *addr)
{
    return addr->addr.ss_family == AF_INET;
}

bool net_addr_is_ipv6(const Network_Addr *addr)
{
    return addr->addr.ss_family == AF_INET6;
}

uint16_t net_addr_get_port(const Network_Addr *addr)
{
    const int family = addr->addr.ss_family;
    if (family == AF_INET6) {
        const struct sockaddr_in6 *addr6 = (const struct sockaddr_in6 *)&addr->addr;
        return addr6->sin6_port;
    } else {
        assert(family == AF_INET);
        const struct sockaddr_in *addr4 = (const struct sockaddr_in *)&addr->addr;
        return addr4->sin_port;
    }
}

int net_addr_get_family(const Network_Addr *addr)
{
    return addr->addr.ss_family;
}

const Network_Addr *net_addrs_get_addr(const Network_Addr *addrs, uint32_t index)
{
    return &addrs[index];
}


non_null()
static Socket os_accept(void *self, Socket sock)
{
    return net_socket_from_native(accept(net_socket_to_native(sock), nullptr, nullptr));
}

non_null()
static int os_bind(void *self, Socket sock, const Network_Addr *addr)
{
    return bind(net_socket_to_native(sock), (const struct sockaddr *)net_addr_get_addr(addr), net_addr_get_size(addr));
}

non_null()
static int os_listen(void *self, Socket sock, int backlog)
{
    return listen(net_socket_to_native(sock), backlog);
}

non_null()
static int os_connect(void *self, Socket sock, const Network_Addr *addr)
{
    return connect(net_socket_to_native(sock), (const struct sockaddr *)net_addr_get_addr(addr), net_addr_get_size(addr));
}

non_null()
static int os_recvbuf(void *self, Socket sock)
{
#ifdef OS_WIN32
    u_long count = 0;
    ioctlsocket(net_socket_to_native(sock), FIONREAD, &count);
#else
    int count = 0;
    ioctl(net_socket_to_native(sock), FIONREAD, &count);
#endif /* OS_WIN32 */

    return count;
}

non_null()
static int os_recv(void *self, Socket sock, uint8_t *buf, size_t len)
{
    return recv(net_socket_to_native(sock), (char *)buf, len, MSG_NOSIGNAL);
}

non_null()
static int os_send(void *self, Socket sock, const uint8_t *buf, size_t len)
{
    return send(net_socket_to_native(sock), (const char *)buf, len, MSG_NOSIGNAL);
}

non_null()
static int os_sendto(void *self, Socket sock, const uint8_t *buf, size_t len, const Network_Addr *addr)
{
    return sendto(net_socket_to_native(sock), (const char *)buf, len, 0, (const struct sockaddr *)&addr->addr, addr->size);
}

non_null()
static int os_recvfrom(void *self, Socket sock, uint8_t *buf, size_t len, Network_Addr *addr)
{
    socklen_t size = addr->size;
    const int ret = recvfrom(net_socket_to_native(sock), (char *)buf, len, 0, (struct sockaddr *)&addr->addr, &size);
    addr->size = size;
    return ret;
}

non_null()
static Socket os_socket(void *self, int domain, int type, int proto)
{
    return net_socket_from_native(socket(domain, type, proto));
}

non_null()
static int os_socket_nonblock(void *self, Socket sock, bool nonblock)
{
#ifdef OS_WIN32
    u_long mode = nonblock ? 1 : 0;
    return ioctlsocket(net_socket_to_native(sock), FIONBIO, &mode);
#else
    return fcntl(net_socket_to_native(sock), F_SETFL, O_NONBLOCK, nonblock ? 1 : 0);
#endif /* OS_WIN32 */
}

non_null()
static int os_getsockopt(void *self, Socket sock, int level, int optname, void *optval, size_t *optlen)
{
    char *optval_bytes = (char *)optval;
    socklen_t len = *optlen;
    const int ret = getsockopt(net_socket_to_native(sock), level, optname, optval_bytes, &len);
    *optlen = len;
    return ret;
}

non_null()
static int os_setsockopt(void *self, Socket sock, int level, int optname, const void *optval, size_t optlen)
{
#ifdef EMSCRIPTEN
    return 0;
#else
    const char *optval_bytes = (const char *)optval;
    return setsockopt(net_socket_to_native(sock), level, optname, optval_bytes, optlen);
#endif /* EMSCRIPTEN */
}

// sets and fills an array of addrs for address
// returns the number of entries in addrs
non_null()
static int os_getaddrinfo(void *obj, const Tox_Memory *mem, const char *address, int family, int sock_type, Network_Addr **addrs)
{
    assert(addrs != nullptr);

    struct addrinfo hints = {0};
    hints.ai_family = family;


    // different platforms favour a different field
    // hints.ai_socktype = SOCK_DGRAM; // type of socket Tox uses.
    hints.ai_socktype = sock_type;
    // hints.ai_protocol = protocol;

    struct addrinfo *infos = nullptr;

    const int rc = getaddrinfo(address, nullptr, &hints, &infos);

    // Lookup failed.
    if (rc != 0) {
        // TODO(Green-Sky): log error
        return 0;
    }

    const int32_t max_count = INT32_MAX / sizeof(Network_Addr);

    // we count number of "valid" results
    int result = 0;
    for (struct addrinfo *walker = infos; walker != nullptr && result < max_count; walker = walker->ai_next) {
        if (walker->ai_family == family || family == AF_UNSPEC) {
            ++result;
        }

        // do we need to check socktype/protocol?
    }

    assert(max_count >= result);

    Network_Addr *tmp_addrs = (Network_Addr *)mem_valloc(mem, result, sizeof(Network_Addr));
    if (tmp_addrs == nullptr) {
        freeaddrinfo(infos);
        return 0;
    }

    // now we fill in
    int i = 0;
    for (struct addrinfo *walker = infos; walker != nullptr; walker = walker->ai_next) {
        if (walker->ai_family == family || family == AF_UNSPEC) {
            tmp_addrs[i].size = sizeof(struct sockaddr_storage);
            tmp_addrs[i].addr.ss_family = walker->ai_family;

            // according to spec, storage is supposed to be large enough (and source shows they are)
            // storage is 128 bytes
            assert(walker->ai_addrlen <= tmp_addrs[i].size);

            memcpy(&tmp_addrs[i].addr, walker->ai_addr, walker->ai_addrlen);
            tmp_addrs[i].size = walker->ai_addrlen;

            ++i;
        }
    }

    assert(i == result);

    freeaddrinfo(infos);

    *addrs = tmp_addrs;

    // number of entries in addrs
    return result;
}

non_null()
static int os_freeaddrinfo(void *obj, const Tox_Memory *mem, Network_Addr *addrs)
{
    if (addrs == nullptr) {
        return 0;
    }

    mem_delete(mem, addrs);

    return 0;
}

static const Tox_Network_Funcs os_network_funcs = {
    os_close,
    os_accept,
    os_bind,
    os_listen,
    os_connect,
    os_recvbuf,
    os_recv,
    os_recvfrom,
    os_send,
    os_sendto,
    os_socket,
    os_socket_nonblock,
    os_getsockopt,
    os_setsockopt,
    os_getaddrinfo,
    os_freeaddrinfo,
};
const Tox_Network os_network_obj = {&os_network_funcs};

#if 0
/* TODO(iphydf): Call this from functions that use `os_network()`. */
void os_network_deinit(const Network *ns)
{
#ifdef OS_WIN32
    WSACleanup();
#endif /* OS_WIN32 */
}
#endif /* 0 */

const Tox_Network *os_network(void)
{
#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
    if ((true)) {
        return nullptr;
    }
#endif /* FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION */
#ifdef OS_WIN32
    WSADATA wsaData;

    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != NO_ERROR) {
        return nullptr;
    }
#endif /* OS_WIN32 */
    return &os_network_obj;
}
