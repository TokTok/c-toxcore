/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2022-2023 The TokTok team.
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

#include "ccompat.h"
#include "os_network_impl.h"
#include "tox_attributes.h"
#include "tox_memory.h"
#include "tox_network.h"
#include "tox_network_impl.h"

// Disable MSG_NOSIGNAL on systems not supporting it, e.g. Windows, FreeBSD
#if !defined(MSG_NOSIGNAL)
#define MSG_NOSIGNAL 0
#endif /* MSG_NOSIGNAL */

non_null()
static int os_close(void *self, Socket sock)
{
#if defined(OS_WIN32)
    return closesocket(sock.value);
#else  // !OS_WIN32
    return close(sock.value);
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


non_null()
static Socket os_accept(void *self, Socket sock)
{
    const Socket newsock = {accept(sock.value, nullptr, nullptr)};
    return newsock;
}

non_null()
static int os_bind(void *self, Socket sock, const Network_Addr *addr)
{
    return bind(sock.value, (const struct sockaddr *)net_addr_get_addr(addr), net_addr_get_size(addr));
}

non_null()
static int os_listen(void *self, Socket sock, int backlog)
{
    return listen(sock.value, backlog);
}

non_null()
static int os_recvbuf(void *self, Socket sock)
{
#ifdef OS_WIN32
    u_long count = 0;
    ioctlsocket(sock.value, FIONREAD, &count);
#else
    int count = 0;
    ioctl(sock.value, FIONREAD, &count);
#endif /* OS_WIN32 */

    return count;
}

non_null()
static int os_recv(void *self, Socket sock, uint8_t *buf, size_t len)
{
    return recv(sock.value, (char *)buf, len, MSG_NOSIGNAL);
}

non_null()
static int os_send(void *self, Socket sock, const uint8_t *buf, size_t len)
{
    return send(sock.value, (const char *)buf, len, MSG_NOSIGNAL);
}

non_null()
static int os_sendto(void *self, Socket sock, const uint8_t *buf, size_t len, const Network_Addr *addr)
{
    return sendto(sock.value, (const char *)buf, len, 0, (const struct sockaddr *)&addr->addr, addr->size);
}

non_null()
static int os_recvfrom(void *self, Socket sock, uint8_t *buf, size_t len, Network_Addr *addr)
{
    socklen_t size = addr->size;
    const int ret = recvfrom(sock.value, (char *)buf, len, 0, (struct sockaddr *)&addr->addr, &size);
    addr->size = size;
    return ret;
}

non_null()
static Socket os_socket(void *self, int domain, int type, int proto)
{
    const Socket sock = {socket(domain, type, proto)};
    return sock;
}

non_null()
static int os_socket_nonblock(void *self, Socket sock, bool nonblock)
{
#ifdef OS_WIN32
    u_long mode = nonblock ? 1 : 0;
    return ioctlsocket(sock.value, FIONBIO, &mode);
#else
    return fcntl(sock.value, F_SETFL, O_NONBLOCK, nonblock ? 1 : 0);
#endif /* OS_WIN32 */
}

non_null()
static int os_getsockopt(void *self, Socket sock, int level, int optname, void *optval, size_t *optlen)
{
    char *optval_bytes = (char *)optval;
    socklen_t len = *optlen;
    const int ret = getsockopt(sock.value, level, optname, optval_bytes, &len);
    *optlen = len;
    return ret;
}

non_null()
static int os_setsockopt(void *self, Socket sock, int level, int optname, const void *optval, size_t optlen)
{
    const char *optval_bytes = (const char *)optval;
    return setsockopt(sock.value, level, optname, optval_bytes, optlen);
}

static const Tox_Network_Funcs os_network_funcs = {
    os_close,
    os_accept,
    os_bind,
    os_listen,
    os_recvbuf,
    os_recv,
    os_recvfrom,
    os_send,
    os_sendto,
    os_socket,
    os_socket_nonblock,
    os_getsockopt,
    os_setsockopt,
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