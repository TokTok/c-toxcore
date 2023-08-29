#ifdef __APPLE__
#define _DARWIN_C_SOURCE
#endif

// For Solaris.
#ifdef __sun
#define __EXTENSIONS__ 1
#endif

// For Linux (and some BSDs).
#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 700
#endif

#if defined(_WIN32) && _WIN32_WINNT >= _WIN32_WINNT_WINXP
#undef _WIN32_WINNT
#define _WIN32_WINNT  0x501
#endif

#if !defined(OS_WIN32) && (defined(_WIN32) || defined(__WIN32__) || defined(WIN32))
#define OS_WIN32
#endif

#if defined(OS_WIN32) && !defined(WINVER)
// Windows XP
#define WINVER 0x0501
#endif

#include "os_network.h"

#include "ccompat.h"
#include "os_network_impl.h"
#include "tox_network_impl.h"

non_null()
static int os_close(void *self, int sock)
{
#if defined(OS_WIN32)
    return closesocket(sock);
#else  // !OS_WIN32
    return close(sock);
#endif
}

non_null()
static int os_accept(void *self, int sock)
{
    return accept(sock, nullptr, nullptr);
}

non_null()
static int os_bind(void *self, int sock, const Network_Addr *addr)
{
    return bind(sock, (const struct sockaddr *)&addr->addr, addr->size);
}

non_null()
static int os_listen(void *self, int sock, int backlog)
{
    return listen(sock, backlog);
}

non_null()
static int os_recvbuf(void *self, int sock)
{
#ifdef OS_WIN32
    u_long count = 0;
    ioctlsocket(sock, FIONREAD, &count);
#else
    int count = 0;
    ioctl(sock, FIONREAD, &count);
#endif

    return count;
}

non_null()
static int os_recv(void *self, int sock, uint8_t *buf, size_t len)
{
    return recv(sock, (char *)buf, len, MSG_NOSIGNAL);
}

non_null()
static int os_send(void *self, int sock, const uint8_t *buf, size_t len)
{
    return send(sock, (const char *)buf, len, MSG_NOSIGNAL);
}

non_null()
static int os_sendto(void *self, int sock, const uint8_t *buf, size_t len, const Network_Addr *addr) {
    return sendto(sock, (const char *)buf, len, 0, (const struct sockaddr *)&addr->addr, addr->size);
}

non_null()
static int os_recvfrom(void *self, int sock, uint8_t *buf, size_t len, Network_Addr *addr) {
    socklen_t size = addr->size;
    const int ret = recvfrom(sock, (char *)buf, len, 0, (struct sockaddr *)&addr->addr, &size);
    addr->size = size;
    return ret;
}

non_null()
static int os_socket(void *self, int domain, int type, int proto)
{
    return (int)socket(domain, type, proto);
}

non_null()
static int os_socket_nonblock(void *self, int sock, bool nonblock)
{
#ifdef OS_WIN32
    u_long mode = nonblock ? 1 : 0;
    return ioctlsocket(sock, FIONBIO, &mode);
#else
    return fcntl(sock, F_SETFL, O_NONBLOCK, nonblock ? 1 : 0);
#endif /* OS_WIN32 */
}

non_null()
static int os_getsockopt(void *self, int sock, int level, int optname, void *optval, size_t *optlen)
{
    socklen_t len = *optlen;
    const int ret = getsockopt(sock, level, optname, optval, &len);
    *optlen = len;
    return ret;
}

non_null()
static int os_setsockopt(void *self, int sock, int level, int optname, const void *optval, size_t optlen)
{
    return setsockopt(sock, level, optname, optval, optlen);
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
static const Tox_Network os_network_obj = {&os_network_funcs};

const Tox_Network *os_network(void)
{
#ifdef FUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION
    if ((true)) {
        return nullptr;
    }
#endif
#ifdef OS_WIN32
    WSADATA wsaData;

    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != NO_ERROR) {
        return nullptr;
    }
#endif
    return &os_network_obj;
}
