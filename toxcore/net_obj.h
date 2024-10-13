/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2024 The TokTok team.
 * Copyright © 2013 Tox project.
 */

/**
 * The networking object.
 */
#ifndef C_TOXCORE_TOXCORE_NET_OBJ_H
#define C_TOXCORE_TOXCORE_NET_OBJ_H

#if defined(_WIN32) && defined(_WIN32_WINNT) && defined(_WIN32_WINNT_WINXP) && _WIN32_WINNT >= _WIN32_WINNT_WINXP
#    undef _WIN32_WINNT
#    define _WIN32_WINNT  0x501
#endif /* defined(_WIN32) && defined(_WIN32_WINNT) && defined(_WIN32_WINNT_WINXP) && _WIN32_WINNT >= _WIN32_WINNT_WINXP */

#if !defined(OS_WIN32) && (defined(_WIN32) || defined(__WIN32__) || defined(WIN32))
#    define OS_WIN32
#endif /* !defined(OS_WIN32) && (defined(_WIN32) || defined(__WIN32__) || defined(WIN32)) */

#if defined(OS_WIN32) && !defined(WINVER)
// Windows XP
#    define WINVER 0x0501
#endif /* defined(OS_WIN32) && !defined(WINVER) */

#include <stdbool.h>    // bool
#include <stddef.h>     // size_t
#include <stdint.h>     // uint*_t

// for sockaddr_storage
#ifdef OS_WIN32
#   include <winsock2.h>
#else
#   include <sys/socket.h>
#endif /* OS_WIN32 */

#include "network.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Wrapper for sockaddr_storage and size.
 */
typedef struct Network_Addr {
    struct sockaddr_storage addr;
    size_t size;
} Network_Addr;

typedef int net_close_cb(void *obj, Socket sock);
typedef Socket net_accept_cb(void *obj, Socket sock);
typedef int net_bind_cb(void *obj, Socket sock, const Network_Addr *addr);
typedef int net_listen_cb(void *obj, Socket sock, int backlog);
typedef int net_connect_cb(void *obj, Socket sock, const Network_Addr *addr);
typedef int net_recvbuf_cb(void *obj, Socket sock);
typedef int net_recv_cb(void *obj, Socket sock, uint8_t *buf, size_t len);
typedef int net_recvfrom_cb(void *obj, Socket sock, uint8_t *buf, size_t len, Network_Addr *addr);
typedef int net_send_cb(void *obj, Socket sock, const uint8_t *buf, size_t len);
typedef int net_sendto_cb(void *obj, Socket sock, const uint8_t *buf, size_t len, const Network_Addr *addr);
typedef Socket net_socket_cb(void *obj, int domain, int type, int proto);
typedef int net_socket_nonblock_cb(void *obj, Socket sock, bool nonblock);
typedef int net_getsockopt_cb(void *obj, Socket sock, int level, int optname, void *optval, size_t *optlen);
typedef int net_setsockopt_cb(void *obj, Socket sock, int level, int optname, const void *optval, size_t optlen);
typedef int net_getaddrinfo_cb(void *obj, const char *address, int family, int protocol, Network_Addr **addrs);
typedef int net_freeaddrinfo_cb(void *obj, Network_Addr *addrs);

/** @brief Functions wrapping POSIX network functions.
 *
 * Refer to POSIX man pages for documentation of what these functions are
 * expected to do when providing alternative Network implementations.
 */
typedef struct Network_Funcs {
    net_close_cb *close;
    net_accept_cb *accept;
    net_bind_cb *bind;
    net_listen_cb *listen;
    net_connect_cb *connect;
    net_recvbuf_cb *recvbuf;
    net_recv_cb *recv;
    net_recvfrom_cb *recvfrom;
    net_send_cb *send;
    net_sendto_cb *sendto;
    net_socket_cb *socket;
    net_socket_nonblock_cb *socket_nonblock;
    net_getsockopt_cb *getsockopt;
    net_setsockopt_cb *setsockopt;
    net_getaddrinfo_cb *getaddrinfo;
    net_freeaddrinfo_cb *freeaddrinfo;
} Network_Funcs;

typedef struct Network {
    const Network_Funcs *funcs;
    void *obj;
} Network;

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* C_TOXCORE_TOXCORE_NET_OBJ_H */

