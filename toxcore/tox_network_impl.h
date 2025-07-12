/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2022-2025 The TokTok team.
 */

#ifndef C_TOXCORE_TOXCORE_TOX_NETWORK_IMPL_H
#define C_TOXCORE_TOXCORE_TOX_NETWORK_IMPL_H

#include "tox_memory.h"
#include "tox_network.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef int tox_network_close_cb(void *self, Socket sock);
typedef Socket tox_network_accept_cb(void *self, Socket sock);
typedef int tox_network_bind_cb(void *self, Socket sock, const Network_Addr *addr);
typedef int tox_network_listen_cb(void *self, Socket sock, int backlog);
typedef int tox_network_connect_cb(void *self, Socket sock, const Network_Addr *addr);
typedef int tox_network_recvbuf_cb(void *self, Socket sock);
typedef int tox_network_recv_cb(void *self, Socket sock, uint8_t *buf, size_t len);
typedef int tox_network_recvfrom_cb(void *self, Socket sock, uint8_t *buf, size_t len, Network_Addr *addr);
typedef int tox_network_send_cb(void *self, Socket sock, const uint8_t *buf, size_t len);
typedef int tox_network_sendto_cb(void *self, Socket sock, const uint8_t *buf, size_t len, const Network_Addr *addr);
typedef Socket tox_network_socket_cb(void *self, int domain, int type, int proto);
typedef int tox_network_socket_nonblock_cb(void *self, Socket sock, bool nonblock);
typedef int tox_network_getsockopt_cb(void *self, Socket sock, int level, int optname, void *optval, size_t *optlen);
typedef int tox_network_setsockopt_cb(void *self, Socket sock, int level, int optname, const void *optval, size_t optlen);
typedef int tox_network_getaddrinfo_cb(void *obj, const Tox_Memory *mem, const char *address, int family, int protocol, Network_Addr **addrs);
typedef int tox_network_freeaddrinfo_cb(void *obj, const Tox_Memory *mem, Network_Addr *addrs);

/** @brief Functions wrapping POSIX network functions.
 *
 * Refer to POSIX man pages for documentation of what these functions are
 * expected to do when providing alternative Network implementations.
 */
struct Tox_Network_Funcs {
    tox_network_close_cb *close_callback;
    tox_network_accept_cb *accept_callback;
    tox_network_bind_cb *bind_callback;
    tox_network_listen_cb *listen_callback;
    tox_network_connect_cb *connect_callback;
    tox_network_recvbuf_cb *recvbuf_callback;
    tox_network_recv_cb *recv_callback;
    tox_network_recvfrom_cb *recvfrom_callback;
    tox_network_send_cb *send_callback;
    tox_network_sendto_cb *sendto_callback;
    tox_network_socket_cb *socket_callback;
    tox_network_socket_nonblock_cb *socket_nonblock_callback;
    tox_network_getsockopt_cb *getsockopt_callback;
    tox_network_setsockopt_cb *setsockopt_callback;
    tox_network_getaddrinfo_cb *getaddrinfo_callback;
    tox_network_freeaddrinfo_cb *freeaddrinfo_callback;
};

struct Tox_Network {
    const Tox_Network_Funcs *funcs;
    void *user_data;

    const Tox_Memory *mem;
};

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* C_TOXCORE_TOXCORE_TOX_NETWORK_IMPL_H */
