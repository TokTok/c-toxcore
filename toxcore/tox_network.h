/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2022-2025 The TokTok team.
 */

#ifndef C_TOXCORE_TOXCORE_TOX_NETWORK_H
#define C_TOXCORE_TOXCORE_TOX_NETWORK_H

#include <stdbool.h>
#include <stddef.h>  // size_t

#include "tox_attributes.h"
#include "tox_memory.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct Tox_Network_Funcs Tox_Network_Funcs;

typedef struct Tox_Network Tox_Network;

tox_non_null(1, 3) tox_nullable(2)
Tox_Network *tox_network_new(const Tox_Network_Funcs *funcs, void *user_data, const Tox_Memory *mem);

tox_nullable(1)
void tox_network_free(Tox_Network *ns);

/**
 * @brief Wrapper for sockaddr_storage and size.
 */
typedef struct Network_Addr Network_Addr;

typedef tox_bitwise int Socket_Value;
typedef struct Socket {
    Socket_Value value;
} Socket;

int net_socket_to_native(Socket sock);
Socket net_socket_from_native(int sock);

tox_non_null()
int tox_network_close(const Tox_Network *ns, Socket sock);
tox_non_null()
Socket tox_network_accept(const Tox_Network *ns, Socket sock);
tox_non_null()
int tox_network_bind(const Tox_Network *ns, Socket sock, const Network_Addr *addr);
tox_non_null()
int tox_network_listen(const Tox_Network *ns, Socket sock, int backlog);
tox_non_null()
int tox_network_connect(const Tox_Network *ns, Socket sock, const Network_Addr *addr);
tox_non_null()
int tox_network_recvbuf(const Tox_Network *ns, Socket sock);
tox_non_null()
int tox_network_recv(const Tox_Network *ns, Socket sock, uint8_t *buf, size_t len);
tox_non_null()
int tox_network_recvfrom(const Tox_Network *ns, Socket sock, uint8_t *buf, size_t len, Network_Addr *addr);
tox_non_null()
int tox_network_send(const Tox_Network *ns, Socket sock, const uint8_t *buf, size_t len);
tox_non_null()
int tox_network_sendto(const Tox_Network *ns, Socket sock, const uint8_t *buf, size_t len, const Network_Addr *addr);
tox_non_null()
Socket tox_network_socket(const Tox_Network *ns, int domain, int type, int proto);
tox_non_null()
int tox_network_socket_nonblock(const Tox_Network *ns, Socket sock, bool nonblock);
tox_non_null()
int tox_network_getsockopt(const Tox_Network *ns, Socket sock, int level, int optname, void *optval, size_t *optlen);
tox_non_null()
int tox_network_setsockopt(const Tox_Network *ns, Socket sock, int level, int optname, const void *optval, size_t optlen);
tox_non_null()
int tox_network_getaddrinfo(const Tox_Network *ns, const Tox_Memory *mem, const char *address, int family, int protocol, Network_Addr **addrs);
tox_non_null()
int tox_network_freeaddrinfo(const Tox_Network *ns, const Tox_Memory *mem, Network_Addr *addrs);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* C_TOXCORE_TOXCORE_TOX_NETWORK_H */
