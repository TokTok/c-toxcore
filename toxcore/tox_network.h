/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2022-2023 The TokTok team.
 */

#ifndef C_TOXCORE_TOXCORE_TOX_NETWORK_H
#define C_TOXCORE_TOXCORE_TOX_NETWORK_H

#include <stdbool.h>
#include <stddef.h>  // size_t

#include "tox_memory.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct Tox_Network_Funcs Tox_Network_Funcs;

typedef struct Tox_Network Tox_Network;

non_null(1, 3) nullable(2)
Tox_Network *tox_network_new(const Tox_Network_Funcs *funcs, void *user_data, const Tox_Memory *mem);

nullable(1)
void tox_network_free(Tox_Network *ns);

/**
 * @brief Wrapper for sockaddr_storage and size.
 */
typedef struct Network_Addr Network_Addr;

non_null()
int tox_network_close(const Tox_Network *ns, int sock);
non_null()
int tox_network_accept(const Tox_Network *ns, int sock);
non_null()
int tox_network_bind(const Tox_Network *ns, int sock, const Network_Addr *addr);
non_null()
int tox_network_listen(const Tox_Network *ns, int sock, int backlog);
non_null()
int tox_network_recvbuf(const Tox_Network *ns, int sock);
non_null()
int tox_network_recv(const Tox_Network *ns, int sock, uint8_t *buf, size_t len);
non_null()
int tox_network_recvfrom(const Tox_Network *ns, int sock, uint8_t *buf, size_t len, Network_Addr *addr);
non_null()
int tox_network_send(const Tox_Network *ns, int sock, const uint8_t *buf, size_t len);
non_null()
int tox_network_sendto(const Tox_Network *ns, int sock, const uint8_t *buf, size_t len, const Network_Addr *addr);
non_null()
int tox_network_socket(const Tox_Network *ns, int domain, int type, int proto);
non_null()
int tox_network_socket_nonblock(const Tox_Network *ns, int sock, bool nonblock);
non_null()
int tox_network_getsockopt(const Tox_Network *ns, int sock, int level, int optname, void *optval, size_t *optlen);
non_null()
int tox_network_setsockopt(const Tox_Network *ns, int sock, int level, int optname, const void *optval, size_t optlen);
non_null()
int tox_network_getaddrinfo(const Tox_Network *ns, int family, Network_Addr **addrs);
non_null()
int tox_network_freeaddrinfo(const Tox_Network *ns, Network_Addr *addrs);

#ifdef __cplusplus
}
#endif

#endif // C_TOXCORE_TOXCORE_TOX_NETWORK_H
