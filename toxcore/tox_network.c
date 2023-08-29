/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2022-2023 The TokTok team.
 */
#include "tox_network.h"

#include "ccompat.h"
#include "tox_network_impl.h"

Tox_Network *tox_network_new(const Tox_Network_Funcs *funcs, void *user_data, const Tox_Memory *mem)
{
    Tox_Network *ns = (Tox_Network *)tox_memory_alloc(mem, sizeof(Tox_Network));

    if (ns == nullptr) {
        return nullptr;
    }

    ns->funcs = funcs;
    ns->user_data = user_data;

    ns->mem = mem;

    return ns;
}

void tox_network_free(Tox_Network *ns)
{
    if (ns == nullptr || ns->mem == nullptr) {
        return;
    }
    tox_memory_dealloc(ns->mem, ns);
}

int tox_network_close(const Tox_Network *ns, int sock)
{
    return ns->funcs->close_callback(ns->user_data, sock);
}

int tox_network_accept(const Tox_Network *ns, int sock)
{
    return ns->funcs->accept_callback(ns->user_data, sock);
}

int tox_network_bind(const Tox_Network *ns, int sock, const Network_Addr *addr)
{
    return ns->funcs->bind_callback(ns->user_data, sock, addr);
}

int tox_network_listen(const Tox_Network *ns, int sock, int backlog)
{
    return ns->funcs->listen_callback(ns->user_data, sock, backlog);
}

int tox_network_recvbuf(const Tox_Network *ns, int sock)
{
    return ns->funcs->recvbuf_callback(ns->user_data, sock);
}

int tox_network_recv(const Tox_Network *ns, int sock, uint8_t *buf, size_t len)
{
    return ns->funcs->recv_callback(ns->user_data, sock, buf, len);
}

int tox_network_recvfrom(const Tox_Network *ns, int sock, uint8_t *buf, size_t len, Network_Addr *addr)
{
    return ns->funcs->recvfrom_callback(ns->user_data, sock, buf, len, addr);
}

int tox_network_send(const Tox_Network *ns, int sock, const uint8_t *buf, size_t len)
{
    return ns->funcs->send_callback(ns->user_data, sock, buf, len);
}

int tox_network_sendto(const Tox_Network *ns, int sock, const uint8_t *buf, size_t len, const Network_Addr *addr)
{
    return ns->funcs->sendto_callback(ns->user_data, sock, buf, len, addr);
}

int tox_network_socket(const Tox_Network *ns, int domain, int type, int proto)
{
    return ns->funcs->socket_callback(ns->user_data, domain, type, proto);
}

int tox_network_socket_nonblock(const Tox_Network *ns, int sock, bool nonblock)
{
    return ns->funcs->socket_nonblock_callback(ns->user_data, sock, nonblock);
}

int tox_network_getsockopt(const Tox_Network *ns, int sock, int level, int optname, void *optval, size_t *optlen)
{
    return ns->funcs->getsockopt_callback(ns->user_data, sock, level, optname, optval, optlen);
}

int tox_network_setsockopt(const Tox_Network *ns, int sock, int level, int optname, const void *optval, size_t optlen)
{
    return ns->funcs->setsockopt_callback(ns->user_data, sock, level, optname, optval, optlen);
}

int tox_network_getaddrinfo(const Tox_Network *ns, int family, Network_Addr **addrs)
{
    return ns->funcs->getaddrinfo_callback(ns->user_data, family, addrs);
}

int tox_network_freeaddrinfo(const Tox_Network *ns, Network_Addr *addrs)
{
    return ns->funcs->freeaddrinfo_callback(ns->user_data, addrs);
}
