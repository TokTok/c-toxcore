/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2026 The TokTok team.
 * Copyright © 2013 Tox project.
 */

#include "net.h"

int net_socket_to_native(Socket sock)
{
    return (force int)sock.value;
}

Socket net_socket_from_native(int sock)
{
    const Socket res = {(force Socket_Value)sock};
    return res;
}

int ns_close(const Network *ns, Socket sock)
{
    return ns->funcs->close(ns->obj, sock);
}

Socket ns_accept(const Network *ns, Socket sock)
{
    return ns->funcs->accept(ns->obj, sock);
}

int ns_bind(const Network *ns, Socket sock, const IP_Port *addr)
{
    return ns->funcs->bind(ns->obj, sock, addr);
}

int ns_listen(const Network *ns, Socket sock, int backlog)
{
    return ns->funcs->listen(ns->obj, sock, backlog);
}

int ns_connect(const Network *ns, Socket sock, const IP_Port *addr)
{
    return ns->funcs->connect(ns->obj, sock, addr);
}

int ns_recvbuf(const Network *ns, Socket sock)
{
    return ns->funcs->recvbuf(ns->obj, sock);
}

int ns_recv(const Network *ns, Socket sock, uint8_t *buf, size_t len)
{
    return ns->funcs->recv(ns->obj, sock, buf, len);
}

int ns_recvfrom(const Network *ns, Socket sock, uint8_t *buf, size_t len, IP_Port *addr)
{
    return ns->funcs->recvfrom(ns->obj, sock, buf, len, addr);
}

int ns_send(const Network *ns, Socket sock, const uint8_t *buf, size_t len)
{
    return ns->funcs->send(ns->obj, sock, buf, len);
}

int ns_sendto(const Network *ns, Socket sock, const uint8_t *buf, size_t len, const IP_Port *addr)
{
    return ns->funcs->sendto(ns->obj, sock, buf, len, addr);
}

Socket ns_socket(const Network *ns, int domain, int type, int proto)
{
    return ns->funcs->socket(ns->obj, domain, type, proto);
}

int ns_socket_nonblock(const Network *ns, Socket sock, bool nonblock)
{
    return ns->funcs->socket_nonblock(ns->obj, sock, nonblock);
}

int ns_getsockopt(const Network *ns, Socket sock, int level, int optname, void *optval, size_t *optlen)
{
    return ns->funcs->getsockopt(ns->obj, sock, level, optname, optval, optlen);
}

int ns_setsockopt(const Network *ns, Socket sock, int level, int optname, const void *optval, size_t optlen)
{
    return ns->funcs->setsockopt(ns->obj, sock, level, optname, optval, optlen);
}

int ns_getaddrinfo(const Network *ns, const Memory *mem, const char *address, int family, int protocol, IP_Port **addrs)
{
    return ns->funcs->getaddrinfo(ns->obj, mem, address, family, protocol, addrs);
}

int ns_freeaddrinfo(const Network *ns, const Memory *mem, IP_Port *addrs)
{
    return ns->funcs->freeaddrinfo(ns->obj, mem, addrs);
}

size_t net_pack_bool(uint8_t *bytes, bool v)
{
    bytes[0] = v ? 1 : 0;
    return 1;
}

size_t net_pack_u16(uint8_t *bytes, uint16_t v)
{
    bytes[0] = (v >> 8) & 0xff;
    bytes[1] = v & 0xff;
    return sizeof(v);
}

size_t net_pack_u32(uint8_t *bytes, uint32_t v)
{
    uint8_t *p = bytes;
    p += net_pack_u16(p, (v >> 16) & 0xffff);
    p += net_pack_u16(p, v & 0xffff);
    return p - bytes;
}

size_t net_pack_u64(uint8_t *bytes, uint64_t v)
{
    uint8_t *p = bytes;
    p += net_pack_u32(p, (v >> 32) & 0xffffffff);
    p += net_pack_u32(p, v & 0xffffffff);
    return p - bytes;
}

size_t net_unpack_bool(const uint8_t *bytes, bool *v)
{
    *v = bytes[0] != 0;
    return 1;
}

size_t net_unpack_u16(const uint8_t *bytes, uint16_t *v)
{
    const uint8_t hi = bytes[0];
    const uint8_t lo = bytes[1];
    *v = ((uint16_t)hi << 8) | lo;
    return sizeof(*v);
}

size_t net_unpack_u32(const uint8_t *bytes, uint32_t *v)
{
    const uint8_t *p = bytes;
    uint16_t hi;
    uint16_t lo;
    p += net_unpack_u16(p, &hi);
    p += net_unpack_u16(p, &lo);
    *v = ((uint32_t)hi << 16) | lo;
    return p - bytes;
}

size_t net_unpack_u64(const uint8_t *bytes, uint64_t *v)
{
    const uint8_t *p = bytes;
    uint32_t hi;
    uint32_t lo;
    p += net_unpack_u32(p, &hi);
    p += net_unpack_u32(p, &lo);
    *v = ((uint64_t)hi << 32) | lo;
    return p - bytes;
}
