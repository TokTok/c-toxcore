#include "network_test_util.hh"

#include <iomanip>

Tox_Network_Funcs const Network_Class::vtable = {
    Method<tox_network_close_cb, Network_Class>::invoke<&Network_Class::close>,
    Method<tox_network_accept_cb, Network_Class>::invoke<&Network_Class::accept>,
    Method<tox_network_bind_cb, Network_Class>::invoke<&Network_Class::bind>,
    Method<tox_network_listen_cb, Network_Class>::invoke<&Network_Class::listen>,
    Method<tox_network_recvbuf_cb, Network_Class>::invoke<&Network_Class::recvbuf>,
    Method<tox_network_recv_cb, Network_Class>::invoke<&Network_Class::recv>,
    Method<tox_network_recvfrom_cb, Network_Class>::invoke<&Network_Class::recvfrom>,
    Method<tox_network_send_cb, Network_Class>::invoke<&Network_Class::send>,
    Method<tox_network_sendto_cb, Network_Class>::invoke<&Network_Class::sendto>,
    Method<tox_network_socket_cb, Network_Class>::invoke<&Network_Class::socket>,
    Method<tox_network_socket_nonblock_cb, Network_Class>::invoke<&Network_Class::socket_nonblock>,
    Method<tox_network_getsockopt_cb, Network_Class>::invoke<&Network_Class::getsockopt>,
    Method<tox_network_setsockopt_cb, Network_Class>::invoke<&Network_Class::setsockopt>,
    Method<tox_network_getaddrinfo_cb, Network_Class>::invoke<&Network_Class::getaddrinfo>,
    Method<tox_network_freeaddrinfo_cb, Network_Class>::invoke<&Network_Class::freeaddrinfo>,
};

int Test_Network::close(void *obj, int sock) { return net->funcs->close_callback(net->user_data, sock); }
int Test_Network::accept(void *obj, int sock) { return net->funcs->accept_callback(net->user_data, sock); }
int Test_Network::bind(void *obj, int sock, const Network_Addr *addr)
{
    return net->funcs->bind_callback(net->user_data, sock, addr);
}
int Test_Network::listen(void *obj, int sock, int backlog)
{
    return net->funcs->listen_callback(net->user_data, sock, backlog);
}
int Test_Network::recvbuf(void *obj, int sock) { return net->funcs->recvbuf_callback(net->user_data, sock); }
int Test_Network::recv(void *obj, int sock, uint8_t *buf, size_t len)
{
    return net->funcs->recv_callback(net->user_data, sock, buf, len);
}
int Test_Network::recvfrom(void *obj, int sock, uint8_t *buf, size_t len, Network_Addr *addr)
{
    return net->funcs->recvfrom_callback(net->user_data, sock, buf, len, addr);
}
int Test_Network::send(void *obj, int sock, const uint8_t *buf, size_t len)
{
    return net->funcs->send_callback(net->user_data, sock, buf, len);
}
int Test_Network::sendto(
    void *obj, int sock, const uint8_t *buf, size_t len, const Network_Addr *addr)
{
    return net->funcs->sendto_callback(net->user_data, sock, buf, len, addr);
}
int Test_Network::socket(void *obj, int domain, int type, int proto)
{
    return net->funcs->socket_callback(net->user_data, domain, type, proto);
}
int Test_Network::socket_nonblock(void *obj, int sock, bool nonblock)
{
    return net->funcs->socket_nonblock_callback(net->user_data, sock, nonblock);
}
int Test_Network::getsockopt(
    void *obj, int sock, int level, int optname, void *optval, size_t *optlen)
{
    return net->funcs->getsockopt_callback(net->user_data, sock, level, optname, optval, optlen);
}
int Test_Network::setsockopt(
    void *obj, int sock, int level, int optname, const void *optval, size_t optlen)
{
    return net->funcs->setsockopt_callback(net->user_data, sock, level, optname, optval, optlen);
}
int Test_Network::getaddrinfo(void *obj, int family, Network_Addr **addrs)
{
    return net->funcs->getaddrinfo_callback(net->user_data, family, addrs);
}
int Test_Network::freeaddrinfo(void *obj, Network_Addr *addrs)
{
    return net->funcs->freeaddrinfo_callback(net->user_data, addrs);
}

Network_Class::~Network_Class() = default;

IP_Port increasing_ip_port::operator()()
{
    IP_Port ip_port;
    ip_port.ip.family = net_family_ipv4();
    ip_port.ip.ip.v4.uint8[0] = 192;
    ip_port.ip.ip.v4.uint8[1] = 168;
    ip_port.ip.ip.v4.uint8[2] = 0;
    ip_port.ip.ip.v4.uint8[3] = start_;
    ip_port.port = random_u16(rng_);
    ++start_;
    return ip_port;
}

IP_Port random_ip_port(const Random *rng)
{
    IP_Port ip_port;
    ip_port.ip.family = net_family_ipv4();
    ip_port.ip.ip.v4.uint8[0] = 192;
    ip_port.ip.ip.v4.uint8[1] = 168;
    ip_port.ip.ip.v4.uint8[2] = 0;
    ip_port.ip.ip.v4.uint8[3] = random_u08(rng);
    ip_port.port = random_u16(rng);
    return ip_port;
}

bool operator==(Family const &a, Family const &b) { return a.value == b.value; }

bool operator==(IP4 const &a, IP4 const &b) { return a.uint32 == b.uint32; }

bool operator==(IP6 const &a, IP6 const &b)
{
    return a.uint64[0] == b.uint64[0] && a.uint64[1] == b.uint64[1];
}

bool operator==(IP const &a, IP const &b)
{
    if (!(a.family == b.family)) {
        return false;
    }

    if (net_family_is_ipv4(a.family)) {
        return a.ip.v4 == b.ip.v4;
    } else {
        return a.ip.v6 == b.ip.v6;
    }
}

bool operator==(IP_Port const &a, IP_Port const &b) { return a.ip == b.ip && a.port == b.port; }

std::ostream &operator<<(std::ostream &out, IP const &v)
{
    Ip_Ntoa ip_str;
    out << '"' << net_ip_ntoa(&v, &ip_str) << '"';
    return out;
}

std::ostream &operator<<(std::ostream &out, IP_Port const &v)
{
    return out << "IP_Port{\n"
               << "        ip = " << v.ip << ",\n"
               << "        port = " << std::dec << std::setw(0) << v.port << " }";
}
