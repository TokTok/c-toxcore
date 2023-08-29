#ifndef C_TOXCORE_TOXCORE_NETWORK_TEST_UTIL_H
#define C_TOXCORE_TOXCORE_NETWORK_TEST_UTIL_H

#include <iosfwd>

#include "crypto_core.h"
#include "network.h"
#include "os_network.h"
#include "test_util.hh"
#include "tox_network_impl.h"

struct Network_Class {
    static Tox_Network_Funcs const vtable;
    Tox_Network const self;

    operator Tox_Network const *() const { return &self; }

    Network_Class(Network_Class const &) = default;
    Network_Class()
        : self{&vtable, this}
    {
    }

    virtual ~Network_Class();
    virtual tox_network_close_cb close = 0;
    virtual tox_network_accept_cb accept = 0;
    virtual tox_network_bind_cb bind = 0;
    virtual tox_network_listen_cb listen = 0;
    virtual tox_network_recvbuf_cb recvbuf = 0;
    virtual tox_network_recv_cb recv = 0;
    virtual tox_network_recvfrom_cb recvfrom = 0;
    virtual tox_network_send_cb send = 0;
    virtual tox_network_sendto_cb sendto = 0;
    virtual tox_network_socket_cb socket = 0;
    virtual tox_network_socket_nonblock_cb socket_nonblock = 0;
    virtual tox_network_getsockopt_cb getsockopt = 0;
    virtual tox_network_setsockopt_cb setsockopt = 0;
    virtual tox_network_getaddrinfo_cb getaddrinfo = 0;
    virtual tox_network_freeaddrinfo_cb freeaddrinfo = 0;
};

/**
 * Base test Network class that just forwards to os_network. Can be
 * subclassed to override individual (or all) functions.
 */
class Test_Network : public Network_Class {
    const Tox_Network *net = REQUIRE_NOT_NULL(os_network());

    int close(void *obj, Socket sock) override;
    Socket accept(void *obj, Socket sock) override;
    int bind(void *obj, Socket sock, const Network_Addr *addr) override;
    int listen(void *obj, Socket sock, int backlog) override;
    int recvbuf(void *obj, Socket sock) override;
    int recv(void *obj, Socket sock, uint8_t *buf, size_t len) override;
    int recvfrom(void *obj, Socket sock, uint8_t *buf, size_t len, Network_Addr *addr) override;
    int send(void *obj, Socket sock, const uint8_t *buf, size_t len) override;
    int sendto(
        void *obj, Socket sock, const uint8_t *buf, size_t len, const Network_Addr *addr) override;
    Socket socket(void *obj, int domain, int type, int proto) override;
    int socket_nonblock(void *obj, Socket sock, bool nonblock) override;
    int getsockopt(
        void *obj, Socket sock, int level, int optname, void *optval, size_t *optlen) override;
    int setsockopt(
        void *obj, Socket sock, int level, int optname, const void *optval, size_t optlen) override;
    int getaddrinfo(void *obj, int family, Network_Addr **addrs) override;
    int freeaddrinfo(void *obj, Network_Addr *addrs) override;
};

template <>
struct Deleter<Networking_Core> : Function_Deleter<Networking_Core, kill_networking> { };

IP_Port random_ip_port(const Random *rng);

class increasing_ip_port {
    uint8_t start_;
    const Random *rng_;

public:
    explicit increasing_ip_port(uint8_t start, const Random *rng)
        : start_(start)
        , rng_(rng)
    {
    }

    IP_Port operator()();
};

bool operator==(Family const &a, Family const &b);

bool operator==(IP4 const &a, IP4 const &b);
bool operator==(IP6 const &a, IP6 const &b);
bool operator==(IP const &a, IP const &b);
bool operator==(IP_Port const &a, IP_Port const &b);

std::ostream &operator<<(std::ostream &out, IP const &v);
std::ostream &operator<<(std::ostream &out, IP_Port const &v);

#endif  // C_TOXCORE_TOXCORE_NETWORK_TEST_UTIL_H
