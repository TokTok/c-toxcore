#ifndef C_TOXCORE_TESTING_SUPPORT_NETWORK_H
#define C_TOXCORE_TESTING_SUPPORT_NETWORK_H

#include <cstdint>
#include <vector>

#include "../../../toxcore/network.h"

namespace tox::test {

/**
 * @brief Abstraction over the network subsystem (sockets).
 */
class NetworkSystem {
public:
    virtual ~NetworkSystem();

    virtual Socket socket(int domain, int type, int protocol) = 0;
    virtual int bind(Socket sock, const IP_Port *addr) = 0;
    virtual int close(Socket sock) = 0;
    virtual int sendto(Socket sock, const uint8_t *buf, size_t len, const IP_Port *addr) = 0;
    virtual int recvfrom(Socket sock, uint8_t *buf, size_t len, IP_Port *addr) = 0;

    // TCP Support
    virtual int listen(Socket sock, int backlog) = 0;
    virtual Socket accept(Socket sock) = 0;
    virtual int connect(Socket sock, const IP_Port *addr) = 0;
    virtual int send(Socket sock, const uint8_t *buf, size_t len) = 0;
    virtual int recv(Socket sock, uint8_t *buf, size_t len) = 0;

    // Auxiliary
    virtual int socket_nonblock(Socket sock, bool nonblock) = 0;
    virtual int getsockopt(Socket sock, int level, int optname, void *optval, size_t *optlen) = 0;
    virtual int setsockopt(Socket sock, int level, int optname, const void *optval, size_t optlen)
        = 0;
};

}  // namespace tox::test

#endif  // C_TOXCORE_TESTING_SUPPORT_NETWORK_H
