#include "fake_network_stack.hh"

#include <cerrno>

namespace tox::test {

static const Network_Funcs kVtable = {
    .close
    = [](void *obj, Socket sock) { return static_cast<FakeNetworkStack *>(obj)->close(sock); },
    .accept
    = [](void *obj, Socket sock) { return static_cast<FakeNetworkStack *>(obj)->accept(sock); },
    .bind
    = [](void *obj, Socket sock,
          const IP_Port *addr) { return static_cast<FakeNetworkStack *>(obj)->bind(sock, addr); },
    .listen
    = [](void *obj, Socket sock,
          int backlog) { return static_cast<FakeNetworkStack *>(obj)->listen(sock, backlog); },
    .connect =
        [](void *obj, Socket sock, const IP_Port *addr) {
            return static_cast<FakeNetworkStack *>(obj)->connect(sock, addr);
        },
    .recvbuf = [](void *obj, Socket sock) { return 0; },
    .recv = [](void *obj, Socket sock, uint8_t *buf,
                size_t len) { return static_cast<FakeNetworkStack *>(obj)->recv(sock, buf, len); },
    .recvfrom =
        [](void *obj, Socket sock, uint8_t *buf, size_t len, IP_Port *addr) {
            return static_cast<FakeNetworkStack *>(obj)->recvfrom(sock, buf, len, addr);
        },
    .send = [](void *obj, Socket sock, const uint8_t *buf,
                size_t len) { return static_cast<FakeNetworkStack *>(obj)->send(sock, buf, len); },
    .sendto =
        [](void *obj, Socket sock, const uint8_t *buf, size_t len, const IP_Port *addr) {
            return static_cast<FakeNetworkStack *>(obj)->sendto(sock, buf, len, addr);
        },
    .socket
    = [](void *obj, int domain, int type,
          int proto) { return static_cast<FakeNetworkStack *>(obj)->socket(domain, type, proto); },
    .socket_nonblock =
        [](void *obj, Socket sock, bool nonblock) {
            return static_cast<FakeNetworkStack *>(obj)->socket_nonblock(sock, nonblock);
        },
    .getsockopt =
        [](void *obj, Socket sock, int level, int optname, void *optval, size_t *optlen) {
            return static_cast<FakeNetworkStack *>(obj)->getsockopt(
                sock, level, optname, optval, optlen);
        },
    .setsockopt =
        [](void *obj, Socket sock, int level, int optname, const void *optval, size_t optlen) {
            return static_cast<FakeNetworkStack *>(obj)->setsockopt(
                sock, level, optname, optval, optlen);
        },
    .getaddrinfo = [](void *obj, const Memory *mem, const char *address, int family, int protocol,
                       IP_Port **addrs) { return 0; },
    .freeaddrinfo = [](void *obj, const Memory *mem, IP_Port *addrs) { return 0; },
};

FakeNetworkStack::FakeNetworkStack(NetworkUniverse &universe)
    : universe_(universe)
{
}

FakeNetworkStack::~FakeNetworkStack() = default;

struct Network FakeNetworkStack::get_c_network() { return Network{&kVtable, this}; }

Socket FakeNetworkStack::socket(int domain, int type, int protocol)
{
    std::lock_guard<std::mutex> lock(mutex_);
    int fd = next_fd_++;

    std::unique_ptr<FakeSocket> sock;
    if (type == SOCK_DGRAM) {
        sock = std::make_unique<FakeUdpSocket>(universe_);
    } else if (type == SOCK_STREAM) {
        sock = std::make_unique<FakeTcpSocket>(universe_);
    } else {
        // Unknown type
        return net_socket_from_native(-1);
    }

    sockets_[fd] = std::move(sock);
    return net_socket_from_native(fd);
}

FakeSocket *FakeNetworkStack::get_sock(Socket sock)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = sockets_.find(net_socket_to_native(sock));
    if (it != sockets_.end()) {
        return it->second.get();
    }
    return nullptr;
}

int FakeNetworkStack::close(Socket sock)
{
    std::lock_guard<std::mutex> lock(mutex_);
    int fd = net_socket_to_native(sock);
    auto it = sockets_.find(fd);
    if (it == sockets_.end()) {
        errno = EBADF;
        return -1;
    }
    it->second->close();
    sockets_.erase(it);
    return 0;
}

// Delegate all others
int FakeNetworkStack::bind(Socket sock, const IP_Port *addr)
{
    if (auto *s = get_sock(sock))
        return s->bind(addr);
    errno = EBADF;
    return -1;
}

int FakeNetworkStack::connect(Socket sock, const IP_Port *addr)
{
    if (auto *s = get_sock(sock))
        return s->connect(addr);
    errno = EBADF;
    return -1;
}

int FakeNetworkStack::listen(Socket sock, int backlog)
{
    if (auto *s = get_sock(sock))
        return s->listen(backlog);
    errno = EBADF;
    return -1;
}

Socket FakeNetworkStack::accept(Socket sock)
{
    // This requires creating a new FD
    IP_Port addr;
    std::unique_ptr<FakeSocket> new_sock_obj;

    {
        auto *s = get_sock(sock);
        if (!s) {
            errno = EBADF;
            return net_socket_from_native(-1);
        }
        new_sock_obj = s->accept(&addr);
    }

    if (!new_sock_obj) {
        // errno set by accept
        return net_socket_from_native(-1);
    }

    std::lock_guard<std::mutex> lock(mutex_);
    int fd = next_fd_++;
    sockets_[fd] = std::move(new_sock_obj);
    return net_socket_from_native(fd);
}

int FakeNetworkStack::send(Socket sock, const uint8_t *buf, size_t len)
{
    if (auto *s = get_sock(sock))
        return s->send(buf, len);
    errno = EBADF;
    return -1;
}

int FakeNetworkStack::recv(Socket sock, uint8_t *buf, size_t len)
{
    if (auto *s = get_sock(sock))
        return s->recv(buf, len);
    errno = EBADF;
    return -1;
}

int FakeNetworkStack::sendto(Socket sock, const uint8_t *buf, size_t len, const IP_Port *addr)
{
    if (auto *s = get_sock(sock))
        return s->sendto(buf, len, addr);
    errno = EBADF;
    return -1;
}

int FakeNetworkStack::recvfrom(Socket sock, uint8_t *buf, size_t len, IP_Port *addr)
{
    if (auto *s = get_sock(sock))
        return s->recvfrom(buf, len, addr);
    errno = EBADF;
    return -1;
}

int FakeNetworkStack::socket_nonblock(Socket sock, bool nonblock)
{
    if (auto *s = get_sock(sock))
        return s->socket_nonblock(nonblock);
    errno = EBADF;
    return -1;
}

int FakeNetworkStack::getsockopt(Socket sock, int level, int optname, void *optval, size_t *optlen)
{
    if (auto *s = get_sock(sock))
        return s->getsockopt(level, optname, optval, optlen);
    errno = EBADF;
    return -1;
}

int FakeNetworkStack::setsockopt(
    Socket sock, int level, int optname, const void *optval, size_t optlen)
{
    if (auto *s = get_sock(sock))
        return s->setsockopt(level, optname, optval, optlen);
    errno = EBADF;
    return -1;
}

FakeUdpSocket *FakeNetworkStack::get_udp_socket(Socket sock)
{
    if (auto *s = get_sock(sock)) {
        if (s->type() == SOCK_DGRAM) {
            return static_cast<FakeUdpSocket *>(s);
        }
    }
    return nullptr;
}

std::vector<FakeUdpSocket *> FakeNetworkStack::get_bound_udp_sockets()
{
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<FakeUdpSocket *> result;
    for (const auto &pair : sockets_) {
        FakeSocket *s = pair.second.get();
        if (s->type() == SOCK_DGRAM && s->local_port() != 0) {
            result.push_back(static_cast<FakeUdpSocket *>(s));
        }
    }
    return result;
}

}  // namespace tox::test
