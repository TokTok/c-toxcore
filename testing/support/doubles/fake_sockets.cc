#include "fake_sockets.hh"

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <iostream>

#include "network_universe.hh"

namespace tox::test {

// --- FakeSocket ---

FakeSocket::FakeSocket(NetworkUniverse &universe, int type)
    : universe_(universe)
    , type_(type)
{
    ip_init(&ip_, false);
    ip_.ip.v4.uint32 = net_htonl(0x7F000001);
}

FakeSocket::~FakeSocket() = default;

int FakeSocket::close()
{
    // Override in subclasses to unbind
    return 0;
}

int FakeSocket::getsockopt(int level, int optname, void *optval, size_t *optlen) { return 0; }
int FakeSocket::setsockopt(int level, int optname, const void *optval, size_t optlen) { return 0; }
int FakeSocket::socket_nonblock(bool nonblock)
{
    nonblocking_ = nonblock;
    return 0;
}

// --- FakeUdpSocket ---

FakeUdpSocket::FakeUdpSocket(NetworkUniverse &universe)
    : FakeSocket(universe, SOCK_DGRAM)
{
}

FakeUdpSocket::~FakeUdpSocket() { close_impl(); }

int FakeUdpSocket::close()
{
    std::lock_guard<std::mutex> lock(mutex_);
    close_impl();
    return 0;
}

void FakeUdpSocket::close_impl()
{
    if (local_port_ != 0) {
        universe_.unbind_udp(ip_, local_port_);
        local_port_ = 0;
    }
}

int FakeUdpSocket::bind(const IP_Port *addr)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (local_port_ != 0)
        return -1;  // Already bound

    uint16_t port = addr->port;
    if (port == 0) {
        port = universe_.find_free_port(ip_);
    } else {
        port = net_ntohs(port);
    }

    if (universe_.bind_udp(ip_, port, this)) {
        local_port_ = port;
        return 0;
    }
    errno = EADDRINUSE;
    return -1;
}

int FakeUdpSocket::connect(const IP_Port *addr)
{
    // UDP connect just sets default dest.
    // Not strictly needed for toxcore UDP but good for completeness.
    return 0;
}

int FakeUdpSocket::listen(int backlog)
{
    errno = EOPNOTSUPP;
    return -1;
}
std::unique_ptr<FakeSocket> FakeUdpSocket::accept(IP_Port *addr)
{
    errno = EOPNOTSUPP;
    return nullptr;
}
int FakeUdpSocket::send(const uint8_t *buf, size_t len)
{
    errno = EDESTADDRREQ;
    return -1;
}
int FakeUdpSocket::recv(uint8_t *buf, size_t len)
{
    errno = EOPNOTSUPP;
    return -1;
}

int FakeUdpSocket::sendto(const uint8_t *buf, size_t len, const IP_Port *addr)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (local_port_ == 0) {
        // Implicit bind
        uint16_t p = universe_.find_free_port(ip_);
        if (universe_.bind_udp(ip_, p, this)) {
            local_port_ = p;
        } else {
            errno = EADDRINUSE;
            return -1;
        }
    }

    Packet p{};
    // Source
    p.from.ip = ip_;
    p.from.port = net_htons(local_port_);
    p.to = *addr;
    p.data.assign(buf, buf + len);
    p.is_tcp = false;

    universe_.send_packet(p);
    if (universe_.is_verbose()) {
        uint32_t tip4 = net_ntohl(addr->ip.ip.v4.uint32);
        std::cerr << "[FakeUdpSocket] sent " << len << " bytes from port " << local_port_ << " to "
                  << ((tip4 >> 24) & 0xFF) << "." << ((tip4 >> 16) & 0xFF) << "."
                  << ((tip4 >> 8) & 0xFF) << "." << (tip4 & 0xFF) << ":" << net_ntohs(addr->port)
                  << std::endl;
    }
    return len;
}

int FakeUdpSocket::recvfrom(uint8_t *buf, size_t len, IP_Port *addr)
{
    RecvObserver observer_copy;
    std::vector<uint8_t> data_copy;
    IP_Port from_copy;
    size_t copy_len = 0;

    {
        std::lock_guard<std::mutex> lock(mutex_);

        if (recv_queue_.empty() && packet_source_) {
            // NOTE: We call packet_source_ with lock held.
            // Be careful not to call back into socket methods from packet_source_.
            std::vector<uint8_t> data;
            IP_Port from;
            if (packet_source_(data, from)) {
                recv_queue_.push_back({std::move(data), from});
            }
        }

        if (recv_queue_.empty()) {
            errno = EWOULDBLOCK;
            return -1;
        }

        auto &p = recv_queue_.front();
        copy_len = std::min(len, p.data.size());
        std::memcpy(buf, p.data.data(), copy_len);
        *addr = p.from;

        if (recv_observer_) {
            observer_copy = recv_observer_;
            data_copy = p.data;
            from_copy = p.from;
        }

        recv_queue_.pop_front();
    }

    if (observer_copy) {
        observer_copy(data_copy, from_copy);
    }

    if (universe_.is_verbose()) {
        std::cerr << "[FakeUdpSocket] recv " << copy_len << " bytes at port " << local_port_
                  << " from port " << net_ntohs(addr->port) << std::endl;
    }

    return copy_len;
}

void FakeUdpSocket::push_packet(std::vector<uint8_t> data, IP_Port from)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (universe_.is_verbose()) {
        uint32_t fip4 = net_ntohl(from.ip.ip.v4.uint32);
        std::cerr << "[FakeUdpSocket] push " << data.size() << " bytes into queue for "
                  << ((ip_.ip.v4.uint32 >> 24) & 0xFF)
                  << "."  // ip_ is in network order from net_htonl
                  << ((ip_.ip.v4.uint32 >> 16) & 0xFF) << "." << ((ip_.ip.v4.uint32 >> 8) & 0xFF)
                  << "." << (ip_.ip.v4.uint32 & 0xFF) << ":" << local_port_ << " from "
                  << ((fip4 >> 24) & 0xFF) << "." << ((fip4 >> 16) & 0xFF) << "."
                  << ((fip4 >> 8) & 0xFF) << "." << (fip4 & 0xFF) << ":" << net_ntohs(from.port)
                  << std::endl;
    }
    recv_queue_.push_back({std::move(data), from});
}

void FakeUdpSocket::set_packet_source(PacketSource source)
{
    std::lock_guard<std::mutex> lock(mutex_);
    packet_source_ = std::move(source);
}

void FakeUdpSocket::set_recv_observer(RecvObserver observer)
{
    std::lock_guard<std::mutex> lock(mutex_);
    recv_observer_ = std::move(observer);
}

// --- FakeTcpSocket ---

FakeTcpSocket::FakeTcpSocket(NetworkUniverse &universe)
    : FakeSocket(universe, SOCK_STREAM)
    , remote_addr_{}
{
}

FakeTcpSocket::~FakeTcpSocket() { close_impl(); }

int FakeTcpSocket::close()
{
    std::lock_guard<std::mutex> lock(mutex_);
    close_impl();
    return 0;
}

void FakeTcpSocket::close_impl()
{
    if (local_port_ != 0) {
        universe_.unbind_tcp(ip_, local_port_, this);
        local_port_ = 0;
    }
    state_ = CLOSED;
}

int FakeTcpSocket::bind(const IP_Port *addr)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (local_port_ != 0)
        return -1;

    uint16_t port = addr->port;
    if (port == 0) {
        port = universe_.find_free_port(ip_);
    } else {
        port = net_ntohs(port);
    }

    if (universe_.bind_tcp(ip_, port, this)) {
        local_port_ = port;
        return 0;
    }
    errno = EADDRINUSE;
    return -1;
}

int FakeTcpSocket::listen(int backlog)
{
    std::lock_guard<std::mutex> lock(mutex_);
    state_ = LISTEN;
    backlog_ = backlog;
    return 0;
}

int FakeTcpSocket::connect(const IP_Port *addr)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (local_port_ == 0) {
        // Implicit bind
        uint16_t p = universe_.find_free_port(ip_);
        if (universe_.bind_tcp(ip_, p, this)) {
            local_port_ = p;
        } else {
            errno = EADDRINUSE;
            return -1;
        }
    }

    remote_addr_ = *addr;
    state_ = SYN_SENT;

    Packet p{};
    p.from.ip = ip_;
    p.from.port = net_htons(local_port_);
    p.to = *addr;
    p.is_tcp = true;
    p.tcp_flags = 0x02;  // SYN
    p.seq = next_seq_;

    universe_.send_packet(p);

    // Non-blocking connect not fully simulated (we return 0 but state is SYN_SENT).
    // Real connect() blocks or returns EINPROGRESS.
    // For simplicity, we assume the test will pump events until connected.
    errno = EINPROGRESS;
    return -1;
}

std::unique_ptr<FakeSocket> FakeTcpSocket::accept(IP_Port *addr)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (state_ != LISTEN) {
        errno = EINVAL;
        return nullptr;
    }

    if (pending_connections_.empty()) {
        errno = EWOULDBLOCK;
        return nullptr;
    }

    auto client = std::move(pending_connections_.front());
    pending_connections_.pop_front();

    if (addr) {
        *addr = client->remote_addr();
    }
    return client;
}

int FakeTcpSocket::send(const uint8_t *buf, size_t len)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (state_ != ESTABLISHED) {
        errno = ENOTCONN;
        return -1;
    }

    // Wrap as TCP packet
    Packet p{};
    // Source
    p.from.ip = ip_;
    p.from.port = net_htons(local_port_);
    p.to = remote_addr_;
    p.data.assign(buf, buf + len);
    p.is_tcp = true;
    p.tcp_flags = 0x10;  // ACK (Data packets usually have ACK)
    p.seq = next_seq_;
    p.ack = last_ack_;

    next_seq_ += len;
    universe_.send_packet(p);
    return len;
}

int FakeTcpSocket::recv(uint8_t *buf, size_t len)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (recv_buffer_.empty()) {
        if (state_ == CLOSED || state_ == CLOSE_WAIT)
            return 0;  // EOF
        errno = EWOULDBLOCK;
        return -1;
    }

    size_t actual = std::min(len, recv_buffer_.size());
    for (size_t i = 0; i < actual; ++i) {
        buf[i] = recv_buffer_.front();
        recv_buffer_.pop_front();
    }
    return actual;
}

size_t FakeTcpSocket::recv_buffer_size()
{
    std::lock_guard<std::mutex> lock(mutex_);
    return recv_buffer_.size();
}

int FakeTcpSocket::sendto(const uint8_t *buf, size_t len, const IP_Port *addr)
{
    errno = EOPNOTSUPP;
    return -1;
}
int FakeTcpSocket::recvfrom(uint8_t *buf, size_t len, IP_Port *addr)
{
    errno = EOPNOTSUPP;
    return -1;
}

void FakeTcpSocket::handle_packet(const Packet &p)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (universe_.is_verbose()) {
        std::cerr << "Handle Packet: Port " << local_port_ << " Flags "
                  << static_cast<int>(p.tcp_flags) << " State " << state_ << std::endl;
    }

    if (state_ == LISTEN) {
        if (p.tcp_flags & 0x02) {  // SYN
            // Create new socket for connection
            auto new_sock = std::make_unique<FakeTcpSocket>(universe_);
            // Bind to ephemeral? No, it's accepted on the same port but distinct 4-tuple.
            // In our simplified model, the new socket is not bound to the global map
            // until accepted? Or effectively bound to the 4-tuple.
            // For now, let's just create it and queue it.

            new_sock->state_ = SYN_RECEIVED;
            new_sock->remote_addr_ = p.from;
            new_sock->local_port_ = local_port_;
            new_sock->last_ack_ = p.seq + 1;
            new_sock->next_seq_ = 1000;  // Random ISN

            universe_.bind_tcp(ip_, local_port_, new_sock.get());

            // Send SYN-ACK
            Packet resp{};
            resp.from = p.to;
            resp.to = p.from;
            resp.is_tcp = true;
            resp.tcp_flags = 0x12;  // SYN | ACK
            resp.seq = new_sock->next_seq_++;
            resp.ack = new_sock->last_ack_;

            universe_.send_packet(resp);

            // In real TCP, we wait for ACK to move to ESTABLISHED and accept queue.
            // Here we cheat and move to ESTABLISHED immediately or wait for ACK?
            // Let's wait for ACK.
            // But where do we store this half-open socket?
            // For simplicity: auto-transition to ESTABLISHED and queue it.
            new_sock->state_ = ESTABLISHED;
            pending_connections_.push_back(std::move(new_sock));
        }
    } else if (state_ == SYN_SENT) {
        if ((p.tcp_flags & 0x12) == 0x12) {  // SYN | ACK
            state_ = ESTABLISHED;
            last_ack_ = p.seq + 1;
            next_seq_++;  // Consumer SYN

            // Send ACK
            Packet ack{};
            ack.from = p.to;
            ack.to = p.from;
            ack.is_tcp = true;
            ack.tcp_flags = 0x10;  // ACK
            ack.seq = next_seq_;
            ack.ack = last_ack_;
            universe_.send_packet(ack);
        }
    } else if (state_ == ESTABLISHED) {
        if (p.tcp_flags & 0x01) {  // FIN
            state_ = CLOSE_WAIT;
            // Send ACK
            Packet ack{};
            ack.from = p.to;
            ack.to = p.from;
            ack.is_tcp = true;
            ack.tcp_flags = 0x10;  // ACK
            ack.seq = next_seq_;
            ack.ack = p.seq + 1;  // Consume FIN
            universe_.send_packet(ack);
        } else if (!p.data.empty()) {
            recv_buffer_.insert(recv_buffer_.end(), p.data.begin(), p.data.end());
            last_ack_ += p.data.size();
            // Should send ACK?
        }
    }
}

std::unique_ptr<FakeTcpSocket> FakeTcpSocket::create_connected(
    NetworkUniverse &universe, const IP_Port &remote, uint16_t local_port)
{
    auto s = std::make_unique<FakeTcpSocket>(universe);
    s->state_ = ESTABLISHED;
    s->remote_addr_ = remote;
    s->local_port_ = local_port;
    return s;
}

}  // namespace tox::test
