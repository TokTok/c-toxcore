#ifndef C_TOXCORE_TESTING_SUPPORT_DOUBLES_FAKE_SOCKETS_H
#define C_TOXCORE_TESTING_SUPPORT_DOUBLES_FAKE_SOCKETS_H

#include <atomic>
#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <vector>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <winsock2.h>
#else
#include <sys/socket.h>
#endif

#include "../../../toxcore/network.h"

namespace tox::test {

class NetworkUniverse;
struct Packet;

/**
 * @brief Abstract base class for all fake sockets.
 */
class FakeSocket {
public:
    FakeSocket(NetworkUniverse &universe, int type);
    virtual ~FakeSocket();

    virtual int bind(const IP_Port *addr) = 0;
    virtual int connect(const IP_Port *addr) = 0;
    virtual int listen(int backlog) = 0;
    virtual std::unique_ptr<FakeSocket> accept(IP_Port *addr) = 0;

    virtual int send(const uint8_t *buf, size_t len) = 0;
    virtual int recv(uint8_t *buf, size_t len) = 0;

    virtual size_t recv_buffer_size() { return 0; }

    virtual int sendto(const uint8_t *buf, size_t len, const IP_Port *addr) = 0;
    virtual int recvfrom(uint8_t *buf, size_t len, IP_Port *addr) = 0;

    virtual int getsockopt(int level, int optname, void *optval, size_t *optlen);
    virtual int setsockopt(int level, int optname, const void *optval, size_t optlen);
    virtual int socket_nonblock(bool nonblock);

    virtual int close();

    bool is_nonblocking() const { return nonblocking_; }
    int type() const { return type_; }
    uint16_t local_port() const { return local_port_; }
    const IP &ip_address() const { return ip_; }

    void set_ip(const IP &ip) { ip_ = ip; }

protected:
    NetworkUniverse &universe_;
    int type_;
    bool nonblocking_ = false;
    uint16_t local_port_ = 0;
    IP ip_;
    std::mutex mutex_;  // Use regular mutex (recursive_mutex not fully supported in MinGW)
};

/**
 * @brief Implements UDP logic.
 */
class FakeUdpSocket : public FakeSocket {
public:
    explicit FakeUdpSocket(NetworkUniverse &universe);
    ~FakeUdpSocket() override;

    int bind(const IP_Port *addr) override;
    int connect(const IP_Port *addr) override;
    int listen(int backlog) override;
    std::unique_ptr<FakeSocket> accept(IP_Port *addr) override;
    int close() override;

    int send(const uint8_t *buf, size_t len) override;
    int recv(uint8_t *buf, size_t len) override;

    int sendto(const uint8_t *buf, size_t len, const IP_Port *addr) override;
    int recvfrom(uint8_t *buf, size_t len, IP_Port *addr) override;

    // Called by Universe to deliver a packet
    void push_packet(std::vector<uint8_t> data, IP_Port from);

    using PacketSource = std::function<bool(std::vector<uint8_t> &data, IP_Port &from)>;
    void set_packet_source(PacketSource source);

    using RecvObserver = std::function<void(const std::vector<uint8_t> &data, const IP_Port &from)>;
    void set_recv_observer(RecvObserver observer);

private:
    void close_impl();

    struct PendingPacket {
        std::vector<uint8_t> data;
        IP_Port from;
    };
    std::deque<PendingPacket> recv_queue_;
    PacketSource packet_source_;
    RecvObserver recv_observer_;
};

/**
 * @brief Implements TCP logic (Simplified for simulation).
 *
 * Supports:
 * - 3-way handshake simulation (instant or delayed)
 * - Stream buffering
 * - Connection states
 */
class FakeTcpSocket : public FakeSocket {
public:
    enum State { CLOSED, LISTEN, SYN_SENT, SYN_RECEIVED, ESTABLISHED, CLOSE_WAIT };

    explicit FakeTcpSocket(NetworkUniverse &universe);
    ~FakeTcpSocket() override;

    int bind(const IP_Port *addr) override;
    int connect(const IP_Port *addr) override;
    int listen(int backlog) override;
    std::unique_ptr<FakeSocket> accept(IP_Port *addr) override;
    int close() override;

    int send(const uint8_t *buf, size_t len) override;
    int recv(uint8_t *buf, size_t len) override;
    size_t recv_buffer_size() override;

    int sendto(const uint8_t *buf, size_t len, const IP_Port *addr) override;
    int recvfrom(uint8_t *buf, size_t len, IP_Port *addr) override;

    // Internal events
    void handle_packet(const Packet &p);

    State state() const { return state_; }
    const IP_Port &remote_addr() const { return remote_addr_; }

    // Factory for accepting connections
    static std::unique_ptr<FakeTcpSocket> create_connected(
        NetworkUniverse &universe, const IP_Port &remote, uint16_t local_port);

private:
    void close_impl();

    State state_ = CLOSED;
    IP_Port remote_addr_;
    std::deque<uint8_t> recv_buffer_;
    std::deque<std::unique_ptr<FakeTcpSocket>> pending_connections_;
    int backlog_ = 0;

    uint32_t next_seq_ = 0;
    uint32_t last_ack_ = 0;
};

}  // namespace tox::test

#endif  // C_TOXCORE_TESTING_SUPPORT_DOUBLES_FAKE_SOCKETS_H
