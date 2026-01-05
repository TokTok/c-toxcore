#include "network_universe.hh"

#include <iostream>

#include "fake_sockets.hh"

namespace tox::test {

NetworkUniverse::NetworkUniverse() { }
NetworkUniverse::~NetworkUniverse() { }

bool NetworkUniverse::bind_udp(uint16_t port, FakeUdpSocket *socket)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (udp_bindings_.count(port))
        return false;
    udp_bindings_[port] = socket;
    return true;
}

void NetworkUniverse::unbind_udp(uint16_t port)
{
    std::lock_guard<std::mutex> lock(mutex_);
    udp_bindings_.erase(port);
}

bool NetworkUniverse::bind_tcp(uint16_t port, FakeTcpSocket *socket)
{
    std::lock_guard<std::mutex> lock(mutex_);
    tcp_bindings_.insert({port, socket});
    return true;
}

void NetworkUniverse::unbind_tcp(uint16_t port, FakeTcpSocket *socket)
{
    std::lock_guard<std::mutex> lock(mutex_);
    auto range = tcp_bindings_.equal_range(port);
    for (auto it = range.first; it != range.second; ++it) {
        if (it->second == socket) {
            tcp_bindings_.erase(it);
            break;
        }
    }
}

void NetworkUniverse::send_packet(Packet p)
{
    // Apply filters
    for (const auto &filter : filters_) {
        if (!filter(p))
            return;
    }

    // Notify observers
    for (const auto &observer : observers_) {
        observer(p);
    }

    p.delivery_time += global_latency_ms_;

    std::lock_guard<std::mutex> lock(mutex_);
    event_queue_.push(std::move(p));
}

void NetworkUniverse::process_events(uint64_t current_time_ms)
{
    while (true) {
        Packet packet;
        bool has_packet = false;

        {
            std::lock_guard<std::mutex> lock(mutex_);
            if (!event_queue_.empty()) {
                const auto &p = event_queue_.top();
                if (p.delivery_time <= current_time_ms) {
                    packet = p;  // Copy
                    event_queue_.pop();
                    has_packet = true;
                }
            }
        }

        if (!has_packet)
            break;

        if (packet.is_tcp) {
            FakeTcpSocket *best_match = nullptr;
            {
                std::lock_guard<std::mutex> lock(mutex_);
                auto range = tcp_bindings_.equal_range(packet.to.port);

                // Route to connected socket if possible
                for (auto it = range.first; it != range.second; ++it) {
                    FakeTcpSocket *sock = it->second;
                    const IP_Port &remote = sock->remote_addr();
                    if (sock->state() != FakeTcpSocket::LISTEN
                        && ipport_equal(&remote, &packet.from)) {
                        best_match = sock;
                        break;
                    }
                }

                // Fallback to listener
                if (!best_match) {
                    for (auto it = range.first; it != range.second; ++it) {
                        if (it->second->state() == FakeTcpSocket::LISTEN) {
                            best_match = it->second;
                            break;
                        }
                    }
                }
            }

            if (best_match) {
                best_match->handle_packet(packet);
            }
        } else {
            FakeUdpSocket *target = nullptr;
            {
                std::lock_guard<std::mutex> lock(mutex_);
                auto it = udp_bindings_.find(packet.to.port);
                if (it != udp_bindings_.end()) {
                    target = it->second;
                }
            }

            if (target) {
                target->push_packet(std::move(packet.data), packet.from);
            }
        }
    }
}

void NetworkUniverse::set_latency(uint64_t ms) { global_latency_ms_ = ms; }

void NetworkUniverse::add_filter(PacketFilter filter) { filters_.push_back(std::move(filter)); }

void NetworkUniverse::add_observer(PacketSink sink) { observers_.push_back(std::move(sink)); }

uint16_t NetworkUniverse::find_free_port(uint16_t start)
{
    std::lock_guard<std::mutex> lock(mutex_);
    for (uint16_t p = start; p < 65535; ++p) {
        if (udp_bindings_.find(p) == udp_bindings_.end()
            && tcp_bindings_.find(p) == tcp_bindings_.end()) {
            return p;
        }
    }
    return 0;
}

}  // namespace tox::test
