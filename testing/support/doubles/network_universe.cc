#include "network_universe.hh"

#include <cstring>
#include <iostream>

#include "fake_sockets.hh"

namespace tox::test {

bool NetworkUniverse::IP_Port_Key::operator<(const IP_Port_Key &other) const
{
    if (port != other.port)
        return port < other.port;
    if (ip.family.value != other.ip.family.value)
        return ip.family.value < other.ip.family.value;

    if (net_family_is_ipv4(ip.family)) {
        return ip.ip.v4.uint32 < other.ip.ip.v4.uint32;
    }

    return std::memcmp(&ip.ip.v6, &other.ip.ip.v6, sizeof(ip.ip.v6)) < 0;
}

NetworkUniverse::NetworkUniverse() { }
NetworkUniverse::~NetworkUniverse() { }

bool NetworkUniverse::bind_udp(IP ip, uint16_t port, FakeUdpSocket *socket)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    IP_Port_Key key{ip, port};
    if (udp_bindings_.count(key))
        return false;
    udp_bindings_[key] = socket;
    return true;
}

void NetworkUniverse::unbind_udp(IP ip, uint16_t port)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    udp_bindings_.erase({ip, port});
}

bool NetworkUniverse::bind_tcp(IP ip, uint16_t port, FakeTcpSocket *socket)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    tcp_bindings_.insert({{ip, port}, socket});
    return true;
}

void NetworkUniverse::unbind_tcp(IP ip, uint16_t port, FakeTcpSocket *socket)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    auto range = tcp_bindings_.equal_range({ip, port});
    for (auto it = range.first; it != range.second; ++it) {
        if (it->second == socket) {
            tcp_bindings_.erase(it);
            break;
        }
    }
}

void NetworkUniverse::send_packet(Packet p)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);

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

    event_queue_.push(std::move(p));
}

static bool is_ipv4_mapped(const IP &ip)
{
    if (!net_family_is_ipv6(ip.family))
        return false;
    const uint8_t *b = ip.ip.v6.uint8;
    for (int i = 0; i < 10; ++i)
        if (b[i] != 0)
            return false;
    if (b[10] != 0xFF || b[11] != 0xFF)
        return false;
    return true;
}

static IP extract_ipv4(const IP &ip)
{
    IP ip4;
    ip_init(&ip4, false);
    const uint8_t *b = ip.ip.v6.uint8;
    std::memcpy(ip4.ip.v4.uint8, b + 12, 4);
    return ip4;
}

void NetworkUniverse::process_events(uint64_t current_time_ms)
{
    while (true) {
        Packet p;
        std::vector<FakeTcpSocket *> tcp_targets;
        FakeUdpSocket *udp_target = nullptr;
        bool has_packet = false;

        {
            std::lock_guard<std::recursive_mutex> lock(mutex_);
            if (!event_queue_.empty() && event_queue_.top().delivery_time <= current_time_ms) {
                p = event_queue_.top();
                event_queue_.pop();
                has_packet = true;

                if (p.is_tcp) {
                    auto range = tcp_bindings_.equal_range({p.to.ip, net_ntohs(p.to.port)});
                    for (auto it = range.first; it != range.second; ++it) {
                        tcp_targets.push_back(it->second);
                    }
                    if (tcp_targets.empty() && is_ipv4_mapped(p.to.ip)) {
                        IP ip4 = extract_ipv4(p.to.ip);
                        auto range4 = tcp_bindings_.equal_range({ip4, net_ntohs(p.to.port)});
                        for (auto it = range4.first; it != range4.second; ++it) {
                            tcp_targets.push_back(it->second);
                        }
                    }
                } else {
                    if (udp_bindings_.count({p.to.ip, net_ntohs(p.to.port)})) {
                        udp_target = udp_bindings_[{p.to.ip, net_ntohs(p.to.port)}];
                    } else if (is_ipv4_mapped(p.to.ip)) {
                        IP ip4 = extract_ipv4(p.to.ip);
                        if (udp_bindings_.count({ip4, net_ntohs(p.to.port)})) {
                            udp_target = udp_bindings_[{ip4, net_ntohs(p.to.port)}];
                        }
                    }
                }
            }
        }

        if (!has_packet) {
            break;
        }

        if (p.is_tcp) {
            for (auto *it : tcp_targets) {
                it->handle_packet(p);
            }
        } else {
            if (udp_target) {
                udp_target->push_packet(std::move(p.data), p.from);
            }
        }
    }
}

void NetworkUniverse::set_latency(uint64_t ms) { global_latency_ms_ = ms; }

void NetworkUniverse::set_verbose(bool verbose) { verbose_ = verbose; }

bool NetworkUniverse::is_verbose() const { return verbose_; }

void NetworkUniverse::add_filter(PacketFilter filter)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    filters_.push_back(std::move(filter));
}

void NetworkUniverse::add_observer(PacketSink sink)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    observers_.push_back(std::move(sink));
}

uint16_t NetworkUniverse::find_free_port(IP ip, uint16_t start)
{
    std::lock_guard<std::recursive_mutex> lock(mutex_);
    for (uint16_t port = start; port < 65535; ++port) {
        if (!udp_bindings_.count({ip, port}))
            return port;
    }
    return 0;
}

}  // namespace tox::test
