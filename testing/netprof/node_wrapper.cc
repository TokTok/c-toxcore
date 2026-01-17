#include "node_wrapper.hh"

#include <iostream>

#include "../../toxcore/tox_options.h"
#include "../../toxcore/tox_private.h"
#include "constants.hh"

namespace tox::netprof {

static void log_cb(Tox *tox, Tox_Log_Level level, const char *file, uint32_t line, const char *func,
    const char *message, void *user_data)
{
    std::cerr << "[Tox Log] " << file << ":" << line << " (" << func << "): " << message
              << std::endl;
}

NodeWrapper::NodeWrapper(tox::test::Simulation &sim, uint32_t id, std::string name, bool verbose,
    float x, float y, bool tcp_only)
    : id_(id)
    , name_(std::move(name))
    , x_(x)
    , y_(y)
    , node_(std::make_unique<tox::test::SimulatedNode>(sim, id))
{
    // Create Tox with default options + event logging enabled
    Tox_Options *options = tox_options_new(nullptr);
    tox_options_set_ipv6_enabled(options, false);
    tox_options_set_udp_enabled(options, !tcp_only);

    // Set port range
    tox_options_set_start_port(options, kBasePort);
    tox_options_set_end_port(options, 55555);

    if (verbose) {
        tox_options_set_log_callback(options, log_cb);
    }

    runner_ = std::make_unique<tox::test::ToxRunner>(*node_, options);
    tox_options_free(options);

    dht_id_ = runner_->invoke([](Tox *tox) {
        std::vector<uint8_t> dht_id(TOX_PUBLIC_KEY_SIZE);
        tox_self_get_dht_id(tox, dht_id.data());
        return dht_id;
    });
}

NodeWrapper::~NodeWrapper() = default;

std::vector<std::unique_ptr<Tox_Events, tox::test::ToxRunner::ToxEventsDeleter>>
NodeWrapper::poll_events()
{
    return runner_->poll_events();
}

NetProfStats NodeWrapper::get_stats()
{
    return runner_->invoke([](Tox *tox) {
        NetProfStats stats;

        // UDP
        stats.total_udp.count_sent = tox_netprof_get_packet_total_count(
            tox, TOX_NETPROF_PACKET_TYPE_UDP, TOX_NETPROF_DIRECTION_SENT);
        stats.total_udp.count_recv = tox_netprof_get_packet_total_count(
            tox, TOX_NETPROF_PACKET_TYPE_UDP, TOX_NETPROF_DIRECTION_RECV);
        stats.total_udp.bytes_sent = tox_netprof_get_packet_total_bytes(
            tox, TOX_NETPROF_PACKET_TYPE_UDP, TOX_NETPROF_DIRECTION_SENT);
        stats.total_udp.bytes_recv = tox_netprof_get_packet_total_bytes(
            tox, TOX_NETPROF_PACKET_TYPE_UDP, TOX_NETPROF_DIRECTION_RECV);

        // TCP (Aggregated)
        stats.total_tcp.count_sent = tox_netprof_get_packet_total_count(
            tox, TOX_NETPROF_PACKET_TYPE_TCP, TOX_NETPROF_DIRECTION_SENT);
        stats.total_tcp.count_recv = tox_netprof_get_packet_total_count(
            tox, TOX_NETPROF_PACKET_TYPE_TCP, TOX_NETPROF_DIRECTION_RECV);
        stats.total_tcp.bytes_sent = tox_netprof_get_packet_total_bytes(
            tox, TOX_NETPROF_PACKET_TYPE_TCP, TOX_NETPROF_DIRECTION_SENT);
        stats.total_tcp.bytes_recv = tox_netprof_get_packet_total_bytes(
            tox, TOX_NETPROF_PACKET_TYPE_TCP, TOX_NETPROF_DIRECTION_RECV);

        // DHT
        stats.dht.num_closelist = tox_dht_get_num_closelist(tox);
        uint32_t num_friends = tox_self_get_friend_list_size(tox);
        stats.dht.num_friends = static_cast<uint16_t>(num_friends);
        stats.dht.connection_status = tox_self_get_connection_status(tox);

        for (uint32_t i = 0; i < num_friends; ++i) {
            Tox_Connection status = tox_friend_get_connection_status(tox, i, nullptr);
            if (status == TOX_CONNECTION_UDP) {
                stats.dht.num_friends_udp++;
            } else if (status == TOX_CONNECTION_TCP) {
                stats.dht.num_friends_tcp++;
            }
        }

        for (uint16_t id = 0; id < 256; ++id) {
            uint8_t id8 = static_cast<uint8_t>(id);

            uint64_t bytes_sent_udp = tox_netprof_get_packet_id_bytes(
                tox, TOX_NETPROF_PACKET_TYPE_UDP, id8, TOX_NETPROF_DIRECTION_SENT);
            uint64_t bytes_recv_udp = tox_netprof_get_packet_id_bytes(
                tox, TOX_NETPROF_PACKET_TYPE_UDP, id8, TOX_NETPROF_DIRECTION_RECV);
            if (bytes_sent_udp > 0 || bytes_recv_udp > 0) {
                stats.udp_packet_stats[id8] = {bytes_sent_udp, bytes_recv_udp};
            }

            uint64_t bytes_sent_tcp = tox_netprof_get_packet_id_bytes(
                tox, TOX_NETPROF_PACKET_TYPE_TCP, id8, TOX_NETPROF_DIRECTION_SENT);
            uint64_t bytes_recv_tcp = tox_netprof_get_packet_id_bytes(
                tox, TOX_NETPROF_PACKET_TYPE_TCP, id8, TOX_NETPROF_DIRECTION_RECV);
            if (bytes_sent_tcp > 0 || bytes_recv_tcp > 0) {
                stats.tcp_packet_stats[id8] = {bytes_sent_tcp, bytes_recv_tcp};
            }
        }

        return stats;
    });
}

void NodeWrapper::send_message(uint32_t friend_number, const std::string &msg)
{
    runner_->execute([friend_number, msg](Tox *tox) {
        tox_friend_send_message(tox, friend_number, TOX_MESSAGE_TYPE_NORMAL,
            reinterpret_cast<const uint8_t *>(msg.data()), msg.size(), nullptr);
    });
}

void NodeWrapper::set_online(bool online)
{
    if (online) {
        runner_->resume();
    } else {
        runner_->pause();
    }
}

bool NodeWrapper::is_online() const { return runner_->is_active(); }

}  // namespace tox::netprof
