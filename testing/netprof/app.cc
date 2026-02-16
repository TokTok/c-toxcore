#include "app.hh"

#include <iostream>

#include "../../toxcore/tox_private.h"
#include "model_utils.hh"
#include "packet_utils.hh"

namespace tox::netprof {

NetProfApp::NetProfApp(uint64_t seed, bool verbose)
    : manager_(seed, verbose)
    , ui_([this](UICommand cmd) { this->handle_command(std::move(cmd)); })
    , last_sync_virtual_time_(manager_.get_virtual_time_ms())
{
    // Initial setup
    auto alice = manager_.add_node("Alice", 20.0f, 50.0f);
    auto bob = manager_.add_node("Bob", 80.0f, 50.0f);
    manager_.connect_nodes(alice->id(), bob->id());

    // Notify UI of initial state
    ui_.emit(MsgNodeAdded{alice->id(), alice->name(), alice->x(), alice->y(), alice->get_dht_id()});
    ui_.emit(MsgNodeAdded{bob->id(), bob->name(), bob->x(), bob->y(), bob->get_dht_id()});
    ui_.emit(MsgLinkUpdated{alice->id(), bob->id(), true, 5, 0.0});
}

NetProfApp::~NetProfApp()
{
    running_ = false;
    pause_cv_.notify_all();
    if (sim_thread_.joinable())
        sim_thread_.join();
}

void NetProfApp::run(bool headless, const std::string &load_path)
{
    if (!load_path.empty()) {
        load_snapshot(load_path);
    }

    if (headless) {
        run_headless();
        return;
    }

    // Start simulation thread.
    sim_thread_ = std::thread([this] { simulation_loop(); });

    // Start UI (blocking).
    ui_.run();
}

void NetProfApp::handle_command(UICommand cmd)
{
    switch (cmd.type) {
    case CmdType::Quit:
        running_ = false;
        pause_cv_.notify_all();
        break;
    case CmdType::TogglePause:
        auto_play_ = !auto_play_;
        pause_cv_.notify_all();
        sync_stats();
        ui_.emit(
            MsgLog{auto_play_ ? "Simulation RESUMED" : "Simulation PAUSED", LogLevel::Command});
        break;
    case CmdType::Step:
        manager_.step(kDefaultTickMs);
        sync_stats();
        ui_.emit(MsgLog{"Simulation STEPPED", LogLevel::Command});
        break;
    case CmdType::SetSpeed:
        if (!cmd.args.empty()) {
            double speed;
            if (safe_stod(cmd.args[0], speed)) {
                simulation_speed_ = speed;
                pause_cv_.notify_all();
                sync_stats();
                ui_.emit(MsgLog{"Simulation speed set to " + cmd.args[0] + "x", LogLevel::Command});
            }
        }
        break;
    case CmdType::AddNode:
        cmd_add_node(cmd.args);
        break;
    case CmdType::MoveNode:
        cmd_move_node(cmd.args);
        break;
    case CmdType::RemoveNode:
        cmd_remove_node(cmd.args);
        break;
    case CmdType::ConnectNodes:
        cmd_connect_nodes(cmd.args);
        break;
    case CmdType::DisconnectNodes:
        cmd_disconnect_nodes(cmd.args);
        break;
    case CmdType::ToggleOffline:
        cmd_toggle_offline(cmd.args);
        break;
    case CmdType::TogglePin:
        cmd_toggle_pin(cmd.args);
        break;
    case CmdType::SaveSnapshot:
        manager_.save_to_file("netprof_save.json");
        ui_.emit(MsgLog{"Saved to netprof_save.json", LogLevel::Command});
        break;
    case CmdType::LoadSnapshot:
        manager_.load_from_file("netprof_save.json");
        resync_ui();
        ui_.emit(MsgLog{"Loaded snapshot and resynced UI", LogLevel::Command});
        break;
    }
}

void NetProfApp::cmd_add_node(const std::vector<std::string> &args)
{
    std::string name;
    bool tcp_only = false;

    // Try to find an unused "nice" name.
    for (const char *candidate : kNiceNames) {
        bool taken = false;
        manager_.for_each_node([&](const NodeWrapper &n) {
            if (n.name() == candidate) {
                taken = true;
            }
        });
        if (!taken) {
            name = candidate;
            break;
        }
    }

    if (name.empty()) {
        name = "Node " + std::to_string(manager_.node_count() + 1);
    }

    if (!args.empty() && args.back() == "tcp") {
        tcp_only = true;
    }

    auto n = manager_.add_node(name, -1.0f, -1.0f, tcp_only);
    ui_.emit(MsgNodeAdded{n->id(), name, -1.0f, -1.0f, n->get_dht_id()});
    ui_.emit(MsgLog{
        "Added node: " + name + " (ID: " + std::to_string(n->id()) + ")", LogLevel::Command});
}

void NetProfApp::cmd_move_node(const std::vector<std::string> &args)
{
    if (args.size() >= 3) {
        uint32_t id;
        std::shared_ptr<NodeWrapper> n;
        if (safe_stoul(args[0], id)) {
            n = manager_.get_node(id);
        } else {
            n = manager_.get_node_by_name(args[0]);
            if (n)
                id = n->id();
        }

        float x, y;
        if (n && safe_stof(args[1], x) && safe_stof(args[2], y)) {
            n->set_pos(x, y);
            n->set_pinned(true);
            ui_.emit(MsgNodeMoved{id, x, y});
            ui_.emit(MsgLog{"Moved and PINNED node " + std::to_string(id) + " to (" + args[1] + ", "
                    + args[2] + ")",
                LogLevel::Command});
        }
    }
}

void NetProfApp::cmd_remove_node(const std::vector<std::string> &args)
{
    if (!args.empty()) {
        uint32_t id;
        if (safe_stoul(args[0], id)) {
            manager_.remove_node(id);
            ui_.emit(MsgNodeRemoved{id});
            ui_.emit(MsgLog{"Removed node " + std::to_string(id), LogLevel::Command});
        } else if (auto n = manager_.get_node_by_name(args[0])) {
            id = n->id();
            manager_.remove_node(id);
            ui_.emit(MsgNodeRemoved{id});
            ui_.emit(MsgLog{
                "Removed node " + std::to_string(id) + " (" + args[0] + ")", LogLevel::Command});
        }
    }
}

void NetProfApp::cmd_connect_nodes(const std::vector<std::string> &args)
{
    if (args.size() >= 2) {
        std::shared_ptr<NodeWrapper> n1, n2;
        uint32_t id1, id2;

        if (safe_stoul(args[0], id1)) {
            n1 = manager_.get_node(id1);
        } else {
            n1 = manager_.get_node_by_name(args[0]);
        }

        if (safe_stoul(args[1], id2)) {
            n2 = manager_.get_node(id2);
        } else {
            n2 = manager_.get_node_by_name(args[1]);
        }

        if (n1 && n2) {
            id1 = n1->id();
            id2 = n2->id();
            if (manager_.connect_nodes(id1, id2)) {
                ui_.emit(MsgLinkUpdated{id1, id2, true, 20, 0.0});
                ui_.emit(
                    MsgLog{"Connected node " + std::to_string(id1) + " and " + std::to_string(id2),
                        LogLevel::Command});
            }
        }
    }
}

void NetProfApp::cmd_disconnect_nodes(const std::vector<std::string> &args)
{
    if (args.size() >= 2) {
        std::shared_ptr<NodeWrapper> n1, n2;
        uint32_t id1, id2;

        if (safe_stoul(args[0], id1)) {
            n1 = manager_.get_node(id1);
        } else {
            n1 = manager_.get_node_by_name(args[0]);
        }

        if (safe_stoul(args[1], id2)) {
            n2 = manager_.get_node(id2);
        } else {
            n2 = manager_.get_node_by_name(args[1]);
        }

        if (n1 && n2) {
            id1 = n1->id();
            id2 = n2->id();
            if (manager_.disconnect_nodes(id1, id2)) {
                ui_.emit(MsgLinkUpdated{id1, id2, false, 0, 0.0});
                ui_.emit(MsgLog{
                    "Disconnected node " + std::to_string(id1) + " and " + std::to_string(id2),
                    LogLevel::Command});
            }
        }
    }
}

void NetProfApp::cmd_toggle_offline(const std::vector<std::string> &args)
{
    if (!args.empty()) {
        uint32_t id;
        std::shared_ptr<NodeWrapper> n;
        if (safe_stoul(args[0], id)) {
            n = manager_.get_node(id);
        } else {
            n = manager_.get_node_by_name(args[0]);
            if (n)
                id = n->id();
        }

        if (n) {
            bool new_state = !n->is_online();
            n->set_online(new_state);
            ui_.emit(MsgLog{
                "Node " + std::to_string(id) + " is now " + (new_state ? "online" : "offline"),
                LogLevel::Command});
        }
    }
}

void NetProfApp::cmd_toggle_pin(const std::vector<std::string> &args)
{
    if (!args.empty()) {
        uint32_t id;
        std::shared_ptr<NodeWrapper> n;
        if (safe_stoul(args[0], id)) {
            n = manager_.get_node(id);
        } else {
            n = manager_.get_node_by_name(args[0]);
            if (n)
                id = n->id();
        }

        if (n) {
            bool new_state = !n->is_pinned();
            n->set_pinned(new_state);
            ui_.emit(MsgLog{
                "Node " + std::to_string(id) + " is now " + (new_state ? "PINNED" : "UNPINNED"),
                LogLevel::Command});
        }
    }
}

void NetProfApp::load_snapshot(const std::string &filename)
{
    manager_.load_from_file(filename);
    resync_ui();
    ui_.emit(MsgLog{"Loaded snapshot: " + filename, LogLevel::Command});
}

void NetProfApp::resync_ui()
{
    ui_.emit(MsgReset{});
    manager_.for_each_node([this](const NodeWrapper &n) {
        ui_.emit(MsgNodeAdded{n.id(), n.name(), n.x(), n.y(), n.get_dht_id()});
    });

    manager_.for_each_connection([this](const SimulationManager::ConnectionIntent &c) {
        ui_.emit(MsgLinkUpdated{c.node_a, c.node_b, true, 20, 0.0});
    });
}

void NetProfApp::sync_stats()
{
    std::lock_guard<std::mutex> lock(stats_mutex_);

    std::vector<UIMessage> batch_msgs;
    auto emit = [&](UIMessage msg) { batch_msgs.push_back(std::move(msg)); };

    uint64_t virtual_time = manager_.get_virtual_time_ms();
    uint64_t delta_ms = virtual_time - last_sync_virtual_time_;
    uint32_t num_ticks = static_cast<uint32_t>(delta_ms / kDefaultTickMs);
    if (num_ticks > 0) {
        last_sync_virtual_time_ += num_ticks * kDefaultTickMs;
    }

    std::map<NodeInfo::ProtocolKey, NetProfStats::PerPacket> global_per_packet_bytes;
    std::vector<std::pair<uint32_t, NetProfStats>> node_stats_snapshots;
    manager_.for_each_node([&](const NodeWrapper &node) {
        auto stats = const_cast<NodeWrapper &>(node).get_stats();
        node_stats_snapshots.push_back({node.id(), stats});

        auto add_stats = [&](const std::map<uint8_t, NetProfStats::PerPacket> &packet_stats,
                             Tox_Netprof_Packet_Type protocol) {
            for (const auto &kv : packet_stats) {
                if (kv.second.sent == 0 && kv.second.recv == 0) {
                    continue;
                }
                NodeInfo::ProtocolKey key{static_cast<uint8_t>(protocol), kv.first};
                global_per_packet_bytes[key].sent += kv.second.sent;
                global_per_packet_bytes[key].recv += kv.second.recv;
            }
        };

        add_stats(stats.udp_packet_stats, TOX_NETPROF_PACKET_TYPE_UDP);
        add_stats(stats.tcp_packet_stats, TOX_NETPROF_PACKET_TYPE_TCP);
    });

    // Collect statistics from simulation and emit to UI.
    GlobalStats gstats;
    gstats.virtual_time_ms = virtual_time;
    gstats.real_time_factor = simulation_speed_;
    gstats.total_packets_sent = manager_.total_packets_sent();
    gstats.total_bytes_sent = manager_.total_bytes_sent();
    gstats.paused = !auto_play_;
    for (const auto &kv : global_per_packet_bytes) {
        gstats.protocol_breakdown[kv.first] = {kv.second.sent, kv.second.recv};
    }
    emit(MsgTick{gstats});

    for (const auto &node_entry : node_stats_snapshots) {
        uint32_t id = node_entry.first;
        const auto &stats = node_entry.second;
        auto node_ptr = manager_.get_node(id);

        int bw_in = 0;
        int bw_out = 0;

        if (last_node_stats_.count(id) && delta_ms > 0) {
            const auto &prev = last_node_stats_[id];
            uint64_t total_recv = stats.total_udp.bytes_recv + stats.total_tcp.bytes_recv;
            uint64_t total_sent = stats.total_udp.bytes_sent + stats.total_tcp.bytes_sent;
            uint64_t prev_recv = prev.total_udp.bytes_recv + prev.total_tcp.bytes_recv;
            uint64_t prev_sent = prev.total_udp.bytes_sent + prev.total_tcp.bytes_sent;

            bw_in = static_cast<int>((total_recv - prev_recv) * 1000 / delta_ms);
            bw_out = static_cast<int>((total_sent - prev_sent) * 1000 / delta_ms);
        }

        if (num_ticks > 0) {
            last_node_stats_[id] = stats;
        }

        std::map<NodeInfo::ProtocolKey, NodeInfo::Traffic> protocol_breakdown;
        auto add_node_stats = [&](const std::map<uint8_t, NetProfStats::PerPacket> &packet_stats,
                                  Tox_Netprof_Packet_Type protocol) {
            for (const auto &kv : packet_stats) {
                if (kv.second.sent == 0 && kv.second.recv == 0) {
                    continue;
                }
                NodeInfo::ProtocolKey key{static_cast<uint8_t>(protocol), kv.first};
                protocol_breakdown[key].sent += kv.second.sent;
                protocol_breakdown[key].recv += kv.second.recv;
            }
        };

        add_node_stats(stats.udp_packet_stats, TOX_NETPROF_PACKET_TYPE_UDP);
        add_node_stats(stats.tcp_packet_stats, TOX_NETPROF_PACKET_TYPE_TCP);

        emit(MsgNodeStats{
            id,
            bw_in,
            bw_out,
            stats.dht.num_closelist,
            stats.dht.num_friends,
            stats.dht.num_friends_udp,
            stats.dht.num_friends_tcp,
            stats.dht.connection_status,
            node_ptr ? node_ptr->is_online() : false,
            node_ptr ? node_ptr->is_pinned() : false,
            num_ticks,
            protocol_breakdown,
        });
        // Poll events.
        if (node_ptr) {
            auto event_batches = node_ptr->poll_events();
            for (const auto &batch : event_batches) {
                uint32_t num_events = tox_events_get_size(batch.get());
                for (uint32_t i = 0; i < num_events; ++i) {
                    const Tox_Event *ev = tox_events_get(batch.get(), i);
                    Tox_Event_Type type = tox_event_get_type(ev);
                    LogLevel level = LogLevel::Info;

                    if (type == TOX_EVENT_DHT_NODES_RESPONSE) {
                        level = LogLevel::DHT;
                        const Tox_Event_Dht_Nodes_Response *res
                            = tox_event_get_dht_nodes_response(ev);
                        const uint8_t *responder_pk
                            = tox_event_dht_nodes_response_get_responder_public_key(res);
                        auto responder = manager_.get_node_by_dht_id(responder_pk);
                        uint32_t responder_id = responder ? responder->id() : 0;

                        const uint8_t *discovered_pk
                            = tox_event_dht_nodes_response_get_public_key(res);
                        auto discovered = manager_.get_node_by_dht_id(discovered_pk);
                        uint32_t discovered_id = discovered ? discovered->id() : 0;

                        emit(MsgDHTResponse{id, responder_id, discovered_id});
                    } else if (type == TOX_EVENT_FRIEND_CONNECTION_STATUS) {
                        level = LogLevel::Conn;
                    }

                    emit(MsgLog{
                        "Node " + std::to_string(id) + " event: " + tox_event_type_to_string(type),
                        level,
                    });
                }
            }
        }
    }

    if (!batch_msgs.empty()) {
        ui_.emit_batch(std::move(batch_msgs));
    }
}

void NetProfApp::simulation_loop()
{
    auto last_sync_real_time = std::chrono::steady_clock::now();
    while (running_) {
        if (auto_play_) {
            auto start_step = std::chrono::steady_clock::now();
            manager_.step(kDefaultTickMs);

            auto now = std::chrono::steady_clock::now();
            if (now - last_sync_real_time >= std::chrono::milliseconds(kUIRefreshIntervalMs)) {
                sync_stats();
                last_sync_real_time = now;
            }

            if (simulation_speed_ > 0.0) {
                auto target_duration = std::chrono::microseconds(
                    static_cast<long long>(kDefaultTickMs * 1000.0 / simulation_speed_));
                auto end_step = std::chrono::steady_clock::now();
                auto elapsed = end_step - start_step;

                if (target_duration > elapsed) {
                    std::unique_lock<std::mutex> lock(pause_mutex_);
                    pause_cv_.wait_for(lock, target_duration - elapsed,
                        [this] { return !running_ || !auto_play_; });
                }
            }
        } else {
            sync_stats();
            std::unique_lock<std::mutex> lock(pause_mutex_);
            pause_cv_.wait_for(
                lock, std::chrono::milliseconds(100), [this] { return !running_ || auto_play_; });
        }
    }
}

void NetProfApp::run_headless()
{
    std::cout << "[Headless] Starting..." << std::endl;
    for (int i = 0; i < 100; ++i) {
        manager_.step(kDefaultTickMs);
        if (i % 20 == 0)
            std::cout << "Tick " << i << std::endl;
    }
}

}  // namespace tox::netprof
