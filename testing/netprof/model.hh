#ifndef C_TOXCORE_TESTING_NETPROF_MODEL_H
#define C_TOXCORE_TESTING_NETPROF_MODEL_H

#include <map>
#include <memory>
#include <string>
#include <variant>
#include <vector>

#include "../../toxcore/tox.h"
#include "constants.hh"

namespace tox::netprof {

enum class LogLevel { Info, Warn, Error, DHT, Crypto, Conn, Command };

/**
 * @brief Snapshot of traffic statistics for a single frame.
 */
struct NetProfStats {
    struct PacketStats {
        uint64_t count_sent = 0;
        uint64_t count_recv = 0;
        uint64_t bytes_sent = 0;
        uint64_t bytes_recv = 0;
    };

    PacketStats total_udp;
    PacketStats total_tcp;

    struct DHTStats {
        uint16_t num_closelist = 0;
        uint16_t num_friends = 0;
        uint16_t num_friends_udp = 0;
        uint16_t num_friends_tcp = 0;
        Tox_Connection connection_status = TOX_CONNECTION_NONE;
    } dht;

    struct PerPacket {
        uint64_t sent = 0;
        uint64_t recv = 0;
    };
    std::map<uint8_t, PerPacket> udp_packet_stats;
    std::map<uint8_t, PerPacket> tcp_packet_stats;
};

struct NodeInfo {
    uint32_t id;
    std::string name;
    bool is_online = true;
    std::vector<uint8_t> dht_id;

    // Statistics history (buffers).
    std::vector<int> dht_neighbors_history = std::vector<int>(kHistoryBufferSize, 0);
    std::vector<int> dht_response_history = std::vector<int>(kHistoryBufferSize, 0);
    std::vector<int> bw_in_history = std::vector<int>(kHistoryBufferSize, 0);
    std::vector<int> bw_out_history = std::vector<int>(kHistoryBufferSize, 0);

    struct Traffic {
        uint64_t sent = 0;
        uint64_t recv = 0;
    };

    struct ProtocolKey {
        uint8_t protocol;  // Tox_Netprof_Packet_Type
        uint8_t id;
        bool operator<(const ProtocolKey &other) const
        {
            if (protocol != other.protocol)
                return protocol < other.protocol;
            return id < other.id;
        }
    };
    std::map<ProtocolKey, Traffic> protocol_breakdown;

    struct DHTInfo {
        uint16_t num_closelist = 0;
        uint16_t num_friends = 0;
        uint16_t num_friends_udp = 0;
        uint16_t num_friends_tcp = 0;
        Tox_Connection connection_status = TOX_CONNECTION_NONE;
    } dht;

    // Visual position (synchronized from LayoutEngine).
    float x = 0.0f;
    float y = 0.0f;

    // Smoothed metrics.
    double ema_bw_in = 0.0;
    double ema_bw_out = 0.0;

    uint32_t dht_responses_received_this_tick = 0;

    bool is_pinned = false;
};

struct LinkInfo {
    uint32_t from;
    uint32_t to;
    bool connected;
    int latency_ms;
    double packet_loss;
    float congestion = 0.0f;
};

struct GlobalStats {
    uint64_t virtual_time_ms = 0;
    double real_time_factor = 0.0;
    uint64_t total_packets_sent = 0;
    uint64_t total_bytes_sent = 0;
    bool paused = true;
    std::map<NodeInfo::ProtocolKey, NodeInfo::Traffic> protocol_breakdown;
};

enum class LayerMode { Normal, TrafficType };

struct UIModel {
    GlobalStats stats;
    std::map<uint32_t, NodeInfo> nodes;
    std::vector<LinkInfo> links;

    struct InteractionKey {
        uint32_t id1;
        uint32_t id2;
        bool is_discovery;
        bool operator<(const InteractionKey &other) const
        {
            if (id1 != other.id1)
                return id1 < other.id1;
            if (id2 != other.id2)
                return id2 < other.id2;
            return is_discovery < other.is_discovery;
        }
    };
    std::map<InteractionKey, uint64_t> dht_interactions;

    struct LogEntry {
        std::string message;
        LogLevel level;
    };
    std::vector<LogEntry> logs;
    std::string log_filter;

    uint32_t selected_node_id = 0;
    uint32_t marked_node_id = 0;  // Selected node for connection operations.
    int cursor_x = 50;
    int cursor_y = 50;
    bool cursor_mode = false;
    bool grab_mode = false;
    LayerMode layer_mode = LayerMode::Normal;

    int screen_width = 0;
    int screen_height = 0;
    bool manual_screen_size = false;
    bool fast_mode = false;

    bool show_dht_interactions_physical = false;
    bool show_dht_responder_lines = true;
    bool show_dht_discovery_lines = true;
    bool show_command_palette = false;
    std::string command_input;
    int command_selected_index = 0;
    struct Suggestion {
        std::string name;
        std::string description;
    };
    std::vector<Suggestion> command_suggestions;
    int command_name_max_width = 15;
    int command_description_max_width = 0;
};

// UI messages.

struct MsgTick {
    GlobalStats stats;
};
struct MsgNodeAdded {
    uint32_t id;
    std::string name;
    float x = -1.0f;
    float y = -1.0f;
    std::vector<uint8_t> dht_id;
};
struct MsgNodeRemoved {
    uint32_t id;
};
struct MsgNodeMoved {
    uint32_t id;
    float x;
    float y;
};
struct MsgNodePinned {
    uint32_t id;
    bool pinned;
};
struct MsgLinkUpdated {
    uint32_t from;
    uint32_t to;
    bool connected;
    int latency;
    double loss;
    float congestion = 0.0f;
};
struct MsgNodeStats {
    uint32_t id;
    int bw_in;
    int bw_out;
    uint16_t dht_nodes;
    uint16_t dht_friends;
    uint16_t dht_friends_udp;
    uint16_t dht_friends_tcp;
    Tox_Connection connection_status;
    bool is_online;
    bool is_pinned;
    uint32_t num_ticks;
    std::map<NodeInfo::ProtocolKey, NodeInfo::Traffic> protocol_breakdown;
};
struct MsgLog {
    std::string message;
    LogLevel level = LogLevel::Info;
};

struct MsgDHTResponse {
    uint32_t receiver_id;
    uint32_t responder_id;  // 0 if responder is unknown or external.
    uint32_t discovered_id;  // 0 if discovered node is unknown or external.
};

struct MsgReset { };

struct MsgResize {
    int width;
    int height;
};

using UIMessage = std::variant<MsgTick, MsgNodeAdded, MsgNodeRemoved, MsgNodeMoved, MsgNodePinned,
    MsgLinkUpdated, MsgNodeStats, MsgLog, MsgDHTResponse, MsgReset, MsgResize>;

// UI commands.

enum class CmdType {
    Quit,
    TogglePause,
    Step,
    AddNode,
    MoveNode,
    RemoveNode,
    ConnectNodes,
    DisconnectNodes,
    ToggleOffline,
    TogglePin,
    SaveSnapshot,
    LoadSnapshot,
    SetSpeed
};

struct UICommand {
    CmdType type;
    std::vector<std::string> args;
};

}  // namespace tox::netprof

#endif  // C_TOXCORE_TESTING_NETPROF_MODEL_H
