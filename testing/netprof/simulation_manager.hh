#ifndef C_TOXCORE_TESTING_NETPROF_SIMULATION_MANAGER_H
#define C_TOXCORE_TESTING_NETPROF_SIMULATION_MANAGER_H

#include <memory>
#include <mutex>
#include <nlohmann/json.hpp>
#include <string>
#include <vector>

#include "../support/public/simulation.hh"
#include "../support/public/tox_network.hh"
#include "../support/public/tox_runner.hh"
#include "constants.hh"
#include "node_wrapper.hh"

namespace tox::netprof {

/**
 * @brief Manages the lifecycle of the simulation and its nodes.
 * Handles persistence (Load/Save) and global simulation control.
 */
class SimulationManager {
public:
    explicit SimulationManager(uint64_t seed, bool verbose = false);
    ~SimulationManager();

    // Simulation Control
    void start();
    void stop();
    void step(uint64_t ms = kDefaultTickMs);
    bool is_running() const;

    // Node Management
    std::shared_ptr<NodeWrapper> add_node(
        std::string name, float x = -1.0f, float y = -1.0f, bool tcp_only = false);
    void remove_node(uint32_t id);
    std::shared_ptr<NodeWrapper> get_node(uint32_t id);
    std::shared_ptr<NodeWrapper> get_node_by_name(const std::string &name) const;
    std::shared_ptr<NodeWrapper> get_node_by_dht_id(const uint8_t *dht_id);
    std::vector<std::shared_ptr<NodeWrapper>> get_nodes() const;

    size_t node_count() const
    {
        std::lock_guard<std::recursive_mutex> lock(nodes_mutex_);
        return nodes_.size();
    }

    template <typename F>
    void for_each_node(F &&f) const
    {
        std::vector<std::shared_ptr<NodeWrapper>> nodes_copy;
        {
            std::lock_guard<std::recursive_mutex> lock(nodes_mutex_);
            nodes_copy = nodes_;
        }
        for (const auto &node : nodes_copy) {
            f(*node);
        }
    }

    // Connection Management
    // Returns true if connection was successfully initiated
    bool connect_nodes(uint32_t id_a, uint32_t id_b, bool tcp_only = false);
    bool disconnect_nodes(uint32_t id_a, uint32_t id_b);

    // Persistence
    nlohmann::json to_json() const;
    void from_json(const nlohmann::json &j);

    void save_to_file(const std::string &filename) const;
    void load_from_file(const std::string &filename);

    // Global Stats
    uint64_t get_virtual_time_ms() const;
    uint64_t total_packets_sent() const { return total_packets_sent_; }
    uint64_t total_bytes_sent() const { return total_bytes_sent_; }
    const std::map<uint8_t, uint64_t> &global_protocol_breakdown() const
    {
        return global_protocol_breakdown_;
    }

    // Track intended topology for persistence
    struct ConnectionIntent {
        uint32_t node_a;
        uint32_t node_b;
        bool tcp_only;
    };

    template <typename F>
    void for_each_connection(F &&f) const
    {
        std::lock_guard<std::recursive_mutex> lock(nodes_mutex_);
        for (const auto &conn : connections_) {
            f(conn);
        }
    }

    // Access to underlying simulation
    tox::test::Simulation &simulation() { return sim_; }

private:
    const uint64_t seed_;
    tox::test::Simulation sim_;
    std::vector<std::shared_ptr<NodeWrapper>> nodes_;
    std::vector<ConnectionIntent> connections_;
    std::map<std::vector<uint8_t>, std::shared_ptr<NodeWrapper>> dht_id_to_node_;

    mutable std::recursive_mutex nodes_mutex_;
    std::atomic<bool> running_{false};
    const bool verbose_;

    std::atomic<uint64_t> total_packets_sent_{0};
    std::atomic<uint64_t> total_bytes_sent_{0};
    std::map<uint8_t, uint64_t> global_protocol_breakdown_;
};

}  // namespace tox::netprof

#endif  // C_TOXCORE_TESTING_NETPROF_SIMULATION_MANAGER_H
