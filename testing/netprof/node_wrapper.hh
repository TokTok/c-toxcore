#ifndef C_TOXCORE_TESTING_NETPROF_NODE_WRAPPER_H
#define C_TOXCORE_TESTING_NETPROF_NODE_WRAPPER_H

#include <map>
#include <memory>
#include <string>
#include <vector>

#include "../../toxcore/tox.h"
#include "../support/public/simulation.hh"
#include "../support/public/tox_runner.hh"
#include "model.hh"

namespace tox::netprof {

/**
 * @brief Wraps a SimulatedNode and its ToxRunner for the UI.
 * Buffers events and provides thread-safe access to stats.
 */
class NodeWrapper {
public:
    NodeWrapper(tox::test::Simulation &sim, uint32_t id, std::string name, bool verbose,
        float x = -1.0f, float y = -1.0f, bool tcp_only = false);
    ~NodeWrapper();

    uint32_t id() const { return id_; }
    const std::string &name() const { return name_; }

    float x() const { return x_; }
    float y() const { return y_; }
    void set_pos(float x, float y)
    {
        x_ = x;
        y_ = y;
    }

    bool is_pinned() const { return pinned_; }
    void set_pinned(bool pinned) { pinned_ = pinned; }

    // Thread-safe access to Tox events
    std::vector<std::unique_ptr<Tox_Events, tox::test::ToxRunner::ToxEventsDeleter>> poll_events();

    // Snapshot current statistics
    NetProfStats get_stats();

    // Get DHT public key
    const std::vector<uint8_t> &get_dht_id() const { return dht_id_; }

    // Basic Tox Actions
    void send_message(uint32_t friend_number, const std::string &msg);
    void set_online(bool online);
    bool is_online() const;

    // Accessors
    tox::test::SimulatedNode &node() { return *node_; }
    tox::test::ToxRunner &runner() { return *runner_; }
    Tox *unsafe_tox() { return runner_->unsafe_tox(); }  // Use with care!

private:
    uint32_t id_;
    std::string name_;
    float x_ = -1.0f;
    float y_ = -1.0f;
    bool pinned_ = false;

    std::vector<uint8_t> dht_id_;

    std::unique_ptr<tox::test::SimulatedNode> node_;
    std::unique_ptr<tox::test::ToxRunner> runner_;
};

}  // namespace tox::netprof

#endif  // C_TOXCORE_TESTING_NETPROF_NODE_WRAPPER_H
