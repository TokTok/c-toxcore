#ifndef C_TOXCORE_TESTING_NETPROF_LAYOUT_ENGINE_H
#define C_TOXCORE_TESTING_NETPROF_LAYOUT_ENGINE_H

#include <cstdint>
#include <map>
#include <random>
#include <vector>

#include "constants.hh"

namespace tox::netprof {

struct LayoutNode {
    uint32_t id;
    float x, y;
    float vx, vy;
    bool fixed;
};

struct LayoutLink {
    uint32_t from;
    uint32_t to;
};

/**
 * @brief Continuous Force-Directed Graph Layout Engine.
 */
class LayoutEngine {
public:
    explicit LayoutEngine(float width = 100.0f, float height = 100.0f);

    void add_node(uint32_t id, float x, float y, bool fixed = false);
    void remove_node(uint32_t id);
    void update_node(uint32_t id, float x, float y, bool fixed);

    void add_link(uint32_t from, uint32_t to);
    void remove_link(uint32_t from, uint32_t to);

    /**
     * @brief Advance the layout simulation by one tick.
     */
    void step(float dt = 0.1f);

    const std::map<uint32_t, LayoutNode> &nodes() const { return nodes_; }
    bool is_stabilized() const { return stabilized_; }

private:
    float width_, height_;
    std::map<uint32_t, LayoutNode> nodes_;
    std::vector<LayoutLink> links_;

    std::minstd_rand rng_{42};
    bool stabilized_ = false;

    // Hyperparameters
    float repulsion_constant_ = kDefaultRepulsion;
    float attraction_constant_ = kDefaultAttraction;
    float ideal_length_ = kDefaultIdealLength;
    float friction_ = kDefaultFriction;
    float stabilization_threshold_ = kDefaultStabilizationThreshold;
};

}  // namespace tox::netprof

#endif  // C_TOXCORE_TESTING_NETPROF_LAYOUT_ENGINE_H
