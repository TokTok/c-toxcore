#include "layout_engine.hh"

#include <algorithm>
#include <cmath>

#ifdef force
#undef force
#endif

namespace tox::netprof {

LayoutEngine::LayoutEngine(float width, float height)
    : width_(width)
    , height_(height)
{
}

void LayoutEngine::add_node(uint32_t id, float x, float y, bool fixed)
{
    std::uniform_real_distribution<float> dist_w(0, width_);
    std::uniform_real_distribution<float> dist_h(0, height_);
    if (x < 0)
        x = dist_w(rng_);
    if (y < 0)
        y = dist_h(rng_);
    nodes_[id] = {id, x, y, 0, 0, fixed};
    stabilized_ = false;
}

void LayoutEngine::remove_node(uint32_t id)
{
    nodes_.erase(id);
    links_.erase(std::remove_if(links_.begin(), links_.end(),
                     [id](const LayoutLink &l) { return l.from == id || l.to == id; }),
        links_.end());
    stabilized_ = false;
}

void LayoutEngine::update_node(uint32_t id, float x, float y, bool fixed)
{
    if (nodes_.count(id)) {
        nodes_[id].x = x;
        nodes_[id].y = y;
        nodes_[id].fixed = fixed;
        nodes_[id].vx = 0;
        nodes_[id].vy = 0;
        stabilized_ = false;
    }
}

void LayoutEngine::add_link(uint32_t from, uint32_t to)
{
    links_.push_back({from, to});
    stabilized_ = false;
}

void LayoutEngine::remove_link(uint32_t from, uint32_t to)
{
    links_.erase(std::remove_if(links_.begin(), links_.end(),
                     [from, to](const LayoutLink &l) {
                         return (l.from == from && l.to == to) || (l.from == to && l.to == from);
                     }),
        links_.end());
    stabilized_ = false;
}

void LayoutEngine::step(float dt)
{
    if (stabilized_)
        return;

    // 1. Repulsion (between all nodes)
    for (auto &it1 : nodes_) {
        for (const auto &it2 : nodes_) {
            if (it1.first == it2.first)
                continue;

            float dx = it1.second.x - it2.second.x;
            float dy = it1.second.y - it2.second.y;
            float dist_sq = dx * dx + dy * dy + 0.01f;
            float dist = std::sqrt(dist_sq);

            float force = repulsion_constant_ / dist_sq;
            it1.second.vx += (dx / dist) * force * dt;
            it1.second.vy += (dy / dist) * force * dt;
        }
    }

    // 2. Attraction (along links)
    for (const auto &link : links_) {
        if (nodes_.count(link.from) == 0 || nodes_.count(link.to) == 0)
            continue;

        auto &n1 = nodes_[link.from];
        auto &n2 = nodes_[link.to];

        float dx = n2.x - n1.x;
        float dy = n2.y - n1.y;
        float dist = std::sqrt(dx * dx + dy * dy + 0.01f);

        float force = attraction_constant_ * (dist - ideal_length_);
        n1.vx += (dx / dist) * force * dt;
        n1.vy += (dy / dist) * force * dt;
        n2.vx -= (dx / dist) * force * dt;
        n2.vy -= (dy / dist) * force * dt;
    }

    // 3. Central Gravity (pull towards middle)
    float cx = width_ / 2.0f;
    float cy = height_ / 2.0f;
    for (auto &it : nodes_) {
        float dx = cx - it.second.x;
        float dy = cy - it.second.y;
        it.second.vx += dx * 0.01f * dt;
        it.second.vy += dy * 0.01f * dt;
    }

    // 4. Integration
    float total_ke = 0.0f;
    std::uniform_real_distribution<float> jitter_dist(-0.005f, 0.005f);
    for (auto &it : nodes_) {
        if (it.second.fixed) {
            it.second.vx = 0;
            it.second.vy = 0;
            continue;
        }

        // Apply a small amount of random jitter to prevent collinearity issues.
        it.second.vx += jitter_dist(rng_);
        it.second.vy += jitter_dist(rng_);

        it.second.x += it.second.vx * dt;
        it.second.y += it.second.vy * dt;

        // Apply friction.
        it.second.vx *= friction_;
        it.second.vy *= friction_;

        total_ke += it.second.vx * it.second.vx + it.second.vy * it.second.vy;

        // Boundary constraints.
        if (it.second.x < 5.0f) {
            it.second.x = 5.0f;
            it.second.vx = 0;
        } else if (it.second.x > width_ - 5.0f) {
            it.second.x = width_ - 5.0f;
            it.second.vx = 0;
        }

        if (it.second.y < 5.0f) {
            it.second.y = 5.0f;
            it.second.vy = 0;
        } else if (it.second.y > height_ - 5.0f) {
            it.second.y = height_ - 5.0f;
            it.second.vy = 0;
        }
    }

    if (total_ke < stabilization_threshold_) {
        stabilized_ = true;
    }
}

}  // namespace tox::netprof
