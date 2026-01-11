#include "../public/simulation.hh"

#include <cassert>
#include <iostream>

namespace tox::test {

// --- Simulation ---

Simulation::Simulation()
    : clock_(std::make_unique<FakeClock>())
    , net_(std::make_unique<NetworkUniverse>())
{
}

Simulation::~Simulation() = default;

void Simulation::advance_time(uint64_t ms)
{
    clock_->advance(ms);
    net_->process_events(clock_->current_time_ms());
}

void Simulation::run_until(std::function<bool()> condition, uint64_t timeout_ms)
{
    uint64_t start_time = clock_->current_time_ms();
    while (!condition()) {
        if (clock_->current_time_ms() - start_time > timeout_ms) {
            break;
        }
        advance_time(10);  // 10ms ticks
    }
}

std::unique_ptr<SimulatedNode> Simulation::create_node()
{
    auto node = std::make_unique<SimulatedNode>(*this, ++node_count_);
    if (net_->is_verbose()) {
        uint32_t ip4 = net_ntohl(node->ip.ip.v4.uint32);
        std::cerr << "[Simulation] Created node " << node_count_ << " with IP "
                  << ((ip4 >> 24) & 0xFF) << "." << ((ip4 >> 16) & 0xFF) << "."
                  << ((ip4 >> 8) & 0xFF) << "." << (ip4 & 0xFF) << std::endl;
    }
    return node;
}

// --- SimulatedNode ---

SimulatedNode::SimulatedNode(Simulation &sim, uint32_t node_id)
    : sim_(sim)
    , network_(std::make_unique<FakeNetworkStack>(sim.net(), make_node_ip(node_id)))
    , random_(std::make_unique<FakeRandom>(12345 + node_id))  // Unique seed
    , memory_(std::make_unique<FakeMemory>())
    , c_network(network_->get_c_network())
    , c_random(random_->get_c_random())
    , c_memory(memory_->get_c_memory())
    , ip(make_node_ip(node_id))
{
}

SimulatedNode::~SimulatedNode() = default;

NetworkSystem &SimulatedNode::network() { return *network_; }
ClockSystem &SimulatedNode::clock() { return sim_.clock(); }
RandomSystem &SimulatedNode::random() { return *random_; }
MemorySystem &SimulatedNode::memory() { return *memory_; }

SimulatedNode::ToxPtr SimulatedNode::create_tox(const Tox_Options *options)
{
    std::unique_ptr<Tox_Options, decltype(&tox_options_free)> default_options(
        nullptr, tox_options_free);

    if (options == nullptr) {
        default_options.reset(tox_options_new(nullptr));
        assert(default_options != nullptr);
        tox_options_set_ipv6_enabled(default_options.get(), false);
        tox_options_set_start_port(default_options.get(), 33445);
        tox_options_set_end_port(default_options.get(), 55555);
        options = default_options.get();
    }

    Tox_Options_Testing opts_testing;
    Tox_System system;
    system.ns = &c_network;
    system.rng = &c_random;
    system.mem = &c_memory;
    system.mono_time_callback = [](void *user_data) -> uint64_t {
        return static_cast<FakeClock *>(user_data)->current_time_ms();
    };
    system.mono_time_user_data = &sim_.clock();

    opts_testing.operating_system = &system;

    Tox_Err_New err;
    Tox_Err_New_Testing err_testing;

    Tox *t = tox_new_testing(options, &err, &opts_testing, &err_testing);

    if (!t) {
        return nullptr;
    }
    return ToxPtr(t);
}

FakeUdpSocket *SimulatedNode::get_primary_socket()
{
    auto sockets = network_->get_bound_udp_sockets();
    if (sockets.empty())
        return nullptr;
    return sockets.front();  // Return the first one bound
}

}  // namespace tox::test
