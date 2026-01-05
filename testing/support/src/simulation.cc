#include "../public/simulation.hh"

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
    return std::make_unique<SimulatedNode>(*this);
}

// --- SimulatedNode ---

SimulatedNode::SimulatedNode(Simulation &sim)
    : sim_(sim)
    , network_(std::make_unique<FakeNetworkStack>(sim.net()))
    , random_(
          std::make_unique<FakeRandom>(12345 + sim.net().find_free_port(0)))  // Pseudo-random seed
    , memory_(std::make_unique<FakeMemory>())
{
}

SimulatedNode::~SimulatedNode() = default;

NetworkSystem &SimulatedNode::network() { return *network_; }
ClockSystem &SimulatedNode::clock() { return sim_.clock(); }
RandomSystem &SimulatedNode::random() { return *random_; }
MemorySystem &SimulatedNode::memory() { return *memory_; }

SimulatedNode::ToxPtr SimulatedNode::create_tox(const Tox_Options *options)
{
    std::unique_ptr<Tox_Options, decltype(&tox_options_free)> opts(
        tox_options_new(nullptr), tox_options_free);
    if (options) {
        // Here we should copy relevant options manually or use the passed options
        // For now, let's just use defaults as base
    }

    // Inject dependencies
    struct Network net_c = get_c_network();
    struct Tox_Random rnd_c = get_c_random();
    struct Tox_Memory mem_c = get_c_memory();

    Tox_Options_Testing opts_testing;
    Tox_System system;
    system.ns = &net_c;
    system.rng = &rnd_c;
    system.mem = &mem_c;
    system.mono_time_callback = [](void *user_data) -> uint64_t {
        return static_cast<FakeClock *>(user_data)->current_time_ms();
    };
    system.mono_time_user_data = &sim_.clock();

    opts_testing.operating_system = &system;

    Tox_Err_New err;
    Tox_Err_New_Testing err_testing;

    // Note: tox_new_testing takes ownership of nothing, but we pass pointers to stack structs
    // These structs must remain valid for the lifetime of Tox.
    // Since SimulatedNode owns the FakeNetworkStack/FakeRandom etc, and ToxPtr is owned by
    // caller, the caller must ensure SimulatedNode outlives ToxPtr. This is standard pattern.

    Tox *t = tox_new_testing(opts.get(), &err, &opts_testing, &err_testing);

    if (!t) {
        // std::cerr << "tox_new_testing failed: " << err << std::endl;
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
