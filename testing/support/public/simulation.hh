#ifndef C_TOXCORE_TESTING_SUPPORT_SIMULATION_H
#define C_TOXCORE_TESTING_SUPPORT_SIMULATION_H

#include <functional>
#include <memory>
#include <vector>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <winsock2.h>
#else
#include <netinet/in.h>
#include <sys/socket.h>
#endif

#include "../../../toxcore/tox.h"
#include "../../../toxcore/tox_memory_impl.h"
#include "../../../toxcore/tox_private.h"
#include "../../../toxcore/tox_random_impl.h"
#include "../doubles/fake_clock.hh"
#include "../doubles/fake_memory.hh"
#include "../doubles/fake_network_stack.hh"
#include "../doubles/fake_random.hh"
#include "../doubles/network_universe.hh"
#include "environment.hh"

namespace tox::test {

class SimulatedNode;

/**
 * @brief The Simulation World.
 * Holds the Clock and the Universe.
 */
class Simulation {
public:
    Simulation();
    ~Simulation();

    // Time Control
    void advance_time(uint64_t ms);
    void run_until(std::function<bool()> condition, uint64_t timeout_ms = 5000);

    // Global Access
    FakeClock &clock() { return *clock_; }
    NetworkUniverse &net() { return *net_; }

    // Node Factory
    std::unique_ptr<SimulatedNode> create_node();

private:
    std::unique_ptr<FakeClock> clock_;
    std::unique_ptr<NetworkUniverse> net_;
};

/**
 * @brief Represents a single node in the simulation.
 * Implements the Environment interface for dependency injection.
 */
class SimulatedNode : public Environment {
public:
    explicit SimulatedNode(Simulation &sim);
    ~SimulatedNode() override;

    // Environment Interface
    NetworkSystem &network() override;
    ClockSystem &clock() override;
    RandomSystem &random() override;
    MemorySystem &memory() override;

    // Direct Access to Fakes
    FakeNetworkStack &fake_network() { return *network_; }
    FakeRandom &fake_random() { return *random_; }
    FakeMemory &fake_memory() { return *memory_; }

    // Tox Creation Helper
    // Returns a configured Tox instance bound to this node's environment.
    // The user owns the Tox instance.
    struct ToxDeleter {
        void operator()(Tox *t) const { tox_kill(t); }
    };
    using ToxPtr = std::unique_ptr<Tox, ToxDeleter>;

    ToxPtr create_tox(const Tox_Options *options = nullptr);

    // Helper to get C structs for manual injection
    struct Network get_c_network() { return network_->get_c_network(); }
    struct Tox_Random get_c_random() { return random_->get_c_random(); }
    struct Tox_Memory get_c_memory() { return memory_->get_c_memory(); }

    // For fuzzing compatibility (exposes first bound UDP socket as "endpoint")
    FakeUdpSocket *get_primary_socket();

private:
    Simulation &sim_;
    std::unique_ptr<FakeNetworkStack> network_;
    std::unique_ptr<FakeRandom> random_;
    std::unique_ptr<FakeMemory> memory_;
};

}  // namespace tox::test

#endif  // C_TOXCORE_TESTING_SUPPORT_SIMULATION_H
