#ifndef C_TOXCORE_TOXCORE_DHT_TEST_UTIL_H
#define C_TOXCORE_TOXCORE_DHT_TEST_UTIL_H

#include <array>
#include <cstdint>
#include <functional>
#include <iosfwd>
#include <map>
#include <memory>
#include <vector>

#include "DHT.h"
#include "crypto_core.h"
#include "logger.h"
#include "mono_time.h"
#include "net_crypto.h"
#include "test_util.hh"

namespace tox::test {
class SimulatedEnvironment;
struct ScopedToxSystem;
}

template <>
struct Deleter<DHT> : Function_Deleter<DHT, kill_dht> { };

bool operator==(Node_format const &a, Node_format const &b);

std::ostream &operator<<(std::ostream &out, Node_format const &v);

Node_format random_node_format(const Random *rng);

// --- Mock DHT ---
struct MockDHT {
    std::uint8_t self_public_key[CRYPTO_PUBLIC_KEY_SIZE];
    std::uint8_t self_secret_key[CRYPTO_SECRET_KEY_SIZE];
    // Cache for shared keys: Public Key -> Shared Key
    std::map<std::array<std::uint8_t, CRYPTO_PUBLIC_KEY_SIZE>,
        std::array<std::uint8_t, CRYPTO_SHARED_KEY_SIZE>>
        shared_keys;
    int computation_count = 0;

    explicit MockDHT(const Random *rng);

    const std::uint8_t *get_shared_key(const std::uint8_t *pk);

    static const Net_Crypto_DHT_Funcs funcs;
};

// --- Mock DHT Wrapper ---
// Wraps a MockDHT instance and its dependencies (networking, etc.) within a SimulatedEnvironment
class WrappedMockDHT {
public:
    WrappedMockDHT(tox::test::SimulatedEnvironment &env, std::uint16_t port);

    MockDHT *get_dht() { return &dht_; }
    const std::uint8_t *dht_public_key() const { return dht_.self_public_key; }
    const std::uint8_t *dht_secret_key() const { return dht_.self_secret_key; }
    int dht_computation_count() const { return dht_.computation_count; }

    // Returns a valid IP_Port for this node in the simulation (Localhost IPv6)
    IP_Port get_ip_port() const;

    void poll();

    tox::test::ScopedToxSystem &node() { return *node_; }
    const tox::test::ScopedToxSystem &node() const { return *node_; }
    Networking_Core *networking() { return networking_.get(); }
    Mono_Time *mono_time() { return mono_time_.get(); }
    Logger *logger() { return logger_.get(); }

    ~WrappedMockDHT();

    static const Net_Crypto_DHT_Funcs funcs;

private:
    std::unique_ptr<tox::test::ScopedToxSystem> node_;
    std::unique_ptr<Logger, void (*)(Logger *)> logger_;
    std::unique_ptr<Mono_Time, std::function<void(Mono_Time *)>> mono_time_;
    std::unique_ptr<Networking_Core, void (*)(Networking_Core *)> networking_;
    MockDHT dht_;
};

// --- Real DHT Wrapper ---
// Wraps a DHT instance and its dependencies within a SimulatedEnvironment
class WrappedDHT {
public:
    WrappedDHT(tox::test::SimulatedEnvironment &env, std::uint16_t port);

    DHT *get_dht() { return dht_.get(); }
    const std::uint8_t *dht_public_key() const;
    const std::uint8_t *dht_secret_key() const;

    // Returns a valid IP_Port for this node in the simulation (Localhost IPv6)
    IP_Port get_ip_port() const;

    void poll();

    tox::test::ScopedToxSystem &node() { return *node_; }
    const tox::test::ScopedToxSystem &node() const { return *node_; }
    Networking_Core *networking() { return networking_.get(); }
    Mono_Time *mono_time() { return mono_time_.get(); }
    Logger *logger() { return logger_.get(); }

    ~WrappedDHT();

    static const Net_Crypto_DHT_Funcs funcs;

private:
    std::unique_ptr<tox::test::ScopedToxSystem> node_;
    std::unique_ptr<Logger, void (*)(Logger *)> logger_;
    std::unique_ptr<Mono_Time, std::function<void(Mono_Time *)>> mono_time_;
    std::unique_ptr<Networking_Core, void (*)(Networking_Core *)> networking_;
    std::unique_ptr<DHT, void (*)(DHT *)> dht_;
};

#endif  // C_TOXCORE_TOXCORE_DHT_TEST_UTIL_H
