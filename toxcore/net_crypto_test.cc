#include "net_crypto.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <functional>
#include <map>
#include <memory>
#include <random>
#include <vector>

#include "../testing/support/public/simulated_environment.hh"
#include "DHT_test_util.hh"
#include "attributes.h"
#include "crypto_core.h"
#include "logger.h"
#include "mono_time.h"
#include "net_profile.h"
#include "network.h"
#include "test_util.hh"

namespace {

using namespace tox::test;

// --- Helper Class ---

template <typename DHTWrapper>
class TestNode {
public:
    TestNode(SimulatedEnvironment &env, std::uint16_t port,
        Crypto_Handshake_Mode mode = CRYPTO_HANDSHAKE_MODE_NOISE_BOTH, bool enable_trace = false)
        : dht_wrapper_(env, port)
        , net_profile_(netprof_new(dht_wrapper_.logger(), &dht_wrapper_.node().c_memory),
              [mem = &dht_wrapper_.node().c_memory](Net_Profile *p) { netprof_kill(mem, p); })
        , net_crypto_(nullptr, [](Net_Crypto *c) { kill_net_crypto(c); })
        , trace_enabled_(enable_trace)
    {
        // Setup Logger to stderr
        logger_callback_log(
            dht_wrapper_.logger(),
            [](void *_Nullable context, Logger_Level level, const char *_Nonnull file,
                std::uint32_t line, const char *_Nonnull func, const char *_Nonnull message,
                void *_Nullable) {
                auto *self = static_cast<TestNode *>(REQUIRE_NOT_NULL(context));
                if (self->trace_enabled_ || level >= LOGGER_LEVEL_DEBUG) {
                    fprintf(stderr, "[%d] %s:%u %s: %s\n", level, file, line, func, message);
                }
            },
            this, nullptr);

        // 3. Setup NetCrypto
        TCP_Proxy_Info proxy_info = {{0}, TCP_PROXY_NONE};
        net_crypto_.reset(new_net_crypto(dht_wrapper_.logger(), &dht_wrapper_.node().c_memory,
            &dht_wrapper_.node().c_random, &dht_wrapper_.node().c_network, dht_wrapper_.mono_time(),
            dht_wrapper_.networking(), dht_wrapper_.get_dht(), &DHTWrapper::funcs, &proxy_info,
            net_profile_.get(), mode));

        // 4. Register Callbacks
        new_connection_handler(net_crypto_.get(), &TestNode::static_new_connection_cb, this);
    }

    Net_Crypto *_Nonnull get_net_crypto() { return REQUIRE_NOT_NULL(net_crypto_.get()); }
    const std::uint8_t *_Nonnull dht_public_key() const { return dht_wrapper_.dht_public_key(); }
    const std::uint8_t *_Nonnull real_public_key() const
    {
        return nc_get_self_public_key(net_crypto_.get());
    }
    int dht_computation_count() const { return dht_wrapper_.dht_computation_count(); }
    const Memory *_Nonnull get_memory() const { return &dht_wrapper_.node().c_memory; }

    IP_Port get_ip_port() const { return dht_wrapper_.get_ip_port(); }

    void poll()
    {
        dht_wrapper_.poll();
        do_net_crypto(net_crypto_.get(), nullptr);
    }

    // -- High Level Operations --

    // Initiates a connection to 'other'. Returns the connection ID.
    template <typename OtherDHTWrapper>
    int connect_to(TestNode<OtherDHTWrapper> &other)
    {
        int id = new_crypto_connection(
            net_crypto_.get(), other.real_public_key(), other.dht_public_key());
        if (id == -1)
            return -1;

        // "Cheating" by telling net_crypto the direct IP immediately
        IP_Port addr = other.get_ip_port();
        set_direct_ip_port(net_crypto_.get(), id, &addr, true);

        // Setup monitoring for this connection
        setup_connection_callbacks(id);
        return id;
    }

    // Sends data to the connected peer (assuming only 1 for simplicity or last connected)
    bool send_data(int conn_id, const std::vector<std::uint8_t> &data)
    {
        if (data.empty())
            return false;

        return write_cryptpacket(net_crypto_.get(), conn_id, data.data(), data.size(), false) != -1;
    }

    void send_direct_packet(const IP_Port &dest, const std::vector<std::uint8_t> &data)
    {
        if (data.empty())
            return;
        sendpacket(dht_wrapper_.networking(), &dest, data.data(), data.size());
    }

    // -- Observability --

    bool is_connected(int conn_id) const
    {
        if (conn_id < 0 || conn_id >= static_cast<int>(connections_.size()))
            return false;
        return connections_[conn_id].connected;
    }

    const std::vector<std::uint8_t> &get_last_received_data(int conn_id) const
    {
        if (conn_id < 0 || conn_id >= static_cast<int>(connections_.size()))
            return empty_vector_;
        return connections_[conn_id].received_data;
    }

    // Helper to get the ID assigned to a peer by Public Key (for the acceptor side)
    int get_connection_id_by_pk(const std::uint8_t *pk) { return last_accepted_id_; }

    bool is_noise_enabled(int conn_id) const
    {
        return nc_testonly_get_noise_enabled(net_crypto_.get(), conn_id);
    }

    ~TestNode();

private:
    DHTWrapper dht_wrapper_;

    struct ConnectionState {
        bool connected = false;
        std::vector<std::uint8_t> received_data;
    };

    // We map connection IDs to state. connection IDs are small ints.
    std::vector<ConnectionState> connections_{128};
    int last_accepted_id_ = -1;
    std::vector<std::uint8_t> empty_vector_;

    void setup_connection_callbacks(int id)
    {
        if (id >= static_cast<int>(connections_.size()))
            connections_.resize(id + 1);

        connection_status_handler(
            net_crypto_.get(), id, &TestNode::static_connection_status_cb, this, id);
        connection_data_handler(
            net_crypto_.get(), id, &TestNode::static_connection_data_cb, this, id);
    }

    // -- Static Callbacks --

    static int static_new_connection_cb(void *_Nonnull object, const New_Connection *_Nonnull n_c)
    {
        auto *self = static_cast<TestNode *>(object);
        int id = accept_crypto_connection(self->net_crypto_.get(), n_c);
        if (id != -1) {
            self->last_accepted_id_ = id;
            self->setup_connection_callbacks(id);
        }
        return id;  // Return ID on success
    }

    static int static_connection_status_cb(
        void *_Nonnull object, int id, bool status, void *_Nullable userdata)
    {
        auto *self = static_cast<TestNode *>(object);
        if (id < static_cast<int>(self->connections_.size())) {
            self->connections_[id].connected = status;
        }
        return 0;
    }

    static int static_connection_data_cb(void *_Nonnull object, int id,
        const std::uint8_t *_Nonnull data, std::uint16_t length, void *_Nullable userdata)
    {
        auto *self = static_cast<TestNode *>(object);
        if (id < static_cast<int>(self->connections_.size())) {
            self->connections_[id].received_data.assign(data, data + length);
        }
        return 0;
    }

    // Use std::function for the deleter to allow capturing memory pointer
    std::unique_ptr<Net_Profile, std::function<void(Net_Profile *)>> net_profile_;
    std::unique_ptr<Net_Crypto, void (*)(Net_Crypto *)> net_crypto_;
    bool trace_enabled_ = false;
};

template <typename DHTWrapper>
TestNode<DHTWrapper>::~TestNode() = default;

using NetCryptoNode = TestNode<WrappedMockDHT>;
using RealDHTNode = TestNode<WrappedDHT>;

class NetCryptoTest : public ::testing::Test {
protected:
    SimulatedEnvironment env{12345};
};

TEST_F(NetCryptoTest, EndToEndDataExchange)
{
    NetCryptoNode alice(env, 33445);
    NetCryptoNode bob(env, 33446);

    // 1. Alice initiates connection to Bob
    int alice_conn_id = alice.connect_to(bob);
    ASSERT_NE(alice_conn_id, -1);

    // 2. Run simulation until connected
    auto start = env.clock().current_time_ms();
    int bob_conn_id = -1;
    bool connected = false;

    while ((env.clock().current_time_ms() - start) < 5000) {
        alice.poll();
        bob.poll();
        env.advance_time(10);  // 10ms steps

        bob_conn_id = bob.get_connection_id_by_pk(alice.real_public_key());
        if (alice.is_connected(alice_conn_id) && bob_conn_id != -1
            && bob.is_connected(bob_conn_id)) {
            connected = true;
            break;
        }
    }

    ASSERT_TRUE(connected) << "Failed to establish connection within timeout";

    // 3. Exchange Data
    // Packet ID must be in custom range (160+)
    std::vector<std::uint8_t> message = {160, 'H', 'e', 'l', 'l', 'o'};

    EXPECT_TRUE(alice.send_data(alice_conn_id, message));

    start = env.clock().current_time_ms();
    bool data_received = false;
    while ((env.clock().current_time_ms() - start) < 1000) {
        alice.poll();
        bob.poll();
        env.advance_time(10);

        if (bob.get_last_received_data(bob_conn_id) == message) {
            data_received = true;
            break;
        }
    }

    EXPECT_TRUE(data_received) << "Bob did not receive the correct data";
}

TEST_F(NetCryptoTest, ConnectionTimeout)
{
    NetCryptoNode alice(env, 33445);
    NetCryptoNode bob(env, 33446);

    // Alice tries to connect to Bob
    int alice_conn_id = alice.connect_to(bob);
    ASSERT_NE(alice_conn_id, -1);

    // Filter: Drop ALL packets from Bob to Alice
    env.simulation().net().add_filter([&](tox::test::Packet &p) {
        // Drop if destination is Alice (33445)
        if (net_ntohs(p.to.port) == 33445) {
            return false;
        }
        return true;
    });

    // Run simulation for longer than timeout (approx 8-10s)
    auto start = env.clock().current_time_ms();
    bool timeout_detected = false;

    // expect Alice to kill the connection after MAX_NUM_SENDPACKET_TRIES * INTERVAL (8*1s=8s).
    //
    // Run for 15 seconds to be safe
    while ((env.clock().current_time_ms() - start) < 15000) {
        alice.poll();
        bob.poll();
        env.advance_time(100);

        bool direct;
        if (!crypto_connection_status(alice.get_net_crypto(), alice_conn_id, &direct, nullptr)) {
            timeout_detected = true;
            break;
        }
    }

    EXPECT_TRUE(timeout_detected) << "Alice should have killed the timed-out connection";
}

TEST_F(NetCryptoTest, DataLossAndRetransmission)
{
    bool dropped = false;
    NetCryptoNode alice(env, 33445);
    NetCryptoNode bob(env, 33446);

    int alice_conn_id = alice.connect_to(bob);
    ASSERT_NE(alice_conn_id, -1);

    // Establish connection
    auto start = env.clock().current_time_ms();
    int bob_conn_id = -1;
    bool connected = false;

    while ((env.clock().current_time_ms() - start) < 5000) {
        alice.poll();
        bob.poll();
        env.advance_time(10);

        bob_conn_id = bob.get_connection_id_by_pk(alice.real_public_key());
        if (alice.is_connected(alice_conn_id) && bob_conn_id != -1
            && bob.is_connected(bob_conn_id)) {
            connected = true;
            break;
        }
    }
    ASSERT_TRUE(connected);

    // Configure network to drop the next packet from Alice
    // NET_PACKET_CRYPTO_DATA is 0x1b
    // We want to drop the *first* data packet sent.
    env.simulation().net().add_filter([&](tox::test::Packet &p) {
        if (!dropped && net_ntohs(p.to.port) == 33446 && p.data.size() > 0
            && p.data[0] == NET_PACKET_CRYPTO_DATA) {
            dropped = true;
            return false;  // Drop it
        }
        return true;
    });

    std::vector<std::uint8_t> message = {161, 'R', 'e', 't', 'r', 'y'};
    alice.send_data(alice_conn_id, message);

    // Alice needs to detect packet loss and retransmit.
    // Timeout for retransmission is tricky, it depends on RTT estimation.
    // Default RTT is 1s.

    start = env.clock().current_time_ms();
    bool data_received = false;
    while ((env.clock().current_time_ms() - start) < 5000) {
        alice.poll();
        bob.poll();
        env.advance_time(50);  // coarser steps

        if (bob.get_last_received_data(bob_conn_id) == message) {
            data_received = true;
            break;
        }
    }

    EXPECT_TRUE(dropped) << "Packet filter failed to target the data packet";
    EXPECT_TRUE(data_received) << "Bob failed to receive data after retransmission";
}

TEST_F(NetCryptoTest, CookieRequestCPUExhaustion)
{
    NetCryptoNode victim(env, 33445);
    NetCryptoNode attacker(env, 33446);

    // Cookie Request Packet Length
    // From net_crypto.c:
    // #define COOKIE_REQUEST_LENGTH (std::uint16_t)(1 + CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_NONCE_SIZE
    // + COOKIE_REQUEST_PLAIN_LENGTH + CRYPTO_MAC_SIZE) 1 + 32 + 24 + (32 * 2 + 8) + 16 = 145
    const int TEST_COOKIE_REQUEST_LENGTH = 145;

    // Send enough packets to trigger rate limiting
    const int NUM_PACKETS = 50;

    std::minstd_rand rng(42);
    std::uniform_int_distribution<unsigned int> dist(0, 255);
    auto gen = [&]() { return static_cast<std::uint8_t>(dist(rng)); };

    for (int i = 0; i < NUM_PACKETS; ++i) {
        std::vector<std::uint8_t> packet(TEST_COOKIE_REQUEST_LENGTH);
        packet[0] = NET_PACKET_COOKIE_REQUEST;

        // Random public key at offset 1 (size 32)
        std::generate(packet.begin() + 1, packet.begin() + 1 + CRYPTO_PUBLIC_KEY_SIZE, gen);

        // Fill the rest with random data just to be safe
        std::generate(packet.begin() + 1 + CRYPTO_PUBLIC_KEY_SIZE, packet.end(), gen);

        attacker.send_direct_packet(victim.get_ip_port(), packet);

        // Advance time to allow network delivery
        env.advance_time(1);
        victim.poll();
    }

    // Verify that the victim performed some computations (as it must for the first few packets)
    // but filtered out the majority of the flood due to rate limiting.
    int computations = victim.dht_computation_count();
    EXPECT_GT(computations, 0) << "Should handle at least some packets";
    EXPECT_LT(computations, NUM_PACKETS) << "Victim performed expensive shared key computations "
                                            "for ALL packets! CPU exhaustion mitigation failed.";
}

TEST_F(NetCryptoTest, CookieRequestRateLimiting)
{
    NetCryptoNode victim(env, 33445);
    NetCryptoNode attacker(env, 33446);

    const int TEST_COOKIE_REQUEST_LENGTH = 145;
    std::minstd_rand rng(42);
    std::uniform_int_distribution<unsigned int> dist(0, 255);
    auto gen = [&]() { return static_cast<std::uint8_t>(dist(rng)); };

    auto send_packet = [&]() {
        std::vector<std::uint8_t> packet(TEST_COOKIE_REQUEST_LENGTH);
        packet[0] = NET_PACKET_COOKIE_REQUEST;
        std::generate(packet.begin() + 1, packet.begin() + 1 + CRYPTO_PUBLIC_KEY_SIZE, gen);
        std::generate(packet.begin() + 1 + CRYPTO_PUBLIC_KEY_SIZE, packet.end(), gen);
        attacker.send_direct_packet(victim.get_ip_port(), packet);
        env.advance_time(1);  // Network delivery
        victim.poll();
    };

    // 1. Initial Burst: Consume all 10 tokens
    int initial_computations = victim.dht_computation_count();
    for (int i = 0; i < 10; ++i) {
        send_packet();
    }
    int burst_computations = victim.dht_computation_count();
    EXPECT_EQ(burst_computations - initial_computations, 10)
        << "Should accept initial burst of 10 packets";

    // 2. Verify Limit Reached: 11th packet should be dropped
    send_packet();
    EXPECT_EQ(victim.dht_computation_count(), burst_computations) << "Should drop 11th packet";

    // 3. Partial Refill Check: Advance 80ms (total < 100ms since empty)
    env.advance_time(80);
    send_packet();
    EXPECT_EQ(victim.dht_computation_count(), burst_computations)
        << "Should drop packet before 100ms refill";

    // 4. Full Refill Check: Advance to > 100ms
    env.advance_time(20);
    send_packet();
    EXPECT_EQ(victim.dht_computation_count(), burst_computations + 1)
        << "Should accept packet after 100ms refill";
}

TEST_F(NetCryptoTest, HandleRequestPacketOOB)
{
    NetCryptoNode alice(env, 33445);
    NetCryptoNode bob(env, 33446);

    // 1. Establish connection
    int alice_conn_id = alice.connect_to(bob);
    ASSERT_NE(alice_conn_id, -1);

    auto start = env.clock().current_time_ms();
    int bob_conn_id = -1;
    bool connected = false;

    while ((env.clock().current_time_ms() - start) < 5000) {
        alice.poll();
        bob.poll();
        env.advance_time(10);

        bob_conn_id = bob.get_connection_id_by_pk(alice.real_public_key());
        if (alice.is_connected(alice_conn_id) && bob_conn_id != -1
            && bob.is_connected(bob_conn_id)) {
            connected = true;
            break;
        }
    }
    ASSERT_TRUE(connected);

    // 2. Alice sends many packets to populate her send_array.
    std::vector<std::uint8_t> dummy_data(50, 'A');
    for (int i = 0; i < 300; ++i) {
        dummy_data[0] = 160 + (i % 30);  // Valid packet ID range
        alice.send_data(alice_conn_id, dummy_data);
    }
    alice.poll();  // Process sends

    // 3. Construct the malicious packet.
    std::uint8_t shared_key[CRYPTO_SHARED_KEY_SIZE];
    std::uint8_t alice_sent_nonce[CRYPTO_NONCE_SIZE];
    std::uint8_t alice_recv_nonce[CRYPTO_NONCE_SIZE];

    // Retrieve secrets
    nc_testonly_get_secrets(
        alice.get_net_crypto(), alice_conn_id, shared_key, alice_sent_nonce, alice_recv_nonce);

    // Use Alice's recv_nonce (which Bob uses to encrypt)
    std::uint8_t nonce[CRYPTO_NONCE_SIZE];
    std::memcpy(nonce, alice_recv_nonce, CRYPTO_NONCE_SIZE);

    // Payload: [PACKET_ID_REQUEST (1), 255]
    // The length of 2 will trigger the OOB read when n wraps around.
    std::uint8_t plaintext[] = {PACKET_ID_REQUEST, 255};
    std::uint16_t plaintext_len = sizeof(plaintext);

    std::uint16_t packet_size = 1 + sizeof(std::uint16_t) + plaintext_len + CRYPTO_MAC_SIZE;
    std::vector<std::uint8_t> malicious_packet(packet_size);

    malicious_packet[0] = NET_PACKET_CRYPTO_DATA;
    std::memcpy(&malicious_packet[1], nonce + (CRYPTO_NONCE_SIZE - sizeof(std::uint16_t)),
        sizeof(std::uint16_t));

    int len = encrypt_data_symmetric(
        alice.get_memory(), shared_key, nonce, plaintext, plaintext_len, &malicious_packet[3]);
    ASSERT_EQ(len, plaintext_len + CRYPTO_MAC_SIZE);

    // 4. Inject the packet
    tox::test::Packet p{};
    p.to = alice.get_ip_port();
    p.data = malicious_packet;
    p.from = bob.get_ip_port();

    env.simulation().net().send_packet(p);

    // 5. Trigger processing - Expect ASAN/UBSAN failure if vulnerable
    alice.poll();
}

// Test with Real DHT (but fake network) to ensure integration works
TEST_F(NetCryptoTest, EndToEndDataExchange_RealDHT)
{
    RealDHTNode alice(env, 33445);
    RealDHTNode bob(env, 33446);

    // 1. Alice initiates connection to Bob
    int alice_conn_id = alice.connect_to(bob);
    ASSERT_NE(alice_conn_id, -1);

    // 2. Run simulation until connected
    auto start = env.clock().current_time_ms();
    int bob_conn_id = -1;
    bool connected = false;

    while ((env.clock().current_time_ms() - start) < 5000) {
        alice.poll();
        bob.poll();
        env.advance_time(10);  // 10ms steps

        bob_conn_id = bob.get_connection_id_by_pk(alice.real_public_key());
        if (alice.is_connected(alice_conn_id) && bob_conn_id != -1
            && bob.is_connected(bob_conn_id)) {
            connected = true;
            break;
        }
    }

    ASSERT_TRUE(connected) << "Failed to establish connection within timeout";

    // 3. Exchange Data
    // Packet ID must be in custom range (160+)
    std::vector<std::uint8_t> message = {160, 'H', 'e', 'l', 'l', 'o'};

    EXPECT_TRUE(alice.send_data(alice_conn_id, message));

    start = env.clock().current_time_ms();
    bool data_received = false;
    while ((env.clock().current_time_ms() - start) < 1000) {
        alice.poll();
        bob.poll();
        env.advance_time(10);

        if (bob.get_last_received_data(bob_conn_id) == message) {
            data_received = true;
            break;
        }
    }

    EXPECT_TRUE(data_received) << "Bob did not receive the correct data";
}

// --- Handshake Mode Integration Tests ---

// Helper: run until both sides are connected, return true on success.
template <typename NodeA, typename NodeB>
bool wait_for_connection(SimulatedEnvironment &env, NodeA &a, int a_conn_id, NodeB &b,
    int &b_conn_id, std::uint64_t timeout_ms = 5000)
{
    auto start = env.clock().current_time_ms();
    while ((env.clock().current_time_ms() - start) < timeout_ms) {
        a.poll();
        b.poll();
        env.advance_time(10);

        b_conn_id = b.get_connection_id_by_pk(a.real_public_key());
        if (a.is_connected(a_conn_id) && b_conn_id != -1 && b.is_connected(b_conn_id)) {
            return true;
        }
    }
    return false;
}

// Helper: send data from a to b, wait for delivery, return true on success.
template <typename NodeA, typename NodeB>
bool exchange_data(SimulatedEnvironment &env, NodeA &a, int a_conn_id, NodeB &b, int b_conn_id,
    const std::vector<std::uint8_t> &message, std::uint64_t timeout_ms = 2000)
{
    if (!a.send_data(a_conn_id, message)) {
        return false;
    }
    auto start = env.clock().current_time_ms();
    while ((env.clock().current_time_ms() - start) < timeout_ms) {
        a.poll();
        b.poll();
        env.advance_time(10);
        if (b.get_last_received_data(b_conn_id) == message) {
            return true;
        }
    }
    return false;
}

TEST_F(NetCryptoTest, NoiseHandshakeDataExchange)
{
    NetCryptoNode alice(env, 33445, CRYPTO_HANDSHAKE_MODE_NOISE_BOTH);
    NetCryptoNode bob(env, 33446, CRYPTO_HANDSHAKE_MODE_NOISE_BOTH);

    int alice_conn_id = alice.connect_to(bob);
    ASSERT_NE(alice_conn_id, -1);

    int bob_conn_id = -1;
    ASSERT_TRUE(wait_for_connection(env, alice, alice_conn_id, bob, bob_conn_id));

    // Both should have used Noise handshake
    EXPECT_TRUE(alice.is_noise_enabled(alice_conn_id));
    EXPECT_TRUE(bob.is_noise_enabled(bob_conn_id));

    // Exchange data
    std::vector<std::uint8_t> message = {160, 'N', 'o', 'i', 's', 'e'};
    EXPECT_TRUE(exchange_data(env, alice, alice_conn_id, bob, bob_conn_id, message));
}

TEST_F(NetCryptoTest, LegacyHandshakeDataExchange)
{
    NetCryptoNode alice(env, 33445, CRYPTO_HANDSHAKE_MODE_LEGACY_ONLY);
    NetCryptoNode bob(env, 33446, CRYPTO_HANDSHAKE_MODE_LEGACY_ONLY);

    int alice_conn_id = alice.connect_to(bob);
    ASSERT_NE(alice_conn_id, -1);

    int bob_conn_id = -1;
    ASSERT_TRUE(wait_for_connection(env, alice, alice_conn_id, bob, bob_conn_id));

    // Both should have used legacy handshake
    EXPECT_FALSE(alice.is_noise_enabled(alice_conn_id));
    EXPECT_FALSE(bob.is_noise_enabled(bob_conn_id));

    // Exchange data
    std::vector<std::uint8_t> message = {160, 'L', 'e', 'g', 'a', 'c', 'y'};
    EXPECT_TRUE(exchange_data(env, alice, alice_conn_id, bob, bob_conn_id, message));
}

TEST_F(NetCryptoTest, NoiseToLegacyFallback)
{
    // One NOISE_BOTH node connects to one LEGACY_ONLY node.
    // Both sides initiate (mirrors real friend_connection behavior).
    // Bob's legacy handshake triggers Alice to fall back from Noise.
    NetCryptoNode alice(env, 33445, CRYPTO_HANDSHAKE_MODE_NOISE_BOTH);
    NetCryptoNode bob(env, 33446, CRYPTO_HANDSHAKE_MODE_LEGACY_ONLY);

    int alice_conn_id = alice.connect_to(bob);
    ASSERT_NE(alice_conn_id, -1);

    // Bob also initiates (as friend_connection would do bidirectionally)
    int bob_conn_id_init = bob.connect_to(alice);
    ASSERT_NE(bob_conn_id_init, -1);

    // Run until connected
    auto start = env.clock().current_time_ms();
    bool connected = false;
    int bob_conn_id = -1;
    while ((env.clock().current_time_ms() - start) < 10000) {
        alice.poll();
        bob.poll();
        env.advance_time(10);

        // Check both possible connection IDs on Bob's side
        if (alice.is_connected(alice_conn_id)) {
            // Bob may have connected via his initiated connection or accepted Alice's
            if (bob.is_connected(bob_conn_id_init)) {
                bob_conn_id = bob_conn_id_init;
                connected = true;
                break;
            }
            int bob_accepted = bob.get_connection_id_by_pk(alice.real_public_key());
            if (bob_accepted != -1 && bob.is_connected(bob_accepted)) {
                bob_conn_id = bob_accepted;
                connected = true;
                break;
            }
        }
    }

    ASSERT_TRUE(connected) << "Noise-to-legacy fallback should succeed";

    // Both should have fallen back to legacy
    EXPECT_FALSE(alice.is_noise_enabled(alice_conn_id));
    EXPECT_FALSE(bob.is_noise_enabled(bob_conn_id));

    // Exchange data
    std::vector<std::uint8_t> message = {160, 'F', 'a', 'l', 'l'};
    EXPECT_TRUE(exchange_data(env, alice, alice_conn_id, bob, bob_conn_id, message));
}

TEST_F(NetCryptoTest, NoiseSimultaneousOpen)
{
    NetCryptoNode alice(env, 33445, CRYPTO_HANDSHAKE_MODE_NOISE_BOTH);
    NetCryptoNode bob(env, 33446, CRYPTO_HANDSHAKE_MODE_NOISE_BOTH);

    // Both sides initiate simultaneously
    int alice_conn_id = alice.connect_to(bob);
    int bob_conn_id_init = bob.connect_to(alice);
    ASSERT_NE(alice_conn_id, -1);
    ASSERT_NE(bob_conn_id_init, -1);

    // Run until at least one side is connected
    auto start = env.clock().current_time_ms();
    bool connected = false;
    while ((env.clock().current_time_ms() - start) < 5000) {
        alice.poll();
        bob.poll();
        env.advance_time(10);

        if (alice.is_connected(alice_conn_id) && bob.is_connected(bob_conn_id_init)) {
            connected = true;
            break;
        }
        // Also check if bob accepted alice's connection
        int bob_accepted = bob.get_connection_id_by_pk(alice.real_public_key());
        if (alice.is_connected(alice_conn_id) && bob_accepted != -1
            && bob.is_connected(bob_accepted)) {
            connected = true;
            break;
        }
    }

    ASSERT_TRUE(connected) << "Simultaneous open should succeed";

    // Exchange data (use alice's initiated connection)
    std::vector<std::uint8_t> message = {160, 'S', 'i', 'm'};
    // Try sending from Alice; Bob may have accepted via callback
    int bob_conn_id = bob.get_connection_id_by_pk(alice.real_public_key());
    if (bob_conn_id != -1 && bob.is_connected(bob_conn_id)) {
        EXPECT_TRUE(exchange_data(env, alice, alice_conn_id, bob, bob_conn_id, message));
    }
}

TEST_F(NetCryptoTest, NoiseHandshakePacketLoss)
{
    NetCryptoNode alice(env, 33445, CRYPTO_HANDSHAKE_MODE_NOISE_BOTH);
    NetCryptoNode bob(env, 33446, CRYPTO_HANDSHAKE_MODE_NOISE_BOTH);

    // Drop the first NET_PACKET_CRYPTO_HS packet
    bool dropped = false;
    env.simulation().net().add_filter([&](tox::test::Packet &p) {
        if (!dropped && p.data.size() > 0 && p.data[0] == NET_PACKET_CRYPTO_HS) {
            dropped = true;
            return false;  // Drop it
        }
        return true;
    });

    int alice_conn_id = alice.connect_to(bob);
    ASSERT_NE(alice_conn_id, -1);

    int bob_conn_id = -1;
    // Allow more time for retransmission (handshake retransmit interval ~1s)
    ASSERT_TRUE(wait_for_connection(env, alice, alice_conn_id, bob, bob_conn_id, 10000))
        << "Handshake should succeed after retransmission";
    EXPECT_TRUE(dropped) << "Filter should have dropped a handshake packet";

    // Exchange data
    std::vector<std::uint8_t> message = {160, 'R', 'e', 't', 'r', 'y'};
    EXPECT_TRUE(exchange_data(env, alice, alice_conn_id, bob, bob_conn_id, message));
}

// --- Security Regression Tests ---

// Compute legacy HANDSHAKE_PACKET_LENGTH from public constants.
// COOKIE_LENGTH = NONCE + sizeof(uint64_t) + 2*PK + MAC = 24+8+64+16 = 112
constexpr std::size_t kCookieLength
    = CRYPTO_NONCE_SIZE + sizeof(std::uint64_t) + CRYPTO_PUBLIC_KEY_SIZE * 2 + CRYPTO_MAC_SIZE;
constexpr std::size_t kLegacyHandshakePacketLength = 1 + kCookieLength + CRYPTO_NONCE_SIZE
    + CRYPTO_NONCE_SIZE + CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_SHA512_SIZE + kCookieLength
    + CRYPTO_MAC_SIZE;

// A NOISE_BOTH node must not destroy its Noise handshake state when it receives
// an invalid packet that happens to be legacy handshake length. The Noise state
// must survive so the handshake can complete via retransmission.
TEST_F(NetCryptoTest, NoiseStateSurvivesGarbageLegacyLengthPacket)
{
    NetCryptoNode alice(env, 33445, CRYPTO_HANDSHAKE_MODE_NOISE_BOTH);
    NetCryptoNode bob(env, 33446, CRYPTO_HANDSHAKE_MODE_NOISE_BOTH);

    int alice_conn_id = alice.connect_to(bob);
    ASSERT_NE(alice_conn_id, -1);

    // Replace the first CRYPTO_HS packet arriving at Alice (Bob's response) with
    // garbage of exactly legacy handshake length. The first CRYPTO_HS on the wire
    // is Alice's initiator HS to Bob; the second is Bob's response to Alice.
    int hs_count = 0;
    bool injected = false;
    env.simulation().net().add_filter([&](tox::test::Packet &p) {
        if (p.data.size() > 0 && p.data[0] == NET_PACKET_CRYPTO_HS) {
            ++hs_count;
            if (hs_count == 2 && !injected) {
                p.data.assign(kLegacyHandshakePacketLength, 0xAA);
                p.data[0] = NET_PACKET_CRYPTO_HS;
                injected = true;
            }
        }
        return true;
    });

    int bob_conn_id = -1;
    ASSERT_TRUE(wait_for_connection(env, alice, alice_conn_id, bob, bob_conn_id, 10000))
        << "Noise handshake must recover after receiving a garbage legacy-length packet";
    EXPECT_TRUE(injected) << "Filter should have injected a garbage packet";

    // Connection completed via Noise (not downgraded to legacy).
    EXPECT_TRUE(alice.is_noise_enabled(alice_conn_id));
    EXPECT_TRUE(bob.is_noise_enabled(bob_conn_id));

    std::vector<std::uint8_t> message = {160, 'O', 'K'};
    EXPECT_TRUE(exchange_data(env, alice, alice_conn_id, bob, bob_conn_id, message));
}

// Two nodes with the same identity key attempting simultaneous open must not
// deadlock. The connection should be cleanly rejected (self-connection).
TEST_F(NetCryptoTest, SimultaneousOpenEqualKeysIsRejected)
{
    NetCryptoNode alice(env, 33445, CRYPTO_HANDSHAKE_MODE_NOISE_BOTH);
    NetCryptoNode bob(env, 33446, CRYPTO_HANDSHAKE_MODE_NOISE_BOTH);

    // Give both nodes the same identity key.
    std::uint8_t shared_sk[CRYPTO_SECRET_KEY_SIZE];
    std::memset(shared_sk, 42, CRYPTO_SECRET_KEY_SIZE);
    load_secret_key(alice.get_net_crypto(), shared_sk);
    load_secret_key(bob.get_net_crypto(), shared_sk);
    ASSERT_EQ(
        std::memcmp(alice.real_public_key(), bob.real_public_key(), CRYPTO_PUBLIC_KEY_SIZE), 0);

    // Both sides initiate simultaneously.
    int alice_conn_id = alice.connect_to(bob);
    int bob_conn_id_init = bob.connect_to(alice);
    ASSERT_NE(alice_conn_id, -1);
    ASSERT_NE(bob_conn_id_init, -1);

    // Neither side should reach CONNECTED — the equal-key case must be detected
    // and the connection rejected rather than silently deadlocking.
    auto start = env.clock().current_time_ms();
    bool connected = false;
    while ((env.clock().current_time_ms() - start) < 10000) {
        alice.poll();
        bob.poll();
        env.advance_time(10);

        if (alice.is_connected(alice_conn_id) || bob.is_connected(bob_conn_id_init)) {
            connected = true;
            break;
        }
    }

    EXPECT_FALSE(connected)
        << "Equal-key nodes must not establish a connection";
}

}  // namespace
