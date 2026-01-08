#include "net_crypto.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <functional>
#include <map>
#include <memory>
#include <vector>

#include "../testing/support/public/simulated_environment.hh"
#include "DHT_test_util.hh"
#include "crypto_core.h"
#include "logger.h"
#include "mono_time.h"
#include "net_profile.h"
#include "network.h"

namespace {

using namespace tox::test;

// --- Helper Class ---

template <typename DHTWrapper>
class TestNode {
public:
    TestNode(SimulatedEnvironment &env, uint16_t port)
        : dht_wrapper_(env, port)
        , net_profile_(netprof_new(dht_wrapper_.logger(), &dht_wrapper_.node().c_memory),
              [mem = &dht_wrapper_.node().c_memory](Net_Profile *p) { netprof_kill(mem, p); })
        , net_crypto_(nullptr, [](Net_Crypto *c) { kill_net_crypto(c); })
    {
        // 3. Setup NetCrypto
        TCP_Proxy_Info proxy_info = {{0}, TCP_PROXY_NONE};
        net_crypto_.reset(new_net_crypto(dht_wrapper_.logger(), &dht_wrapper_.node().c_memory,
            &dht_wrapper_.node().c_random, &dht_wrapper_.node().c_network, dht_wrapper_.mono_time(),
            dht_wrapper_.networking(), dht_wrapper_.get_dht(), &DHTWrapper::funcs, &proxy_info,
            net_profile_.get(), true));

        // 4. Register Callbacks
        new_connection_handler(net_crypto_.get(), &TestNode::static_new_connection_cb, this);
    }

    Net_Crypto *get_net_crypto() { return net_crypto_.get(); }
    const uint8_t *dht_public_key() const { return dht_wrapper_.dht_public_key(); }
    const uint8_t *real_public_key() const { return nc_get_self_public_key(net_crypto_.get()); }

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
    bool send_data(int conn_id, const std::vector<uint8_t> &data)
    {
        // PACKET_ID_RANGE_LOSSLESS_CUSTOM_START is 160.
        // The first byte of the data passed to write_cryptpacket is the packet ID.
        // It must be in the correct range.
        if (data.empty())
            return false;

        return write_cryptpacket(net_crypto_.get(), conn_id, data.data(), data.size(), false) != -1;
    }

    // -- Observability --

    bool is_connected(int conn_id) const
    {
        if (conn_id < 0 || conn_id >= static_cast<int>(connections_.size()))
            return false;
        return connections_[conn_id].connected;
    }

    const std::vector<uint8_t> &get_last_received_data(int conn_id) const
    {
        if (conn_id < 0 || conn_id >= static_cast<int>(connections_.size()))
            return empty_vector_;
        return connections_[conn_id].received_data;
    }

    // Helper to get the ID assigned to a peer by Public Key (for the acceptor side)
    int get_connection_id_by_pk(const uint8_t *pk) { return last_accepted_id_; }

    ~TestNode();

private:
    DHTWrapper dht_wrapper_;

    struct ConnectionState {
        bool connected = false;
        std::vector<uint8_t> received_data;
    };

    // We map connection IDs to state. connection IDs are small ints.
    std::vector<ConnectionState> connections_{128};
    int last_accepted_id_ = -1;
    std::vector<uint8_t> empty_vector_;

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

    static int static_new_connection_cb(void *object, const New_Connection *n_c)
    {
        auto *self = static_cast<TestNode *>(object);
        int id = accept_crypto_connection(self->net_crypto_.get(), n_c);
        if (id != -1) {
            self->last_accepted_id_ = id;
            self->setup_connection_callbacks(id);
        }
        return id;  // Return ID on success
    }

    static int static_connection_status_cb(void *object, int id, bool status, void *userdata)
    {
        auto *self = static_cast<TestNode *>(object);
        if (id < static_cast<int>(self->connections_.size())) {
            self->connections_[id].connected = status;
        }
        return 0;
    }

    static int static_connection_data_cb(
        void *object, int id, const uint8_t *data, uint16_t length, void *userdata)
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
};

template <typename DHTWrapper>
TestNode<DHTWrapper>::~TestNode() = default;

using NetCryptoNode = TestNode<WrappedMockDHT>;
using RealDHTNode = TestNode<WrappedDHT>;

class NetCryptoTest : public ::testing::Test {
protected:
    SimulatedEnvironment env;
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
    std::vector<uint8_t> message = {160, 'H', 'e', 'l', 'l', 'o'};

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
    bool dropped = false;
    env.simulation().net().add_filter([&](tox::test::Packet &p) {
        if (!dropped && net_ntohs(p.to.port) == 33446 && p.data.size() > 0
            && p.data[0] == NET_PACKET_CRYPTO_DATA) {
            dropped = true;
            return false;  // Drop it
        }
        return true;
    });

    std::vector<uint8_t> message = {161, 'R', 'e', 't', 'r', 'y'};
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
    std::vector<uint8_t> message = {160, 'H', 'e', 'l', 'l', 'o'};

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

}  // namespace
