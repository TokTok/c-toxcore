#include "onion_client.h"

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
#include "net_crypto.h"
#include "net_profile.h"
#include "network.h"

namespace {

using namespace tox::test;

// --- Helper Class ---

template <typename DHTWrapper>
class OnionTestNode {
public:
    OnionTestNode(SimulatedEnvironment &env, uint16_t port)
        : dht_wrapper_(env, port)
        , net_profile_(netprof_new(dht_wrapper_.logger(), &dht_wrapper_.node().c_memory),
              [mem = &dht_wrapper_.node().c_memory](Net_Profile *p) { netprof_kill(mem, p); })
        , net_crypto_(nullptr, [](Net_Crypto *c) { kill_net_crypto(c); })
        , onion_client_(nullptr, [](Onion_Client *c) { kill_onion_client(c); })
    {
        // Setup NetCrypto
        TCP_Proxy_Info proxy_info = {{0}, TCP_PROXY_NONE};
        net_crypto_.reset(new_net_crypto(dht_wrapper_.logger(), &dht_wrapper_.node().c_memory,
            &dht_wrapper_.node().c_random, &dht_wrapper_.node().c_network, dht_wrapper_.mono_time(),
            dht_wrapper_.networking(), dht_wrapper_.get_dht(), &DHTWrapper::funcs, &proxy_info,
            net_profile_.get(), true));

        // Setup Onion Client
        onion_client_.reset(new_onion_client(dht_wrapper_.logger(), &dht_wrapper_.node().c_memory,
            &dht_wrapper_.node().c_random, dht_wrapper_.mono_time(), net_crypto_.get(),
            dht_wrapper_.get_dht(), dht_wrapper_.networking()));
    }

    Onion_Client *get_onion_client() { return onion_client_.get(); }
    Net_Crypto *get_net_crypto() { return net_crypto_.get(); }
    DHT *get_dht() { return dht_wrapper_.get_dht(); }
    const uint8_t *dht_public_key() const { return dht_wrapper_.dht_public_key(); }
    const uint8_t *real_public_key() const { return nc_get_self_public_key(net_crypto_.get()); }
    const Random *get_random() { return &dht_wrapper_.node().c_random; }

    IP_Port get_ip_port() const { return dht_wrapper_.get_ip_port(); }

    void poll()
    {
        dht_wrapper_.poll();
        do_net_crypto(net_crypto_.get(), nullptr);
        do_onion_client(onion_client_.get());
    }

    ~OnionTestNode();

private:
    DHTWrapper dht_wrapper_;
    std::unique_ptr<Net_Profile, std::function<void(Net_Profile *)>> net_profile_;
    std::unique_ptr<Net_Crypto, void (*)(Net_Crypto *)> net_crypto_;
    std::unique_ptr<Onion_Client, void (*)(Onion_Client *)> onion_client_;
};

template <typename DHTWrapper>
OnionTestNode<DHTWrapper>::~OnionTestNode() = default;

using OnionNode = OnionTestNode<WrappedDHT>;

class OnionClientTest : public ::testing::Test {
protected:
    SimulatedEnvironment env;
};

TEST_F(OnionClientTest, CreationAndDestruction)
{
    OnionNode alice(env, 33445);
    EXPECT_NE(alice.get_onion_client(), nullptr);
}

TEST_F(OnionClientTest, FriendManagement)
{
    OnionNode alice(env, 33445);
    uint8_t friend_pk[CRYPTO_PUBLIC_KEY_SIZE];
    uint8_t friend_sk[CRYPTO_SECRET_KEY_SIZE];
    crypto_new_keypair(alice.get_random(), friend_pk, friend_sk);

    // Add Friend
    int friend_num = onion_addfriend(alice.get_onion_client(), friend_pk);
    ASSERT_NE(friend_num, -1);

    // Check Friend Num
    EXPECT_EQ(onion_friend_num(alice.get_onion_client(), friend_pk), friend_num);

    // Add Same Friend Again
    EXPECT_EQ(onion_addfriend(alice.get_onion_client(), friend_pk), friend_num);

    // Check Friend Count
    EXPECT_EQ(onion_get_friend_count(alice.get_onion_client()), 1);

    // Delete Friend
    EXPECT_NE(onion_delfriend(alice.get_onion_client(), friend_num), -1);
    EXPECT_EQ(onion_get_friend_count(alice.get_onion_client()), 0);

    // Check Friend Num after deletion
    EXPECT_EQ(onion_friend_num(alice.get_onion_client(), friend_pk), -1);

    // Delete Invalid Friend
    EXPECT_EQ(onion_delfriend(alice.get_onion_client(), friend_num), -1);
}

TEST_F(OnionClientTest, FriendStatus)
{
    OnionNode alice(env, 33445);
    uint8_t friend_pk[CRYPTO_PUBLIC_KEY_SIZE];
    uint8_t friend_sk[CRYPTO_SECRET_KEY_SIZE];
    crypto_new_keypair(alice.get_random(), friend_pk, friend_sk);

    int friend_num = onion_addfriend(alice.get_onion_client(), friend_pk);
    ASSERT_NE(friend_num, -1);

    // Set DHT Key so we can get IP
    uint8_t dht_key[CRYPTO_PUBLIC_KEY_SIZE];
    crypto_new_keypair(alice.get_random(), dht_key, friend_sk);
    EXPECT_EQ(onion_set_friend_dht_pubkey(alice.get_onion_client(), friend_num, dht_key), 0);

    uint32_t lock_token;
    EXPECT_EQ(
        dht_addfriend(alice.get_dht(), dht_key, nullptr, nullptr, friend_num, &lock_token), 0);

    // Set Online
    EXPECT_EQ(onion_set_friend_online(alice.get_onion_client(), friend_num, true), 0);

    // Get Friend IP (should be 0 as not connected)
    IP_Port ip;
    EXPECT_EQ(onion_getfriendip(alice.get_onion_client(), friend_num, &ip), 0);

    // Set Offline
    EXPECT_EQ(onion_set_friend_online(alice.get_onion_client(), friend_num, false), 0);

    // Invalid friend num
    EXPECT_EQ(onion_set_friend_online(alice.get_onion_client(), 12345, true), -1);
}

TEST_F(OnionClientTest, DHTKey)
{
    OnionNode alice(env, 33445);
    uint8_t friend_pk[CRYPTO_PUBLIC_KEY_SIZE];
    uint8_t friend_sk[CRYPTO_SECRET_KEY_SIZE];
    crypto_new_keypair(alice.get_random(), friend_pk, friend_sk);

    int friend_num = onion_addfriend(alice.get_onion_client(), friend_pk);
    ASSERT_NE(friend_num, -1);

    uint8_t dht_key[CRYPTO_PUBLIC_KEY_SIZE];
    crypto_new_keypair(alice.get_random(), dht_key, friend_sk);

    // Set DHT Key
    EXPECT_EQ(onion_set_friend_dht_pubkey(alice.get_onion_client(), friend_num, dht_key), 0);

    // Get DHT Key
    uint8_t retrieved_key[CRYPTO_PUBLIC_KEY_SIZE];
    EXPECT_EQ(onion_getfriend_dht_pubkey(alice.get_onion_client(), friend_num, retrieved_key), 1);
    EXPECT_EQ(std::memcmp(dht_key, retrieved_key, CRYPTO_PUBLIC_KEY_SIZE), 0);

    // Invalid friend
    EXPECT_EQ(onion_set_friend_dht_pubkey(alice.get_onion_client(), 12345, dht_key), -1);
    EXPECT_EQ(onion_getfriend_dht_pubkey(alice.get_onion_client(), 12345, retrieved_key), 0);
}

TEST_F(OnionClientTest, BootstrapNodes)
{
    OnionNode alice(env, 33445);
    IP_Port ip_port;
    ip_init(&ip_port.ip, 1);
    ip_port.port = 1234;
    uint8_t pk[CRYPTO_PUBLIC_KEY_SIZE];
    crypto_new_keypair(alice.get_random(), pk, pk);

    EXPECT_TRUE(onion_add_bs_path_node(alice.get_onion_client(), &ip_port, pk));

    Node_format nodes[MAX_ONION_CLIENTS];
    uint16_t count = onion_backup_nodes(alice.get_onion_client(), nodes, MAX_ONION_CLIENTS);
    EXPECT_GE(count, 0);
}

TEST_F(OnionClientTest, ConnectionStatus)
{
    OnionNode alice(env, 33445);
    Onion_Connection_Status status = onion_connection_status(alice.get_onion_client());
    EXPECT_GE(status, ONION_CONNECTION_STATUS_NONE);
    EXPECT_LE(status, ONION_CONNECTION_STATUS_UDP);
}

TEST_F(OnionClientTest, GroupChatHelpers)
{
    OnionNode alice(env, 33445);
    uint8_t friend_pk[CRYPTO_PUBLIC_KEY_SIZE];
    uint8_t friend_sk[CRYPTO_SECRET_KEY_SIZE];
    crypto_new_keypair(alice.get_random(), friend_pk, friend_sk);

    int friend_num = onion_addfriend(alice.get_onion_client(), friend_pk);
    ASSERT_NE(friend_num, -1);

    Onion_Friend *friend_obj = onion_get_friend(alice.get_onion_client(), friend_num);
    EXPECT_NE(friend_obj, nullptr);

    // Test Group Chat Public Key
    uint8_t gc_pk[CRYPTO_PUBLIC_KEY_SIZE];
    crypto_new_keypair(alice.get_random(), gc_pk, friend_sk);

    onion_friend_set_gc_public_key(friend_obj, gc_pk);
    const uint8_t *retrieved_gc_pk = onion_friend_get_gc_public_key(friend_obj);
    EXPECT_EQ(std::memcmp(gc_pk, retrieved_gc_pk, CRYPTO_PUBLIC_KEY_SIZE), 0);

    // Test Group Chat Flag
    EXPECT_FALSE(onion_friend_is_groupchat(friend_obj));
    uint8_t data[] = {1, 2, 3};
    onion_friend_set_gc_data(friend_obj, data, sizeof(data));
    EXPECT_TRUE(onion_friend_is_groupchat(friend_obj));
}

}  // namespace
