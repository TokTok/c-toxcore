/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2026 The TokTok team.
 */

#include "announce_client.h"

#include <gtest/gtest.h>

#include <cstdint>
#include <cstring>
#include <memory>
#include <vector>

#include "../testing/support/public/simulated_environment.hh"
#include "DHT.h"
#include "DHT_test_util.hh"
#include "announce.h"
#include "attributes.h"
#include "crypto_core.h"
#include "forwarding.h"
#include "logger.h"
#include "mono_time.h"
#include "net_crypto.h"
#include "net_profile.h"
#include "network.h"
#include "timed_auth.h"

namespace {

using tox::test::FakeUdpSocket;
using tox::test::SimulatedEnvironment;

class AnnounceNode {
public:
    AnnounceNode(SimulatedEnvironment &env, std::uint16_t port)
        : dht_(env, port)
    {
        const TCP_Proxy_Info proxy_info = {{0}, TCP_PROXY_NONE};
        net_profile_ = netprof_new(dht_.logger(), mem());
        net_crypto_
            = new_net_crypto(dht_.logger(), mem(), rng(), &dht_.node().c_network, dht_.mono_time(),
                dht_.networking(), dht_.get_dht(), &WrappedDHT::funcs, &proxy_info, net_profile_);
        forwarding_ = new_forwarding(
            dht_.logger(), mem(), rng(), dht_.mono_time(), dht_.get_dht(), dht_.networking());
        announcements_ = new_announcements(dht_.logger(), mem(), mem(), rng(), dht_.mono_time(),
            forwarding_, dht_.get_dht(), dht_.networking());
        client_ = new_announce_client(dht_.logger(), mem(), rng(), dht_.mono_time(), forwarding_,
            dht_.get_dht(), dht_.networking(), net_crypto_, announcements_);
    }

    ~AnnounceNode()
    {
        stop_client();
        kill_announcements(announcements_);
        kill_forwarding(forwarding_);
        kill_net_crypto(net_crypto_);
        netprof_kill(mem(), net_profile_);
    }

    AnnounceNode(const AnnounceNode &) = delete;
    AnnounceNode &operator=(const AnnounceNode &) = delete;

    void stop_client()
    {
        kill_announce_client(client_);
        client_ = nullptr;
    }

    void poll()
    {
        mono_time_update(dht_.mono_time());
        networking_poll(dht_.networking(), nullptr);

        if (client_ != nullptr) {
            do_announce_client(client_);
        }
    }

    void add_node(const AnnounceNode &other) { add_node(other.ip_port(), other.public_key()); }

    void add_node(const IP_Port &ip_port, const std::uint8_t *_Nonnull public_key)
    {
        addto_lists(dht(), &ip_port, public_key);
        set_announce_node(dht(), public_key);
    }

    const Memory *_Nonnull mem() const { return &dht_.node().c_memory; }
    const Random *_Nonnull rng() const { return &dht_.node().c_random; }
    DHT *_Nonnull dht() { return dht_.get_dht(); }
    const std::uint8_t *_Nonnull public_key() const { return dht_.dht_public_key(); }
    const std::uint8_t *_Nonnull secret_key() const { return dht_.dht_secret_key(); }
    IP_Port ip_port() const { return dht_.get_ip_port(); }
    Announce_Client *_Nonnull client() { return REQUIRE_NOT_NULL(client_); }
    Announcements *_Nonnull announcements() { return REQUIRE_NOT_NULL(announcements_); }

private:
    WrappedDHT dht_;
    Net_Profile *_Nullable net_profile_ = nullptr;
    Net_Crypto *_Nullable net_crypto_ = nullptr;
    Forwarding *_Nullable forwarding_ = nullptr;
    Announcements *_Nullable announcements_ = nullptr;
    Announce_Client *_Nullable client_ = nullptr;
};

constexpr std::uint16_t kBasePort = 33445;
constexpr std::uint8_t kData[] = {'h', 'e', 'l', 'l', 'o'};

class AnnounceClientTest : public ::testing::Test {
protected:
    std::vector<std::unique_ptr<AnnounceNode>> make_nodes(std::uint32_t n)
    {
        std::vector<std::unique_ptr<AnnounceNode>> nodes;

        for (std::uint32_t i = 0; i < n; ++i) {
            nodes.push_back(std::make_unique<AnnounceNode>(env, kBasePort + i));
        }

        return nodes;
    }

    template <typename Done>
    bool run_until(std::vector<std::unique_ptr<AnnounceNode>> &nodes, Done done)
    {
        for (int i = 0; i < 600 && !done(); ++i) {
            env.advance_time(100);

            for (auto &node : nodes) {
                node->poll();
            }
        }

        return done();
    }

    void announce_and_retrieve(std::vector<std::vector<bool>> const &edges, std::uint32_t announcer,
        std::uint32_t target, std::uint32_t searcher, std::uint16_t width)
    {
        auto nodes = make_nodes(edges.size());

        for (std::size_t i = 0; i < edges.size(); ++i) {
            for (std::size_t j = 0; j < edges.size(); ++j) {
                if (edges[i][j]) {
                    nodes[i]->add_node(*nodes[j]);
                }
            }
        }

        const std::uint8_t *const pk = nodes[target]->public_key();
        const std::uint8_t *const sk = nodes[target]->secret_key();

        ASSERT_TRUE(announce_client_add_announce(
            nodes[announcer]->client(), pk, width, sk, kData, sizeof(kData)));
        ASSERT_TRUE(run_until(nodes, [&] {
            return announce_on_stored(nodes[target]->announcements(), pk, nullptr, nullptr);
        })) << "the announcement wasn't stored on the target";
        ASSERT_TRUE(announce_client_delete(nodes[announcer]->client(), pk));

        bool retrieved = false;
        ASSERT_TRUE(announce_client_add_search(
            nodes[searcher]->client(), pk, width,
            [](void *_Nullable, const std::uint8_t *_Nonnull) { return true; },
            [](void *_Nullable object, const std::uint8_t *_Nullable data, std::uint16_t length) {
                if (length == sizeof(kData) && std::memcmp(data, kData, length) == 0) {
                    *static_cast<bool *>(object) = true;
                }
            },
            0, &retrieved));
        EXPECT_TRUE(run_until(nodes, [&] { return retrieved; }))
            << "the searcher didn't retrieve the announcement";
    }

    SimulatedEnvironment env{12345};
};

std::vector<std::vector<bool>> no_edges(std::uint32_t n)
{
    return std::vector<std::vector<bool>>(n, std::vector<bool>(n, false));
}

std::vector<std::vector<bool>> line(std::uint32_t n)
{
    auto edges = no_edges(n);

    for (std::uint32_t i = 0; i + 1 < n; ++i) {
        edges[i][i + 1] = true;
    }

    return edges;
}

std::vector<std::vector<bool>> vee(std::uint32_t len)
{
    auto edges = no_edges(2 * len + 1);

    for (std::uint32_t i = 0; i < len; ++i) {
        edges[i][i + 1] = true;
        edges[len + i + 1][len + i] = true;
    }

    return edges;
}

std::vector<std::vector<bool>> complete(std::uint32_t n)
{
    auto edges = no_edges(n);

    for (std::uint32_t i = 0; i < n; ++i) {
        for (std::uint32_t j = 0; j < n; ++j) {
            edges[i][j] = i != j;
        }
    }

    return edges;
}

TEST_F(AnnounceClientTest, ALookupNeedsANode)
{
    auto nodes = make_nodes(1);
    EXPECT_FALSE(announce_client_add_announce(nodes[0]->client(), nodes[0]->public_key(), 0,
        nodes[0]->secret_key(), kData, sizeof(kData)));
}

TEST_F(AnnounceClientTest, StoresOnAndRetrievesFromTheOnlyOtherNode)
{
    announce_and_retrieve(line(2), 0, 1, 0, 2);
}

TEST_F(AnnounceClientTest, ForwardsAlongALine) { announce_and_retrieve(line(4), 0, 3, 0, 4); }

TEST_F(AnnounceClientTest, ForwardsFromBothEndsOfAVee)
{
    announce_and_retrieve(vee(4), 0, 4, 8, 4);
}

TEST_F(AnnounceClientTest, FindsTheTargetInSmallAndLargeCompleteGraphs)
{
    announce_and_retrieve(complete(5), 0, 1, 2, 4);
    announce_and_retrieve(complete(25), 0, 1, 2, 4);
}

class LyingResponder {
public:
    LyingResponder(SimulatedEnvironment &env, std::uint16_t port,
        const std::uint8_t *_Nonnull data_pk, std::size_t junk)
        : dht_(env, port)
    {
        std::uint8_t listed_sk[CRYPTO_SECRET_KEY_SIZE];
        crypto_new_keypair(&dht_.node().c_random, listed_.public_key, listed_sk);
        ip_init(&listed_.ip_port.ip, false);
        listed_.ip_port.ip.ip.v4.uint32 = net_htonl(0x0a000009);
        listed_.ip_port.port = net_htons(kBasePort);

        FakeUdpSocket *socket = dht_.node().endpoint;
        socket->set_recv_observer(
            [this, socket,
                key = std::vector<std::uint8_t>(data_pk, data_pk + CRYPTO_PUBLIC_KEY_SIZE),
                junk](const std::vector<std::uint8_t> &packet, const IP_Port &from) {
                if (!packet.empty() && packet[0] == NET_PACKET_FORWARD_REQUEST) {
                    asked_to_forward_ = true;
                }

                if (!answered_) {
                    answered_ = answer(socket, packet, from, key.data(), junk);
                }
            });
    }

    const std::uint8_t *_Nonnull public_key() const { return dht_.dht_public_key(); }
    IP_Port ip_port() const { return dht_.get_ip_port(); }
    bool answered() const { return answered_; }
    bool asked_to_forward() const { return asked_to_forward_; }

    void poll() { networking_poll(dht_.networking(), nullptr); }

private:
    bool answer(FakeUdpSocket *_Nonnull socket, const std::vector<std::uint8_t> &packet,
        const IP_Port &from, const std::uint8_t *_Nonnull data_pk, std::size_t junk)
    {
        constexpr std::size_t header = 1 + CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_NONCE_SIZE;

        if (packet.size()
                < header + CRYPTO_MAC_SIZE + CRYPTO_PUBLIC_KEY_SIZE + sizeof(std::uint64_t)
            || packet[0] != NET_PACKET_DATA_SEARCH_REQUEST) {
            return false;
        }

        const Memory *mem = &dht_.node().c_memory;
        std::uint8_t shared_key[CRYPTO_SHARED_KEY_SIZE];

        if (encrypt_precompute(packet.data() + 1, dht_.dht_secret_key(), shared_key) != 0) {
            return false;
        }

        std::vector<std::uint8_t> request(packet.size() - header - CRYPTO_MAC_SIZE);

        if (decrypt_data_symmetric(mem, shared_key, packet.data() + 1 + CRYPTO_PUBLIC_KEY_SIZE,
                packet.data() + header, packet.size() - header, request.data())
                != static_cast<std::int32_t>(request.size())
            || !pk_equal(request.data(), data_pk)) {
            return false;
        }

        constexpr std::size_t nodes_start = CRYPTO_PUBLIC_KEY_SIZE + 1 + TIMED_AUTH_SIZE + 1 + 1;
        std::vector<std::uint8_t> response(
            nodes_start + PACKED_NODE_SIZE_IP6 + junk + sizeof(std::uint64_t), 0);
        std::memcpy(response.data(), data_pk, CRYPTO_PUBLIC_KEY_SIZE);
        response[nodes_start - 1] = 1;

        const int packed_size
            = pack_nodes(dht_.logger(), &response[nodes_start], PACKED_NODE_SIZE_IP6, &listed_, 1);
        if (packed_size <= 0) {
            ADD_FAILURE() << "couldn't pack the listed node";
            return false;
        }

        response.resize(nodes_start + packed_size + junk + sizeof(std::uint64_t));

        std::uint8_t *const after_node = &response[nodes_start + packed_size];
        std::memset(after_node, 0xff, junk);
        std::memcpy(after_node + junk, &request[request.size() - sizeof(std::uint64_t)],
            sizeof(std::uint64_t));

        std::vector<std::uint8_t> reply(
            1 + CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_NONCE_SIZE + response.size() + CRYPTO_MAC_SIZE);
        const int reply_size = dht_create_packet(mem, &dht_.node().c_random, dht_.dht_public_key(),
            shared_key, NET_PACKET_DATA_SEARCH_RESPONSE, response.data(), response.size(),
            reply.data(), reply.size());
        EXPECT_EQ(reply_size, static_cast<int>(reply.size()));

        socket->sendto(reply.data(), reply.size(), &from);
        return true;
    }

    WrappedDHT dht_;
    Node_format listed_{};
    bool answered_ = false;
    bool asked_to_forward_ = false;
};

class AnnounceClientResponseTest : public AnnounceClientTest {
protected:
    bool follows_listed_node(std::size_t junk)
    {
        std::vector<std::unique_ptr<AnnounceNode>> nodes = make_nodes(1);
        AnnounceNode &alice = *nodes[0];

        std::uint8_t data_pk[CRYPTO_PUBLIC_KEY_SIZE];
        std::uint8_t data_sk[CRYPTO_SECRET_KEY_SIZE];
        crypto_new_keypair(alice.rng(), data_pk, data_sk);

        LyingResponder bob(env, kBasePort + 1, data_pk, junk);
        alice.add_node(bob.ip_port(), bob.public_key());

        EXPECT_TRUE(
            announce_client_add_search(alice.client(), data_pk, 2, nullptr, nullptr, 0, nullptr));

        for (int i = 0; i < 100 && !bob.asked_to_forward(); ++i) {
            env.advance_time(100);
            alice.poll();
            bob.poll();
        }

        EXPECT_TRUE(bob.answered());
        return bob.asked_to_forward();
    }
};

TEST_F(AnnounceClientResponseTest, FollowsTheNodesInAResponse)
{
    EXPECT_TRUE(follows_listed_node(0));
}

TEST_F(AnnounceClientResponseTest, IgnoresAResponseWithBytesAfterTheNodes)
{
    EXPECT_FALSE(follows_listed_node(1000));
}

TEST_F(AnnounceClientResponseTest, IgnoresAResponseWithAByteAfterTheNodes)
{
    EXPECT_FALSE(follows_listed_node(1));
}

class AnnounceClientDhtTest : public AnnounceClientTest {
protected:
    std::uint16_t announce_capable_after_meeting(std::vector<std::unique_ptr<AnnounceNode>> &nodes)
    {
        AnnounceNode &alice = *nodes[0];
        AnnounceNode &bob = *nodes[1];
        const IP_Port bob_ip_port = bob.ip_port();
        addto_lists(alice.dht(), &bob_ip_port, bob.public_key());
        run_until(nodes, [&] { return dht_get_num_closelist_announce_capable(alice.dht()) > 0; });
        return dht_get_num_closelist_announce_capable(alice.dht());
    }
};

TEST_F(AnnounceClientDhtTest, DhtLearnsWhichNodesStoreAnnouncementsWhileAClientExists)
{
    auto nodes = make_nodes(2);
    EXPECT_EQ(announce_capable_after_meeting(nodes), 1);
}

TEST_F(AnnounceClientDhtTest, DhtLearnsWhichNodesStoreAnnouncementsAfterTheClientIsGone)
{
    auto nodes = make_nodes(2);
    nodes[0]->stop_client();
    EXPECT_EQ(announce_capable_after_meeting(nodes), 1);
}

}  // namespace
