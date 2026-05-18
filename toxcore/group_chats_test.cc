// clang-format off
#include "group_chats.h"
// clang-format on

#include <gtest/gtest.h>

#include <array>
#include <cstdint>
#include <cstring>
#include <memory>
#include <vector>

#include "group_common.h"
#include "net.h"

namespace {

// Fills a saved peer with a fully-formed UDP address and TCP relay so that it
// survives a pack/unpack round-trip unambiguously.
void fill_saved_peer(GC_SavedPeerInfo *peer)
{
    peer->ip_port.ip.family = net_family_ipv4();
    peer->ip_port.ip.ip.v4.uint8[0] = 0x7f;
    peer->ip_port.ip.ip.v4.uint8[3] = 0x01;
    peer->ip_port.port = 0x1234;

    peer->tcp_relay.ip_port.ip.family = net_family_ipv4();
    peer->tcp_relay.ip_port.ip.ip.v4.uint8[0] = 0x7f;
    peer->tcp_relay.ip_port.ip.ip.v4.uint8[3] = 0x02;
    peer->tcp_relay.ip_port.port = 0x1234;
    std::memset(peer->tcp_relay.public_key, 0xab, sizeof(peer->tcp_relay.public_key));

    std::memset(peer->public_key, 0xcd, sizeof(peer->public_key));
}

// A saved-peers blob loaded from disk can describe more peers than the fixed
// chat->saved_peers[GC_MAX_SAVED_PEERS] array holds. unpack_gc_saved_peers must
// stop at the array bound rather than writing past it.
TEST(UnpackGcSavedPeers, DoesNotOverflowSavedPeersArray)
{
    auto src = std::make_unique<GC_Chat>();
    fill_saved_peer(&src->saved_peers[0]);

    // Encode one peer to obtain the wire bytes of a single entry.
    std::array<uint8_t, 256> entry{};
    uint16_t entry_len = 0;
    ASSERT_EQ(pack_gc_saved_peers(src.get(), entry.data(), entry.size(), &entry_len), 1);
    ASSERT_GT(entry_len, 0);

    // Sanity: one entry decodes back to exactly one saved peer.
    auto one = std::make_unique<GC_Chat>();
    ASSERT_EQ(unpack_gc_saved_peers(one.get(), entry.data(), entry_len), 1);

    // Build a blob describing far more peers than the array can hold.
    const int peer_count = GC_MAX_SAVED_PEERS + 200;
    std::vector<uint8_t> blob;
    blob.reserve(static_cast<std::size_t>(peer_count) * entry_len);
    for (int i = 0; i < peer_count; ++i) {
        blob.insert(blob.end(), entry.begin(), entry.begin() + entry_len);
    }
    ASSERT_LE(blob.size(), static_cast<std::size_t>(UINT16_MAX));

    auto dst = std::make_unique<GC_Chat>();
    const int unpacked
        = unpack_gc_saved_peers(dst.get(), blob.data(), static_cast<uint16_t>(blob.size()));

    EXPECT_LE(unpacked, GC_MAX_SAVED_PEERS);
}

}  // namespace
