#include "DHT.h"

#include <gtest/gtest.h>

#include <array>
#include <algorithm>

#include "crypto_core.h"

namespace {

using PublicKey = std::array<uint8_t, CRYPTO_PUBLIC_KEY_SIZE>;

template<typename T, size_t N>
std::array<T, N> to_array(T const (&arr)[N]) {
  std::array<T, N> stdarr;
  memcpy(stdarr.data(), arr, N);
  return stdarr;
}

TEST(IdClosest, IdenticalKeysAreSameDistance) {
  PublicKey pk0;
  random_bytes(pk0.data(), CRYPTO_PUBLIC_KEY_SIZE);

  PublicKey pk1;
  random_bytes(pk1.data(), CRYPTO_PUBLIC_KEY_SIZE);

  PublicKey pk2 = pk1;

  EXPECT_EQ(id_closest(pk0.data(), pk1.data(), pk2.data()), 0);
}

TEST(IdClosest, DistanceIsCommutative) {
  for (uint32_t i = 0; i < 100; ++i) {
    PublicKey pk0;
    random_bytes(pk0.data(), CRYPTO_PUBLIC_KEY_SIZE);

    PublicKey pk1;
    random_bytes(pk1.data(), CRYPTO_PUBLIC_KEY_SIZE);

    PublicKey pk2;
    random_bytes(pk2.data(), CRYPTO_PUBLIC_KEY_SIZE);

    if (id_closest(pk0.data(), pk1.data(), pk2.data()) == 0) {
      EXPECT_EQ(id_closest(pk0.data(), pk2.data(), pk1.data()), 0);
    }

    if (id_closest(pk0.data(), pk1.data(), pk2.data()) == 1) {
      EXPECT_EQ(id_closest(pk0.data(), pk2.data(), pk1.data()), 2);
    }

    if (id_closest(pk0.data(), pk1.data(), pk2.data()) == 2) {
      EXPECT_EQ(id_closest(pk0.data(), pk2.data(), pk1.data()), 1);
    }
  }
}

TEST(IdClosest, SmallXorDistanceIsCloser) {
  PublicKey pk0 = {{0xaa}};
  PublicKey pk1 = {{0xa0}};
  PublicKey pk2 = {{0x0a}};

  EXPECT_EQ(id_closest(pk0.data(), pk1.data(), pk2.data()), 1);
}

TEST(AddToList, OverridesKeysWithCloserKeys) {
  PublicKey self_pk = {{0xaa}};
  std::vector<PublicKey> keys = {
    {{0xa0}},  // closest
    {{0x0a}},  //
    {{0x0b}},  //
    {{0x0c}},  //
    {{0x0d}},  //
    {{0xa1}},  // closer than the 4 keys above
  };

  std::vector<Node_format> nodes(4);

  EXPECT_TRUE(add_to_list(nodes.data(), nodes.size(), keys[0].data(), IP_Port(), self_pk.data()));
  EXPECT_TRUE(add_to_list(nodes.data(), nodes.size(), keys[1].data(), IP_Port(), self_pk.data()));
  EXPECT_TRUE(add_to_list(nodes.data(), nodes.size(), keys[2].data(), IP_Port(), self_pk.data()));
  EXPECT_TRUE(add_to_list(nodes.data(), nodes.size(), keys[3].data(), IP_Port(), self_pk.data()));

  EXPECT_EQ(to_array(nodes[0].public_key), keys[0]);
  EXPECT_EQ(to_array(nodes[1].public_key), keys[1]);
  EXPECT_EQ(to_array(nodes[2].public_key), keys[2]);
  EXPECT_EQ(to_array(nodes[3].public_key), keys[3]);

  // key 4 is less close than keys 0-3
  EXPECT_FALSE(add_to_list(nodes.data(), nodes.size(), keys[4].data(), IP_Port(), self_pk.data()));
  // 5 is closer than all except key 0
  EXPECT_TRUE(add_to_list(nodes.data(), nodes.size(), keys[5].data(), IP_Port(), self_pk.data()));

  EXPECT_EQ(to_array(nodes[0].public_key), keys[0]);
  EXPECT_EQ(to_array(nodes[1].public_key), keys[5]);
  EXPECT_EQ(to_array(nodes[2].public_key), keys[1]);
  EXPECT_EQ(to_array(nodes[3].public_key), keys[2]);
}

}  // namespace
