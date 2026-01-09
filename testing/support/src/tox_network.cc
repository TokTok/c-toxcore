/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2026 The TokTok team.
 */

#include "../public/tox_network.hh"

#include <cstring>
#include <iostream>

#include "../../../toxcore/network.h"
#include "../../../toxcore/tox.h"

namespace tox::test {

ConnectedFriend::~ConnectedFriend() = default;

std::vector<ConnectedFriend> setup_connected_friends(Simulation &sim, Tox *main_tox,
    SimulatedNode &main_node, int num_friends, const Tox_Options *options)
{
    std::vector<ConnectedFriend> friends;
    friends.reserve(num_friends);

    uint8_t main_pk[TOX_PUBLIC_KEY_SIZE];
    tox_self_get_public_key(main_tox, main_pk);
    uint8_t main_dht_id[TOX_PUBLIC_KEY_SIZE];
    tox_self_get_dht_id(main_tox, main_dht_id);

    FakeUdpSocket *main_socket = main_node.get_primary_socket();
    if (!main_socket) {
        return {};
    }
    uint16_t main_port = main_socket->local_port();

    char main_ip_str[TOX_INET_ADDRSTRLEN];
    ip_parse_addr(&main_node.ip, main_ip_str, sizeof(main_ip_str));

    uint8_t prev_dht_id[TOX_PUBLIC_KEY_SIZE];
    memcpy(prev_dht_id, main_dht_id, TOX_PUBLIC_KEY_SIZE);
    char prev_ip_str[TOX_INET_ADDRSTRLEN];
    ip_parse_addr(&main_node.ip, prev_ip_str, sizeof(prev_ip_str));
    uint16_t prev_port = main_port;

    for (int i = 0; i < num_friends; ++i) {
        auto node = sim.create_node();
        auto tox = node->create_tox(options);
        if (!tox) {
            return {};
        }

        uint8_t friend_pk[TOX_PUBLIC_KEY_SIZE];
        tox_self_get_public_key(tox.get(), friend_pk);

        Tox_Err_Friend_Add err;
        uint32_t fn = tox_friend_add_norequest(main_tox, friend_pk, &err);
        if (fn == UINT32_MAX || err != TOX_ERR_FRIEND_ADD_OK) {
            return {};
        }
        if (tox_friend_add_norequest(tox.get(), main_pk, &err) == UINT32_MAX
            || err != TOX_ERR_FRIEND_ADD_OK) {
            return {};
        }

        // Bootstrap to the main node AND the PREVIOUS node in the chain
        tox_bootstrap(tox.get(), main_ip_str, main_port, main_dht_id, nullptr);
        if (i > 0) {
            tox_bootstrap(tox.get(), prev_ip_str, prev_port, prev_dht_id, nullptr);
        }

        // Update prev for next node
        tox_self_get_dht_id(tox.get(), prev_dht_id);
        ip_parse_addr(&node->ip, prev_ip_str, sizeof(prev_ip_str));

        FakeUdpSocket *node_socket = node->get_primary_socket();
        if (!node_socket) {
            return {};
        }
        prev_port = node_socket->local_port();

        friends.push_back({std::move(node), std::move(tox), fn});

        // Run simulation to let DHT stabilize
        sim.run_until(
            [&]() {
                tox_iterate(main_tox, nullptr);
                for (auto &f : friends) {
                    tox_iterate(f.tox.get(), nullptr);
                }
                return false;
            },
            200);
    }

    // Optional: Bootstrap main_tox to the last node to complete the circle
    if (!friends.empty()) {
        tox_bootstrap(main_tox, prev_ip_str, prev_port, prev_dht_id, nullptr);
    }

    // Run simulation until all are connected
    sim.run_until(
        [&]() {
            bool all_connected = true;
            int connected_count = 0;
            tox_iterate(main_tox, nullptr);
            for (auto &f : friends) {
                tox_iterate(f.tox.get(), nullptr);
                if (tox_friend_get_connection_status(main_tox, f.friend_number, nullptr)
                        != TOX_CONNECTION_NONE
                    && tox_friend_get_connection_status(f.tox.get(), 0, nullptr)
                        != TOX_CONNECTION_NONE) {
                    connected_count++;
                } else {
                    all_connected = false;
                }
            }
            static uint64_t last_print = 0;
            if (sim.clock().current_time_ms() - last_print > 1000) {
                std::cerr << "[setup_connected_friends] Friends connected: " << connected_count
                          << "/" << friends.size() << " (time: " << sim.clock().current_time_ms()
                          << "ms)" << std::endl;

                if (connected_count < static_cast<int>(friends.size())
                    && sim.clock().current_time_ms() > 10000) {
                    for (size_t i = 0; i < friends.size(); ++i) {
                        auto s1 = tox_friend_get_connection_status(
                            main_tox, friends[i].friend_number, nullptr);
                        auto s2
                            = tox_friend_get_connection_status(friends[i].tox.get(), 0, nullptr);
                        if (s1 == TOX_CONNECTION_NONE || s2 == TOX_CONNECTION_NONE) {
                            std::cerr << "  Friend " << i << " not connected (Main->F: " << s1
                                      << ", F->Main: " << s2 << ")" << std::endl;
                        }
                    }
                }

                last_print = sim.clock().current_time_ms();
            }
            return all_connected;
        },
        300000);  // 5 minutes simulation time for 100 nodes to converge

    return friends;
}

bool connect_friends(
    Simulation &sim, SimulatedNode &node1, Tox *tox1, SimulatedNode &node2, Tox *tox2)
{
    uint8_t pk1[TOX_PUBLIC_KEY_SIZE];
    uint8_t pk2[TOX_PUBLIC_KEY_SIZE];
    tox_self_get_public_key(tox1, pk1);
    tox_self_get_public_key(tox2, pk2);

    Tox_Err_Friend_Add err_add;
    uint32_t f1 = tox_friend_add_norequest(tox1, pk2, &err_add);
    if (f1 == UINT32_MAX || err_add != TOX_ERR_FRIEND_ADD_OK) {
        return false;
    }

    uint32_t f2 = tox_friend_add_norequest(tox2, pk1, &err_add);
    if (f2 == UINT32_MAX || err_add != TOX_ERR_FRIEND_ADD_OK) {
        return false;
    }

    uint8_t dht_id1[TOX_PUBLIC_KEY_SIZE];
    tox_self_get_dht_id(tox1, dht_id1);
    char ip1_str[TOX_INET_ADDRSTRLEN];
    ip_parse_addr(&node1.ip, ip1_str, sizeof(ip1_str));

    FakeUdpSocket *s1 = node1.get_primary_socket();
    if (!s1) {
        return false;
    }
    uint16_t port1 = s1->local_port();

    uint8_t dht_id2[TOX_PUBLIC_KEY_SIZE];
    tox_self_get_dht_id(tox2, dht_id2);
    char ip2_str[TOX_INET_ADDRSTRLEN];
    ip_parse_addr(&node2.ip, ip2_str, sizeof(ip2_str));

    FakeUdpSocket *s2 = node2.get_primary_socket();
    if (!s2) {
        return false;
    }
    uint16_t port2 = s2->local_port();

    tox_bootstrap(tox1, ip2_str, port2, dht_id2, nullptr);
    tox_bootstrap(tox2, ip1_str, port1, dht_id1, nullptr);

    sim.run_until(
        [&]() {
            tox_iterate(tox1, nullptr);
            tox_iterate(tox2, nullptr);
            return tox_friend_get_connection_status(tox1, f1, nullptr) != TOX_CONNECTION_NONE
                && tox_friend_get_connection_status(tox2, f2, nullptr) != TOX_CONNECTION_NONE;
        },
        60000);

    return tox_friend_get_connection_status(tox1, f1, nullptr) != TOX_CONNECTION_NONE
        && tox_friend_get_connection_status(tox2, f2, nullptr) != TOX_CONNECTION_NONE;
}

uint32_t setup_connected_group(
    Simulation &sim, Tox *main_tox, const std::vector<ConnectedFriend> &friends)
{
    struct NodeGroupState {
        uint32_t peer_count = 0;
        uint32_t group_number = UINT32_MAX;
    };

    NodeGroupState main_state;
    tox_callback_group_peer_join(main_tox, [](Tox *, uint32_t, uint32_t, void *user_data) {
        static_cast<NodeGroupState *>(user_data)->peer_count++;
    });

    Tox_Err_Group_New err_new;
    main_state.group_number = tox_group_new(main_tox, TOX_GROUP_PRIVACY_STATE_PUBLIC,
        reinterpret_cast<const uint8_t *>("test"), 4, reinterpret_cast<const uint8_t *>("main"), 4,
        &err_new);

    if (main_state.group_number == UINT32_MAX || err_new != TOX_ERR_GROUP_NEW_OK) {
        std::cerr << "tox_group_new failed with error: " << err_new << std::endl;
        return UINT32_MAX;
    }

    std::vector<std::unique_ptr<NodeGroupState>> friend_states;
    friend_states.reserve(friends.size());

    for (size_t i = 0; i < friends.size(); ++i) {
        auto state = std::make_unique<NodeGroupState>();
        tox_callback_group_peer_join(
            friends[i].tox.get(), [](Tox *, uint32_t, uint32_t, void *user_data) {
                static_cast<NodeGroupState *>(user_data)->peer_count++;
            });

        tox_callback_group_invite(friends[i].tox.get(),
            [](Tox *tox, uint32_t friend_number, const uint8_t *invite_data,
                size_t invite_data_length, const uint8_t *, size_t, void *user_data) {
                NodeGroupState *ng_state = static_cast<NodeGroupState *>(user_data);
                Tox_Err_Group_Invite_Accept err_accept;
                ng_state->group_number
                    = tox_group_invite_accept(tox, friend_number, invite_data, invite_data_length,
                        reinterpret_cast<const uint8_t *>("peer"), 4, nullptr, 0, &err_accept);
                if (ng_state->group_number == UINT32_MAX
                    || err_accept != TOX_ERR_GROUP_INVITE_ACCEPT_OK) {
                    ng_state->group_number = UINT32_MAX;
                }
            });

        friend_states.push_back(std::move(state));
    }

    // Run until all have joined and see everyone
    bool success = false;
    uint64_t last_print = 0;
    size_t invites_sent = 0;

    sim.run_until(
        [&]() {
            tox_iterate(main_tox, &main_state);

            // Throttle invites: keep max 5 pending
            size_t accepted_count = 0;
            for (size_t k = 0; k < invites_sent; ++k) {
                if (friend_states[k]->group_number != UINT32_MAX) {
                    accepted_count++;
                }
            }

            while (invites_sent < friends.size() && (invites_sent - accepted_count) < 5) {
                Tox_Err_Group_Invite_Friend err_invite;
                if (tox_group_invite_friend(main_tox, main_state.group_number,
                        friends[invites_sent].friend_number, &err_invite)) {
                    invites_sent++;
                } else {
                    if (err_invite != TOX_ERR_GROUP_INVITE_FRIEND_FAIL_SEND) {
                        std::cerr << "Invite failed for friend " << invites_sent << ": "
                                  << err_invite << std::endl;
                    }
                    break;  // Stop trying to send for this tick if we failed
                }
            }

            bool all_see_all = true;

            if (main_state.peer_count < friends.size()) {
                all_see_all = false;
            }

            for (size_t i = 0; i < friends.size(); ++i) {
                tox_iterate(friends[i].tox.get(), friend_states[i].get());
                if (friend_states[i]->group_number == UINT32_MAX
                    || friend_states[i]->peer_count < friends.size()) {
                    all_see_all = false;
                }
            }

            if ((sim.clock().current_time_ms() - last_print) % 5000 == 0) {
                int joined = 0;
                int fully_connected = 0;
                if (main_state.group_number != UINT32_MAX)
                    joined++;
                if (main_state.peer_count >= friends.size())
                    fully_connected++;

                for (const auto &fs : friend_states) {
                    if (fs->group_number != UINT32_MAX) {
                        joined++;
                        if (fs->peer_count >= friends.size())
                            fully_connected++;
                    }
                }
                std::cerr << "[setup_connected_group] Main peer count: " << main_state.peer_count
                          << "/" << friends.size() << ", Nodes joined: " << joined << "/"
                          << (friends.size() + 1) << ", fully connected: " << fully_connected << "/"
                          << (friends.size() + 1) << " (time: " << sim.clock().current_time_ms()
                          << "ms)" << std::endl;
                last_print = sim.clock().current_time_ms();
            }

            if (all_see_all) {
                success = true;
                return true;
            }
            return false;
        },
        300000);  // 5 minutes

    return success ? main_state.group_number : UINT32_MAX;
}

}  // namespace tox::test
