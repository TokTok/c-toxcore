/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2026 The TokTok team.
 */

#ifndef C_TOXCORE_TESTING_SUPPORT_TOX_NETWORK_H
#define C_TOXCORE_TESTING_SUPPORT_TOX_NETWORK_H

#include <vector>

#include "simulation.hh"

namespace tox::test {

struct ConnectedFriend {
    std::unique_ptr<SimulatedNode> node;
    SimulatedNode::ToxPtr tox;
    uint32_t friend_number;

    ConnectedFriend(std::unique_ptr<SimulatedNode> node_in, SimulatedNode::ToxPtr tox_in,
        uint32_t friend_number_in)
        : node(std::move(node_in))
        , tox(std::move(tox_in))
        , friend_number(friend_number_in)
    {
    }

    ConnectedFriend(ConnectedFriend &&) = default;
    ConnectedFriend &operator=(ConnectedFriend &&) = default;
    ~ConnectedFriend();
};

/**
 * @brief Sets up a network of connected Tox instances.
 *
 * This function creates num_friends Tox instances, adds them as friends to main_tox,
 * and bootstraps them to main_node. It then runs the simulation until all friends
 * are connected to main_tox.
 *
 * @param sim The simulation to run.
 * @param main_tox The main Tox instance to which friends will connect.
 * @param main_node The simulated node hosting the main Tox instance.
 * @param num_friends The number of friends to create and connect.
 * @param options Optional Tox_Options to use for the friend Tox instances.
 * @return A vector of ConnectedFriend structures, each representing a friend.
 */
std::vector<ConnectedFriend> setup_connected_friends(Simulation &sim, Tox *main_tox,
    SimulatedNode &main_node, int num_friends, const Tox_Options *options = nullptr);

/**
 * @brief Connects two existing Tox instances as friends.
 *
 * This function adds each Tox instance as a friend to the other, bootstraps
 * them to each other, and runs the simulation until they are connected.
 *
 * @param sim The simulation to run.
 * @param node1 The simulated node hosting the first Tox instance.
 * @param tox1 The first Tox instance.
 * @param node2 The simulated node hosting the second Tox instance.
 * @param tox2 The second Tox instance.
 * @return True if connected successfully, false otherwise.
 */
bool connect_friends(
    Simulation &sim, SimulatedNode &node1, Tox *tox1, SimulatedNode &node2, Tox *tox2);

/**
 * @brief Sets up a group and has all friends join it.
 *
 * This function creates a new public group on main_tox, invites all friends in the
 * provided vector, and runs the simulation until all friends have joined and
 * main_tox sees all of them.
 *
 * @param sim The simulation to run.
 * @param main_tox The main Tox instance that creates the group.
 * @param friends The friends to invite to the group.
 * @return The group number on the main Tox instance, or UINT32_MAX on failure.
 */
uint32_t setup_connected_group(
    Simulation &sim, Tox *main_tox, const std::vector<ConnectedFriend> &friends);

}  // namespace tox::test

#endif  // C_TOXCORE_TESTING_SUPPORT_TOX_NETWORK_H
