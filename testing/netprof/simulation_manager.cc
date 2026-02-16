#include "simulation_manager.hh"

#include <algorithm>
#include <fstream>
#include <iostream>
#include <random>

#include "../../toxcore/tox_options.h"
#include "../../toxcore/tox_private.h"
#include "constants.hh"
#include "model_utils.hh"

namespace tox::netprof {

// --- SimulationManager Implementation ---

SimulationManager::SimulationManager(uint64_t seed, bool verbose)
    : seed_(seed)
    , sim_(seed)
    , verbose_(verbose)
{
    if (verbose_) {
        sim_.net().set_verbose(true);
    }

    sim_.net().add_observer([this](const tox::test::Packet &p) {
        total_packets_sent_++;
        total_bytes_sent_ += p.data.size();
    });
}
SimulationManager::~SimulationManager() = default;

void SimulationManager::start()
{
    // TODO(iphydf): Implement background thread runner if required.
    // The UI loop currently drives the 'step' function.
    running_ = true;
}

void SimulationManager::stop() { running_ = false; }

void SimulationManager::step(uint64_t ms)
{
    sim_.run_until([] { return false; }, ms);
}

uint64_t SimulationManager::get_virtual_time_ms() const { return sim_.clock().current_time_ms(); }

bool SimulationManager::is_running() const { return running_; }

std::shared_ptr<NodeWrapper> SimulationManager::add_node(
    std::string name, float x, float y, bool tcp_only)
{
    std::lock_guard<std::recursive_mutex> lock(nodes_mutex_);

    // Find unique ID (starting at 1)
    uint32_t id = 1;
    while (std::any_of(
        nodes_.begin(), nodes_.end(), [id](const auto &node) { return node->id() == id; })) {
        id++;
    }

    auto wrapper
        = std::make_shared<NodeWrapper>(sim_, id, std::move(name), verbose_, x, y, tcp_only);
    auto ptr = wrapper;

    // Bootstrap against up to 4 other nodes
    std::vector<std::shared_ptr<NodeWrapper>> others = nodes_;
    std::mt19937 g(seed_ + nodes_.size());
    std::shuffle(others.begin(), others.end(), g);

    int count = 0;
    for (const auto &other : others) {
        if (count >= kMaxBootstrapNodes)
            break;

        auto dht_id = other->runner().invoke([](Tox *t) {
            std::vector<uint8_t> res(TOX_PUBLIC_KEY_SIZE);
            tox_self_get_dht_id(t, res.data());
            return res;
        });

        auto *socket = other->node().get_primary_socket();
        if (socket) {
            Ip_Ntoa ip_str;
            net_ip_ntoa(&other->node().ip, &ip_str);
            std::string ip(ip_str.buf);
            uint16_t port = socket->local_port();

            ptr->runner().execute([dht_id, port, ip](Tox *t) {
                tox_bootstrap(t, ip.c_str(), port, dht_id.data(), nullptr);
                tox_add_tcp_relay(t, ip.c_str(), port, dht_id.data(), nullptr);
            });
            count++;
        }
    }

    dht_id_to_node_[ptr->get_dht_id()] = ptr;
    nodes_.push_back(std::move(wrapper));

    return ptr;
}

void SimulationManager::remove_node(uint32_t id)
{
    std::lock_guard<std::recursive_mutex> lock(nodes_mutex_);
    for (auto it = nodes_.begin(); it != nodes_.end(); ++it) {
        if ((*it)->id() == id) {
            dht_id_to_node_.erase((*it)->get_dht_id());
            nodes_.erase(it);

            // Remove connections involving this node
            connections_.erase(
                std::remove_if(connections_.begin(), connections_.end(),
                    [id](const ConnectionIntent &c) { return c.node_a == id || c.node_b == id; }),
                connections_.end());
            return;
        }
    }
}

std::shared_ptr<NodeWrapper> SimulationManager::get_node(uint32_t id)
{
    std::lock_guard<std::recursive_mutex> lock(nodes_mutex_);
    for (const auto &node : nodes_) {
        if (node->id() == id) {
            return node;
        }
    }
    return nullptr;
}

std::shared_ptr<NodeWrapper> SimulationManager::get_node_by_name(const std::string &name) const
{
    std::lock_guard<std::recursive_mutex> lock(nodes_mutex_);
    for (const auto &node : nodes_) {
        if (case_insensitive_equal(node->name(), name)) {
            return node;
        }
    }
    return nullptr;
}

std::shared_ptr<NodeWrapper> SimulationManager::get_node_by_dht_id(const uint8_t *dht_id)
{
    std::lock_guard<std::recursive_mutex> lock(nodes_mutex_);
    std::vector<uint8_t> key(dht_id, dht_id + TOX_PUBLIC_KEY_SIZE);
    auto it = dht_id_to_node_.find(key);
    if (it != dht_id_to_node_.end()) {
        return it->second;
    }
    return nullptr;
}

std::vector<std::shared_ptr<NodeWrapper>> SimulationManager::get_nodes() const
{
    std::lock_guard<std::recursive_mutex> lock(nodes_mutex_);
    return nodes_;
}

bool SimulationManager::connect_nodes(uint32_t id_a, uint32_t id_b, bool tcp_only)
{
    std::lock_guard<std::recursive_mutex> lock(nodes_mutex_);
    std::shared_ptr<NodeWrapper> node_a;
    std::shared_ptr<NodeWrapper> node_b;

    for (const auto &node : nodes_) {
        if (node->id() == id_a)
            node_a = node;
        if (node->id() == id_b)
            node_b = node;
    }

    if (!node_a || !node_b)
        return false;

    // Record intent
    connections_.push_back({id_a, id_b, tcp_only});

    // Execute connection logic
    // 1. Get Address and DHT ID from Node B
    auto [address_b, dht_id_b] = node_b->runner().invoke([](Tox *t) {
        std::pair<std::vector<uint8_t>, std::vector<uint8_t>> res;
        res.first.resize(TOX_ADDRESS_SIZE);
        tox_self_get_address(t, res.first.data());

        res.second.resize(TOX_PUBLIC_KEY_SIZE);
        tox_self_get_dht_id(t, res.second.data());
        return res;
    });

    // 2. Get Address from Node A
    auto address_a = node_a->runner().invoke([](Tox *t) {
        std::vector<uint8_t> addr(TOX_ADDRESS_SIZE);
        tox_self_get_address(t, addr.data());
        return addr;
    });

    // 3. Exchange Friend Requests
    node_a->runner().execute(
        [address_b](Tox *t) { tox_friend_add_norequest(t, address_b.data(), nullptr); });

    node_b->runner().execute(
        [address_a](Tox *t) { tox_friend_add_norequest(t, address_a.data(), nullptr); });

    // 4. Bootstrap A to B
    auto *socket = node_b->node().get_primary_socket();
    if (socket) {
        uint16_t port = socket->local_port();
        Ip_Ntoa ip_str;
        net_ip_ntoa(&node_b->node().ip, &ip_str);
        std::string ip(ip_str.buf);

        node_a->runner().execute([dht_id_b, port, ip](Tox *t) {
            tox_bootstrap(t, ip.c_str(), port, dht_id_b.data(), nullptr);
            tox_add_tcp_relay(t, ip.c_str(), port, dht_id_b.data(), nullptr);
        });
    }

    return true;
}

bool SimulationManager::disconnect_nodes(uint32_t id_a, uint32_t id_b)
{
    std::lock_guard<std::recursive_mutex> lock(nodes_mutex_);
    std::shared_ptr<NodeWrapper> node_a;
    std::shared_ptr<NodeWrapper> node_b;

    for (const auto &node : nodes_) {
        if (node->id() == id_a)
            node_a = node;
        if (node->id() == id_b)
            node_b = node;
    }

    if (!node_a || !node_b)
        return false;

    // 1. Get Public Keys
    auto pk_a = node_a->runner().invoke([](Tox *t) {
        std::vector<uint8_t> pk(TOX_PUBLIC_KEY_SIZE);
        tox_self_get_public_key(t, pk.data());
        return pk;
    });

    auto pk_b = node_b->runner().invoke([](Tox *t) {
        std::vector<uint8_t> pk(TOX_PUBLIC_KEY_SIZE);
        tox_self_get_public_key(t, pk.data());
        return pk;
    });

    // 2. Remove friends from both sides
    node_a->runner().execute([pk_b](Tox *t) {
        uint32_t fn = tox_friend_by_public_key(t, pk_b.data(), nullptr);
        if (fn != UINT32_MAX) {
            tox_friend_delete(t, fn, nullptr);
        }
    });

    node_b->runner().execute([pk_a](Tox *t) {
        uint32_t fn = tox_friend_by_public_key(t, pk_a.data(), nullptr);
        if (fn != UINT32_MAX) {
            tox_friend_delete(t, fn, nullptr);
        }
    });

    // 3. Update intent
    connections_.erase(std::remove_if(connections_.begin(), connections_.end(),
                           [id_a, id_b](const ConnectionIntent &c) {
                               return (c.node_a == id_a && c.node_b == id_b)
                                   || (c.node_a == id_b && c.node_b == id_a);
                           }),
        connections_.end());

    return true;
}

nlohmann::json SimulationManager::to_json() const
{
    nlohmann::json j;
    j["nodes"] = nlohmann::json::array();
    j["connections"] = nlohmann::json::array();

    std::lock_guard<std::recursive_mutex> lock(nodes_mutex_);
    for (const auto &nw : nodes_) {
        j["nodes"].push_back({
            {"id", nw->id()},
            {"name", nw->name()},
            {"pos", {nw->x(), nw->y()}},
            {"pinned", nw->is_pinned()},
        });
    }

    for (const auto &conn : connections_) {
        j["connections"].push_back({
            {"from", conn.node_a},
            {"to", conn.node_b},
            {"tcp", conn.tcp_only},
        });
    }

    return j;
}

void SimulationManager::from_json(const nlohmann::json &j)
{
    std::lock_guard<std::recursive_mutex> lock(nodes_mutex_);
    // Clear existing. Node destruction handles unregistration.
    nodes_.clear();
    dht_id_to_node_.clear();
    connections_.clear();

    if (j.contains("nodes")) {
        for (const auto &item : j["nodes"]) {
            float x = -1.0f;
            float y = -1.0f;
            if (item.contains("pos") && item["pos"].is_array() && item["pos"].size() == 2) {
                x = item["pos"][0].get<float>();
                y = item["pos"][1].get<float>();
            }
            auto n = add_node(item.value("name", "Unnamed"), x, y);
            n->set_pinned(item.value("pinned", false));
        }
    }

    if (j.contains("connections")) {
        for (const auto &item : j["connections"]) {
            connect_nodes(item.value("from", 0), item.value("to", 0), item.value("tcp", false));
        }
    }
}

void SimulationManager::save_to_file(const std::string &filename) const
{
    std::ofstream o(filename);
    o << std::setw(4) << to_json() << std::endl;
}

void SimulationManager::load_from_file(const std::string &filename)
{
    std::ifstream i(filename);
    if (i.is_open()) {
        nlohmann::json j;
        i >> j;
        from_json(j);
    }
}

}  // namespace tox::netprof
