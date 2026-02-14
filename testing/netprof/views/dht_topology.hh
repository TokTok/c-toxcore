#ifndef C_TOXCORE_TESTING_NETPROF_VIEWS_DHT_TOPOLOGY_HH
#define C_TOXCORE_TESTING_NETPROF_VIEWS_DHT_TOPOLOGY_HH

#include <ftxui/component/component.hpp>

#include "../model.hh"

namespace tox::netprof::views {

/**
 * @brief Creates the DHT Topology (Kademlia Ring) component.
 */
ftxui::Component dht_topology(const UIModel &model);

}  // namespace tox::netprof::views

#endif  // C_TOXCORE_TESTING_NETPROF_VIEWS_DHT_TOPOLOGY_HH
