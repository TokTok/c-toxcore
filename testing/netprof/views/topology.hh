#ifndef C_TOXCORE_TESTING_NETPROF_VIEWS_TOPOLOGY_HH
#define C_TOXCORE_TESTING_NETPROF_VIEWS_TOPOLOGY_HH

#include <ftxui/component/component.hpp>

#include "../model.hh"

namespace tox::netprof::views {

/**
 * @brief Creates the Physical Topology component.
 */
ftxui::Component topology(const UIModel &model);

}  // namespace tox::netprof::views

#endif  // C_TOXCORE_TESTING_NETPROF_VIEWS_TOPOLOGY_HH
