#ifndef C_TOXCORE_TESTING_NETPROF_VIEWS_INSPECTOR_HH
#define C_TOXCORE_TESTING_NETPROF_VIEWS_INSPECTOR_HH

#include <ftxui/component/component.hpp>

#include "../model.hh"

namespace tox::netprof::views {

/**
 * @brief Creates the Node Inspector component.
 */
ftxui::Component inspector(const UIModel &model);

}  // namespace tox::netprof::views

#endif  // C_TOXCORE_TESTING_NETPROF_VIEWS_INSPECTOR_HH
