#ifndef C_TOXCORE_TESTING_NETPROF_VIEWS_BOTTOM_BAR_HH
#define C_TOXCORE_TESTING_NETPROF_VIEWS_BOTTOM_BAR_HH

#include <ftxui/component/component.hpp>

#include "../model.hh"

namespace tox::netprof::views {

/**
 * @brief Creates the Bottom Status Bar component.
 */
ftxui::Component bottom_bar(const UIModel &model);

}  // namespace tox::netprof::views

#endif  // C_TOXCORE_TESTING_NETPROF_VIEWS_BOTTOM_BAR_HH
