#ifndef C_TOXCORE_TESTING_NETPROF_VIEWS_COMMAND_LOG_HH
#define C_TOXCORE_TESTING_NETPROF_VIEWS_COMMAND_LOG_HH

#include <ftxui/component/component.hpp>

#include "../model.hh"

namespace tox::netprof::views {

/**
 * @brief Creates the Command Log component.
 */
ftxui::Component command_log(const UIModel &model);

}  // namespace tox::netprof::views

#endif  // C_TOXCORE_TESTING_NETPROF_VIEWS_COMMAND_LOG_HH
