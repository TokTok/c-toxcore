#ifndef C_TOXCORE_TESTING_NETPROF_VIEWS_COMMAND_PALETTE_HH
#define C_TOXCORE_TESTING_NETPROF_VIEWS_COMMAND_PALETTE_HH

#include <ftxui/component/component.hpp>
#include <functional>

#include "../model.hh"

namespace tox::netprof::views {

/**
 * @brief Creates the Command Palette component.
 */
ftxui::Component command_palette(
    UIModel &model, std::function<void()> on_execute, std::function<void()> on_change = nullptr);

}  // namespace tox::netprof::views

#endif  // C_TOXCORE_TESTING_NETPROF_VIEWS_COMMAND_PALETTE_HH
