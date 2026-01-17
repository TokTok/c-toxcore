#ifndef C_TOXCORE_TESTING_NETPROF_VIEWS_HUD_HH
#define C_TOXCORE_TESTING_NETPROF_VIEWS_HUD_HH

#include <ftxui/component/component.hpp>

#include "../model.hh"

namespace tox::netprof::views {

/**
 * @brief Creates the HUD (Heads-Up Display) component.
 */
ftxui::Component hud(const UIModel &model);

}  // namespace tox::netprof::views

#endif  // C_TOXCORE_TESTING_NETPROF_VIEWS_HUD_HH
