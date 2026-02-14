#include "dht_filter.hh"

#include <ftxui/component/component.hpp>
#include <ftxui/screen/color.hpp>

namespace tox::netprof::views {

using namespace ftxui;

ftxui::Component dht_filter(UIModel &model)
{
    return Container::Vertical({
        Checkbox(" Responder", &model.show_dht_responder_lines) | color(Color::Cyan),
        Checkbox(" Discovered", &model.show_dht_discovery_lines) | color(Color::Yellow),
    });
}

}  // namespace tox::netprof::views
