#include "command_log.hh"

#include <ftxui/dom/elements.hpp>

#include "../constants.hh"
#include "focusable.hh"

namespace tox::netprof::views {

using namespace ftxui;

ftxui::Component command_log(const UIModel &model)
{
    return make_focusable(Renderer([&] {
        Elements list;
        int count = 0;
        for (int i = static_cast<int>(model.logs.size()) - 1; i >= 0 && count < kLogHeight; --i) {
            const auto &log = model.logs[i];

            if (log.level != LogLevel::Command)
                continue;

            list.insert(list.begin(), text(log.message) | color(Color::Cyan));
            count++;
        }
        return vbox(std::move(list));
    }));
}

}  // namespace tox::netprof::views
