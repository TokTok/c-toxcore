#include "event_log.hh"

#include <ftxui/dom/elements.hpp>
#include <string>
#include <vector>

#include "../constants.hh"
#include "focusable.hh"

namespace tox::netprof::views {

using namespace ftxui;

ftxui::Component event_log(const UIModel &model)
{
    return make_focusable(Renderer([&] {
        Elements list;
        int count = 0;
        for (int i = static_cast<int>(model.logs.size()) - 1; i >= 0 && count < kLogHeight; --i) {
            const auto &log = model.logs[i];

            Color col = Color::White;
            switch (log.level) {
            case LogLevel::Info:
                break;
            case LogLevel::Warn:
                col = Color::Yellow;
                break;
            case LogLevel::Error:
                col = Color::Red;
                break;
            case LogLevel::DHT:
                col = Color::Cyan;
                break;
            case LogLevel::Crypto:
                col = Color::Magenta;
                break;
            case LogLevel::Conn:
                col = Color::Green;
                break;
            case LogLevel::Command:
                // Commands are in the command log.
                continue;
            }

            if (!model.log_filter.empty()
                && log.message.find(model.log_filter) == std::string::npos)
                continue;

            list.insert(list.begin(), text(log.message) | color(col));
            count++;
        }
        return vbox(std::move(list));
    }));
}

}  // namespace tox::netprof::views
