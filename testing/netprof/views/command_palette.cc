#include "command_palette.hh"

#include <ftxui/component/component.hpp>
#include <ftxui/dom/elements.hpp>

namespace tox::netprof::views {

using namespace ftxui;

ftxui::Component command_palette(
    UIModel &model, std::function<void()> on_execute, std::function<void()> on_change)
{
    auto input_option = InputOption();
    input_option.on_enter = std::move(on_execute);
    input_option.on_change = std::move(on_change);
    input_option.multiline = false;
    input_option.transform = [](InputState state) {
        auto e = state.element;
        if (state.focused) {
            e |= color(Color::White) | bgcolor(Color::Black);
        } else {
            e |= dim;
        }
        return e;
    };

    auto input
        = Input(&model.command_input, "Type command (e.g. 'pause', 'speed 2.0')...", input_option);

    return Renderer(input, [input, &model] {
        int name_w = model.command_name_max_width + 2;
        int desc_w = model.command_description_max_width + 2;
        int total_w = std::max(60, name_w + desc_w + 3);

        Elements suggestions;
        for (size_t i = 0; i < model.command_suggestions.size(); ++i) {
            bool selected = (static_cast<int>(i) == model.command_selected_index);
            const auto &s = model.command_suggestions[i];
            auto element = hbox({
                text(" " + s.name) | size(WIDTH, EQUAL, name_w),
                separator(),
                text(" " + s.description) | dim,
                filler(),
            });
            if (selected) {
                element |= ftxui::focus | bgcolor(Color::Blue) | bold;
            }
            suggestions.push_back(element);
        }

        auto suggestion_list = vbox(std::move(suggestions));
        if (model.command_suggestions.empty()) {
            suggestion_list = text(" (No matching commands) ") | dim | hcenter;
        }

        return vbox({
                   text(" COMMAND PALETTE ") | bold | center | bgcolor(Color::Blue),
                   hbox({text("> ") | bold,
                       [&]() {
                           auto e = input->Render() | focus;
                           if (!model.command_input.empty()) {
                               e |= focusCursorBlockBlinking;
                           }
                           return e
                               | size(WIDTH, EQUAL,
                                   model.command_input.empty()
                                       ? (total_w - 6)
                                       : static_cast<int>(model.command_input.length()) + 1);
                       }(),
                       filler() | xflex})
                       | size(WIDTH, EQUAL, total_w - 2) | border,
                   suggestion_list | frame | size(HEIGHT, EQUAL, 10) | vscroll_indicator | border,
                   text(" Press Enter to execute, Esc to cancel ") | dim | hcenter,
               })
            | size(WIDTH, EQUAL, total_w) | border | bgcolor(Color::Black) | clear_under | center;
    });
}

}  // namespace tox::netprof::views
