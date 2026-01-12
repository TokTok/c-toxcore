#include "bottom_bar.hh"

#include <ftxui/dom/elements.hpp>
#include <string>
#include <vector>

namespace tox::netprof::views {

using namespace ftxui;

ftxui::Component bottom_bar(const UIModel &model)
{
    return Renderer([&] {
        Elements items = {
            text(" q: Quit "),
            text(" Space: Pause "),
            text(" s: Step "),
            text(" a: Add Node "),
            text(" d: Delete "),
            text(model.cursor_mode ? (model.grab_mode ? " g: Drop " : " g: Grab ") : ""),
            text(" c: Cursor "),
            text(" p: Pin "),
            text(" o: Offline "),
            text(" l: Toggle Layer "),
            text(" F: Fast "),
            text(" +/-: Speed, =: Reset "),
            text(" S: Save "),
            text(" L: Load "),
            filler(),
        };

        if (model.marked_node_id != 0) {
            std::string name = "???";
            if (model.nodes.count(model.marked_node_id))
                name = model.nodes.at(model.marked_node_id).name;
            items.push_back(text(" [Linking from " + name + "] ") | bgcolor(Color::Blue));
            items.push_back(text(" f: Connect "));
            items.push_back(text(" u: Unfriend "));
            items.push_back(text(" Esc: Cancel "));
        } else {
            items.push_back(text(" f: Mark for linking "));
        }

        items.push_back(text(" Tab: Switch Pane "));
        return hbox(std::move(items));
    });
}

}  // namespace tox::netprof::views
