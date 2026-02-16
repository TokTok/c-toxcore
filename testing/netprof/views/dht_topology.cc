#include "dht_topology.hh"

#include <algorithm>
#include <cmath>
#include <ftxui/dom/canvas.hpp>
#include <ftxui/dom/elements.hpp>
#include <ftxui/screen/terminal.hpp>
#include <map>
#include <vector>

#include "../constants.hh"
#include "../model_utils.hh"
#include "focusable.hh"

namespace tox::netprof::views {

using namespace ftxui;

ftxui::Component dht_topology(const UIModel &model)
{
    auto component = Renderer([&] {
        int dimx = model.screen_width;
        int dimy = model.screen_height;

        if (dimx <= 0 || dimy <= 0) {
            auto terminal = ftxui::Terminal::Size();
            dimx = terminal.dimx;
            dimy = terminal.dimy;
        }

        if (dimx <= 0)
            dimx = 200;
        if (dimy <= 0)
            dimy = 60;

        int avail_w = std::max(20, (dimx - 6) / 3);
        int avail_h = std::max(20, dimy - 18);

        int canvas_w = avail_w * 2;
        int canvas_h = avail_h * 4;

        auto c = Canvas(canvas_w, canvas_h);

        float scale = std::min(static_cast<float>(canvas_w), static_cast<float>(canvas_h)) / 100.0f;
        float off_x = (static_cast<float>(canvas_w) - 100.0f * scale) / 2.0f;
        float off_y = (static_cast<float>(canvas_h) - 100.0f * scale) / 2.0f;

        struct NodePos {
            uint32_t id;
            float theta;
            float r;
            float x, y;
        };
        std::vector<NodePos> sorted_nodes;
        for (const auto &kv : model.nodes) {
            sorted_nodes.push_back(
                {kv.first, project_dht_id_to_theta(kv.second.dht_id), kDHTRingRadius, 0, 0});
        }
        std::sort(sorted_nodes.begin(), sorted_nodes.end(),
            [](const auto &a, const auto &b) { return a.theta < b.theta; });

        for (size_t i = 0; i < sorted_nodes.size(); ++i) {
            int stack = 0;
            for (int j = static_cast<int>(i) - 1; j >= 0; --j) {
                float diff = std::abs(sorted_nodes[i].theta - sorted_nodes[j].theta);
                if (diff > 3.14159f)
                    diff = 2.0f * 3.14159f - diff;
                if (diff < 0.05f) {
                    stack++;
                } else {
                    break;
                }
            }
            sorted_nodes[i].r += static_cast<float>(stack) * 5.0f;
            sorted_nodes[i].x = 50.0f + sorted_nodes[i].r * std::cos(sorted_nodes[i].theta);
            sorted_nodes[i].y = 50.0f + sorted_nodes[i].r * std::sin(sorted_nodes[i].theta);
        }

        std::map<uint32_t, NodePos> pos_map;
        for (const auto &np : sorted_nodes)
            pos_map[np.id] = np;

        for (int i = 0; i < 100; ++i) {
            float t1 = static_cast<float>(i) / 100.0f * 2.0f * 3.14159f;
            float t2 = static_cast<float>(i + 1) / 100.0f * 2.0f * 3.14159f;
            c.DrawPointLine(static_cast<int>(off_x + (50.0f + 42.0f * std::cos(t1)) * scale),
                static_cast<int>(off_y + (50.0f + 42.0f * std::sin(t1)) * scale),
                static_cast<int>(off_x + (50.0f + 42.0f * std::cos(t2)) * scale),
                static_cast<int>(off_y + (50.0f + 42.0f * std::sin(t2)) * scale), Color::GrayDark);
        }

        for (const auto &kv : model.dht_interactions) {
            const auto &key = kv.first;
            uint64_t timestamp_ms = kv.second;

            if (!pos_map.count(key.id1) || !pos_map.count(key.id2))
                continue;

            if (key.is_discovery && !model.show_dht_discovery_lines)
                continue;
            if (!key.is_discovery && !model.show_dht_responder_lines)
                continue;

            auto p1 = pos_map.at(key.id1);
            auto p2 = pos_map.at(key.id2);

            uint64_t diff = 0;
            if (model.stats.virtual_time_ms > timestamp_ms) {
                diff = model.stats.virtual_time_ms - timestamp_ms;
            }
            uint8_t brightness
                = static_cast<uint8_t>(std::max(0, 255 - static_cast<int>(diff * 255 / 1000)));

            Color col;
            if (key.is_discovery) {
                col = Color::RGB(brightness, brightness, 0);  // Yellow for discovery
            } else {
                col = Color::RGB(0, brightness, brightness);  // Cyan for interaction
            }

            c.DrawPointLine(static_cast<int>(off_x + p1.x * scale),
                static_cast<int>(off_y + p1.y * scale), static_cast<int>(off_x + p2.x * scale),
                static_cast<int>(off_y + p2.y * scale), col);
        }

        for (const auto &np : sorted_nodes) {
            const auto &n = model.nodes.at(np.id);
            bool selected = (n.id == model.selected_node_id);

            Color color = n.is_online ? Color::Cyan : Color::GrayDark;
            c.DrawPointCircle(static_cast<int>(off_x + np.x * scale),
                static_cast<int>(off_y + np.y * scale), 2, color);
            c.DrawText(static_cast<int>(off_x + np.x * scale) + 2,
                static_cast<int>(off_y + np.y * scale), n.name, [&](Pixel &pix) {
                    pix.foreground_color = Color::White;
                    if (selected) {
                        pix.bold = true;
                        pix.underlined = true;
                    }
                });
        }

        return canvas(std::move(c)) | flex;
    });

    return make_focusable(component);
}

}  // namespace tox::netprof::views
