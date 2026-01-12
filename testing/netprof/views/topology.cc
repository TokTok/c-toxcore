#include "topology.hh"

#include <cmath>
#include <ftxui/dom/canvas.hpp>
#include <ftxui/dom/elements.hpp>
#include <ftxui/screen/terminal.hpp>

#include "../model_utils.hh"
#include "focusable.hh"

namespace tox::netprof::views {

using namespace ftxui;

static void draw_links(Canvas &c, const UIModel &model)
{
    float sx = static_cast<float>(c.width()) / 100.0f;
    float sy = static_cast<float>(c.height()) / 100.0f;

    for (const auto &link : model.links) {
        if (!model.nodes.count(link.from) || !model.nodes.count(link.to))
            continue;
        auto &n1 = model.nodes.at(link.from);
        auto &n2 = model.nodes.at(link.to);

        Color color = link.connected ? Color::Green : Color::Red;
        if (link.connected && link.latency_ms > 100)
            color = Color::Yellow;
        if (link.connected && link.latency_ms > 300)
            color = Color::Red;

        c.DrawPointLine(static_cast<int>(n1.x * sx), static_cast<int>(n1.y * sy),
            static_cast<int>(n2.x * sx), static_cast<int>(n2.y * sy), color);

        if (link.congestion > 0.5f) {
            c.DrawPointLine(static_cast<int>(n1.x * sx) + 1, static_cast<int>(n1.y * sy),
                static_cast<int>(n2.x * sx) + 1, static_cast<int>(n2.y * sy), color);
        }
        if (link.congestion > 0.8f) {
            c.DrawPointLine(static_cast<int>(n1.x * sx), static_cast<int>(n1.y * sy) + 1,
                static_cast<int>(n2.x * sx), static_cast<int>(n2.y * sy) + 1, color);
        }
    }
}

static void draw_nodes(Canvas &c, const UIModel &model)
{
    float sx = static_cast<float>(c.width()) / 100.0f;
    float sy = static_cast<float>(c.height()) / 100.0f;

    for (const auto &kv : model.nodes) {
        const auto &n = kv.second;
        bool selected = (n.id == model.selected_node_id);
        bool marked = (n.id == model.marked_node_id);
        Color color = selected ? Color::Cyan : Color::White;
        if (marked)
            color = Color::Blue;

        if (!n.is_online) {
            color = Color::GrayDark;
        } else if (model.layer_mode == LayerMode::TrafficType) {
            switch (get_dominant_traffic_category(n)) {
            case TrafficCategory::DHT:
                color = Color::Cyan;
                break;
            case TrafficCategory::Data:
                color = Color::Magenta;
                break;
            case TrafficCategory::Onion:
                color = Color::Yellow;
                break;
            case TrafficCategory::None:
                break;
            }
        }

        c.DrawPointCircle(static_cast<int>(n.x * sx), static_cast<int>(n.y * sy), 3, color);
        if (n.is_pinned) {
            c.DrawPointCircle(static_cast<int>(n.x * sx), static_cast<int>(n.y * sy), 4, color);
        }

        if (marked) {
            c.DrawPointCircle(
                static_cast<int>(n.x * sx), static_cast<int>(n.y * sy), 5, Color::Blue);
        }

        std::string label = n.name;
        if (n.is_pinned) {
            label += " [P]";
        }

        c.DrawText(
            static_cast<int>(n.x * sx) - 2, static_cast<int>(n.y * sy) - 5, label, [&](Pixel &p) {
                p.foreground_color = Color::White;
                if (selected) {
                    p.bold = true;
                    p.underlined = true;
                }
            });
    }
}

static void draw_dht_interactions(Canvas &c, const UIModel &model)
{
    float sx = static_cast<float>(c.width()) / 100.0f;
    float sy = static_cast<float>(c.height()) / 100.0f;

    for (const auto &kv : model.dht_interactions) {
        const auto &key = kv.first;
        uint64_t timestamp_ms = kv.second;

        if (!model.nodes.count(key.id1) || !model.nodes.count(key.id2))
            continue;

        if (key.is_discovery && !model.show_dht_discovery_lines)
            continue;
        if (!key.is_discovery && !model.show_dht_responder_lines)
            continue;

        const auto &n1 = model.nodes.at(key.id1);
        const auto &n2 = model.nodes.at(key.id2);

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

        c.DrawPointLine(static_cast<int>(n1.x * sx), static_cast<int>(n1.y * sy),
            static_cast<int>(n2.x * sx), static_cast<int>(n2.y * sy), col);
    }
}

static void draw_preview_line(Canvas &c, const UIModel &model)
{
    if (model.marked_node_id == 0 || !model.nodes.count(model.marked_node_id)) {
        return;
    }

    float sx = static_cast<float>(c.width()) / 100.0f;
    float sy = static_cast<float>(c.height()) / 100.0f;

    const auto &n1 = model.nodes.at(model.marked_node_id);
    int target_x, target_y;

    if (model.cursor_mode) {
        target_x = static_cast<int>(static_cast<float>(model.cursor_x) * sx);
        target_y = static_cast<int>(static_cast<float>(model.cursor_y) * sy);
    } else if (model.nodes.count(model.selected_node_id)) {
        target_x = static_cast<int>(model.nodes.at(model.selected_node_id).x * sx);
        target_y = static_cast<int>(model.nodes.at(model.selected_node_id).y * sy);
    } else {
        return;
    }

    if (n1.id != model.selected_node_id || model.cursor_mode) {
        c.DrawPointLine(static_cast<int>(n1.x * sx), static_cast<int>(n1.y * sy), target_x,
            target_y, Color::BlueLight);
    }
}

static void draw_cursor(Canvas &c, const UIModel &model)
{
    if (model.cursor_mode) {
        float sx = static_cast<float>(c.width()) / 100.0f;
        float sy = static_cast<float>(c.height()) / 100.0f;

        int cx = static_cast<int>(static_cast<float>(model.cursor_x) * sx);
        int cy = static_cast<int>(static_cast<float>(model.cursor_y) * sy);

        c.DrawPointLine(cx - 2, cy, cx + 2, cy, Color::Yellow);
        c.DrawPointLine(cx, cy - 2, cx, cy + 2, Color::Yellow);
    }
}

ftxui::Component topology(const UIModel &model)
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

        draw_links(c, model);
        draw_nodes(c, model);
        if (model.show_dht_interactions_physical) {
            draw_dht_interactions(c, model);
        }
        draw_preview_line(c, model);
        draw_cursor(c, model);

        return canvas(std::move(c)) | flex;
    });

    return make_focusable(component);
}

}  // namespace tox::netprof::views
