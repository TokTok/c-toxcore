#include "hud.hh"

#include <ftxui/dom/elements.hpp>
#include <iomanip>
#include <sstream>
#include <string>

namespace tox::netprof::views {

using namespace ftxui;

static std::string format_time(uint64_t ms)
{
    uint64_t s = ms / 1000;
    uint64_t m = s / 60;
    uint64_t h = m / 60;
    std::stringstream ss;
    ss << "T+" << std::setfill('0') << std::setw(2) << h << ":" << std::setw(2) << (m % 60) << ":"
       << std::setw(2) << (s % 60) << "." << std::setw(3) << (ms % 1000);
    return ss.str();
}

ftxui::Component hud(const UIModel &model)
{
    return Renderer([&] {
        return hbox({
            text(" NetProf v1.0 ") | bold | bgcolor(Color::Blue) | color(Color::White),
            separator(),
            text(format_time(model.stats.virtual_time_ms)),
            separator(),
            text(model.stats.paused ? " PAUSED " : " RUNNING ")
                | color(model.stats.paused ? Color::Red : Color::Green),
            separator(),
            text(" Speed: " +
                [&]() {
                    if (model.stats.real_time_factor <= 0.0)
                        return std::string("MAX");
                    std::stringstream ss;
                    ss << std::fixed << std::setprecision(1) << model.stats.real_time_factor << "x";
                    return ss.str();
                }())
                | color(Color::Cyan),
            separator(),
            text(std::string(" Layer: ") +
                [&]() {
                    switch (model.layer_mode) {
                    case LayerMode::Normal:
                        return "Normal";
                    case LayerMode::TrafficType:
                        return "Traffic";
                    }
                    return "Unknown";
                }())
                | color(Color::Yellow),
            separator(),
            text(" Term: " + std::to_string(model.screen_width) + "x"
                + std::to_string(model.screen_height))
                | color(Color::GrayDark),
            filler(),
            text("Nodes: " + std::to_string(model.nodes.size())),
            separator(),
            text("Pkts: " + std::to_string(model.stats.total_packets_sent)),
            separator(),
            text("Bytes: " + std::to_string(model.stats.total_bytes_sent)),
        });
    });
}

}  // namespace tox::netprof::views
