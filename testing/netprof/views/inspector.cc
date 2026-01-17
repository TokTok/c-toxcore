#include "inspector.hh"

#include <algorithm>
#include <ftxui/dom/canvas.hpp>
#include <ftxui/dom/elements.hpp>
#include <ftxui/screen/terminal.hpp>
#include <map>
#include <string>
#include <vector>

#include "../../../toxcore/tox_private.h"
#include "../model_utils.hh"
#include "../packet_utils.hh"
#include "focusable.hh"

namespace tox::netprof::views {

using namespace ftxui;

ftxui::Component inspector(const UIModel &model)
{
    return make_focusable(Renderer([&] {
        int dimx = model.screen_width;
        int dimy = model.screen_height;

        if (dimx <= 0 || dimy <= 0) {
            auto terminal = ftxui::Terminal::Size();
            dimx = terminal.dimx;
            dimy = terminal.dimy;
        }

        if (dimx <= 0)
            dimx = 100;
        if (dimy <= 0)
            dimy = 50;

        int avail_w = std::max(20, (dimx - 6) / 3);
        int canvas_w = avail_w * 2;

        if (model.nodes.empty())
            return text("No nodes") | center;

        if (model.nodes.count(model.selected_node_id) == 0) {
            return vbox({
                text("NETWORK DASHBOARD") | bold | hcenter,
                separator(),
                hbox({
                    vbox({
                        text("Fleet Status") | bold,
                        text("Total Nodes: " + std::to_string(model.nodes.size())),
                        text("Total Links: " + std::to_string(model.links.size())),
                    }) | flex,
                    separator(),
                    vbox({
                        text("Aggregate Traffic") | bold,
                        text("Pkts:  " + std::to_string(model.stats.total_packets_sent)),
                        text("Bytes: " + std::to_string(model.stats.total_bytes_sent)),
                    }) | flex,
                }),
                separator(),
                text(" 🧬 GLOBAL PROTOCOL BREAKDOWN ") | bold | hcenter,
                hbox({
                    text("  Protocol") | size(WIDTH, GREATER_THAN, 22) | flex | bold,
                    text("Sent / Recv") | size(WIDTH, EQUAL, 25) | hcenter | bold,
                }),
                [&] {
                    Elements rows;
                    struct ProtoStat {
                        std::string name;
                        uint64_t sent;
                        uint64_t recv;
                        uint64_t total;
                    };
                    std::vector<ProtoStat> stats;

                    for (const auto &kv : model.stats.protocol_breakdown) {
                        uint64_t total = kv.second.sent + kv.second.recv;
                        if (total > 0) {
                            std::string name = get_packet_name(
                                static_cast<Tox_Netprof_Packet_Type>(kv.first.protocol),
                                kv.first.id);
                            stats.push_back({name, kv.second.sent, kv.second.recv, total});
                        }
                    }

                    std::sort(stats.begin(), stats.end(),
                        [](const auto &a, const auto &b) { return a.total > b.total; });

                    for (const auto &s : stats) {
                        rows.push_back(hbox({
                            text("  " + s.name) | size(WIDTH, GREATER_THAN, 22) | flex,
                            hbox({
                                text(std::to_string(s.sent)) | color(Color::RedLight),
                                text(" / "),
                                text(std::to_string(s.recv)) | color(Color::GreenLight),
                            }) | size(WIDTH, EQUAL, 25)
                                | hcenter,
                        }));
                    }
                    if (rows.empty())
                        return text("No traffic recorded") | dim | hcenter;
                    return vbox(std::move(rows));
                }(),
                filler(),
            });
        }

        const auto &n = model.nodes.at(model.selected_node_id);

        int max_val = 1024;
        for (int v : n.bw_in_history)
            max_val = std::max(max_val, v);
        for (int v : n.bw_out_history)
            max_val = std::max(max_val, v);
        max_val = max_val * 11 / 10;

        int total_protocols = 0;
        for (const auto &kv : n.protocol_breakdown) {
            if (kv.second.sent + kv.second.recv > 0)
                total_protocols++;
        }

        // Layout constants for space estimation.
        const int kIdentityHeight = 4;
        const int kSeparatorHeight = 1;
        const int kBandwidthHeight = 15;  // 1 header + 12 graph + 2 border
        const int kDHTActivityHeight = 10;  // 1 header + 7 graph + 2 border
        const int kProtocolHeaderHeight = 3;  // Title + Column Headers + blank/sep

        // Fixed overhead: Identity + 2 separators + BW graph + Protocol headers.
        const int kFixedOverhead = kIdentityHeight + kSeparatorHeight + kBandwidthHeight
            + kSeparatorHeight + kProtocolHeaderHeight;

        // Effective available height for the inspector content.
        // dimy - HUD(1) - Border(2) - Top Header(1) - Event Log(9) - Bottom(1) = dimy - 14.
        int avail_h = std::max(0, dimy - 14);
        int prot_space = std::max(0, avail_h - kFixedOverhead);

        // We want to show at least 10 protocols if possible.
        // DHT fits if there's space for DHT(10) + baseline protocols(10).
        bool show_dht_activity = (prot_space >= (kDHTActivityHeight + 10));

        int protocols_to_show;
        if (show_dht_activity) {
            protocols_to_show = prot_space - (kDHTActivityHeight + kSeparatorHeight);
        } else {
            protocols_to_show = prot_space;
        }

        // Account for the "... and X more" line if we're truncating.
        if (total_protocols > protocols_to_show && protocols_to_show > 0) {
            protocols_to_show -= 1;
        }

        protocols_to_show = std::max(0, std::min(total_protocols, protocols_to_show));

        Elements content;

        // Identity and DHT Status.
        content.push_back(hbox(Elements({
            vbox(Elements({
                text(" 👤 Identity") | bold | color(Color::Yellow),
                text("  ID:   " + std::to_string(n.id)),
                text("  Name: " + n.name),
                text(n.is_online ? "  Status: ONLINE" : "  Status: OFFLINE")
                    | color(n.is_online ? Color::Green : Color::Red),
            })) | flex,
            separator(),
            vbox(Elements({
                text(" 🌐 DHT Status") | bold | color(Color::Cyan),
                hbox(Elements({
                    text("  State: "),
                    [&]() {
                        switch (n.dht.connection_status) {
                        case TOX_CONNECTION_UDP:
                            return text("● ONLINE (UDP)") | bold | color(Color::Green);
                        case TOX_CONNECTION_TCP:
                            return text("● ONLINE (TCP)") | bold | color(Color::Yellow);
                        case TOX_CONNECTION_NONE:
                            return text("○ OFFLINE") | bold | color(Color::Red);
                        }
                        return text("UNKNOWN") | dim;
                    }(),
                })),
                text("  Nodes:   " + std::to_string(n.dht.num_closelist)),
                text("  Friends: " + std::to_string(n.dht.num_friends) + " ("
                    + std::to_string(n.dht.num_friends_udp) + " UDP, "
                    + std::to_string(n.dht.num_friends_tcp) + " TCP)"),
            })) | flex,
        })));

        content.push_back(separator());

        // Bandwidth Section.
        content.push_back(vbox(Elements({
            hbox(Elements({
                text(" 📊 Bandwidth (B/s) ") | bold,
                text("(Max Y: " + std::to_string(max_val) + ")") | dim,
                filler(),
                text(" IN: " + std::to_string(static_cast<int>(n.ema_bw_in))) | color(Color::Green),
                text(" "),
                text(" OUT: " + std::to_string(static_cast<int>(n.ema_bw_out))) | color(Color::Red),
            })),
            vbox(Elements({
                canvas([&, max_val, canvas_w] {
                    auto c = Canvas(canvas_w, 40);
                    const auto &in_h = n.bw_in_history;
                    const auto &out_h = n.bw_out_history;

                    auto draw_history = [&](const std::vector<int> &h, Color col, int offset_y) {
                        if (h.size() < 2)
                            return;
                        int start_x = canvas_w - static_cast<int>(h.size());
                        for (size_t i = 0; i < h.size() - 1; ++i) {
                            int y1 = 18 - (h[i] * 18 / max_val);
                            int y2 = 18 - (h[i + 1] * 18 / max_val);
                            c.DrawPointLine(start_x + static_cast<int>(i), y1 + offset_y,
                                start_x + static_cast<int>(i) + 1, y2 + offset_y, col);
                        }
                    };

                    draw_history(in_h, Color::Green, 0);
                    draw_history(out_h, Color::Red, 21);
                    for (int x = 0; x < canvas_w; ++x)
                        c.DrawPoint(x, 20, Color::GrayDark);
                    return c;
                }()) | size(HEIGHT, EQUAL, 12)
                    | border,
            })),
        })));

        // DHT Activity Section (Conditional).
        if (show_dht_activity) {
            content.push_back(vbox(Elements({
                hbox(Elements({
                    text(" 🔍 DHT Activity (Resp/tick) ") | bold,
                    filler(),
                })),
                vbox(Elements({
                    canvas([&, canvas_w] {
                        auto c = Canvas(canvas_w, 20);
                        const auto &h = n.dht_response_history;
                        if (h.empty())
                            return c;
                        int max_dht = 1;
                        for (int v : h)
                            max_dht = std::max(max_dht, v);
                        int start_x = canvas_w - static_cast<int>(h.size());
                        for (size_t i = 0; i < h.size() - 1; ++i) {
                            int y1 = 18 - (h[i] * 18 / max_dht);
                            int y2 = 18 - (h[i + 1] * 18 / max_dht);
                            c.DrawPointLine(start_x + static_cast<int>(i), y1,
                                start_x + static_cast<int>(i) + 1, y2, Color::Cyan);
                        }
                        return c;
                    }()) | size(HEIGHT, EQUAL, 7)
                        | border,
                })),
            })));
        }

        // Protocol Breakdown Section.
        content.push_back(separator());
        content.push_back(text(" 🧬 PROTOCOL BREAKDOWN (Cumulative Bytes) ") | bold | hcenter);
        content.push_back(hbox(Elements({
            text("  Protocol") | size(WIDTH, GREATER_THAN, 22) | flex | bold,
            text("Sent / Recv") | size(WIDTH, EQUAL, 25) | hcenter | bold,
            text("Share") | size(WIDTH, EQUAL, 15) | hcenter | bold,
        })));

        content.push_back([&] {
            Elements rows;
            uint64_t total_bytes = 0;
            struct ProtoStat {
                std::string name;
                uint64_t sent;
                uint64_t recv;
                uint64_t total;
            };
            std::vector<ProtoStat> stats;

            for (const auto &kv : n.protocol_breakdown) {
                uint64_t node_total = kv.second.sent + kv.second.recv;
                if (node_total > 0) {
                    std::string name = get_packet_name(
                        static_cast<Tox_Netprof_Packet_Type>(kv.first.protocol), kv.first.id);
                    stats.push_back({name, kv.second.sent, kv.second.recv, node_total});
                    total_bytes += node_total;
                }
            }

            std::sort(stats.begin(), stats.end(),
                [](const auto &a, const auto &b) { return a.total > b.total; });

            int count = 0;
            for (const auto &s : stats) {
                if (++count > protocols_to_show)
                    break;
                float share = static_cast<float>(s.total) / static_cast<float>(total_bytes);
                int bar_width = static_cast<int>(share * 14.0f);
                std::string bar_str;
                for (int i = 0; i < bar_width; ++i)
                    bar_str += "█";
                rows.push_back(hbox(Elements({
                    text("  " + s.name) | size(WIDTH, GREATER_THAN, 22) | flex,
                    hbox(Elements({
                        text(std::to_string(s.sent)) | color(Color::RedLight),
                        text(" / "),
                        text(std::to_string(s.recv)) | color(Color::GreenLight),
                    })) | size(WIDTH, EQUAL, 25)
                        | hcenter,
                    hbox(Elements({
                        text(bar_str) | color(Color::Cyan),
                        text(std::string(std::max(0, 14 - bar_width), ' ')) | dim,
                    })) | size(WIDTH, EQUAL, 15)
                        | color(Color::GrayDark),
                })));
            }
            if (rows.empty())
                return text("No traffic recorded") | dim | hcenter;
            if (total_protocols > protocols_to_show) {
                rows.push_back(text("  ... and "
                                   + std::to_string(total_protocols - protocols_to_show) + " more")
                    | dim);
            }
            return vbox(std::move(rows));
        }());

        content.push_back(filler());

        return vbox(std::move(content));
    }));
}

}  // namespace tox::netprof::views
