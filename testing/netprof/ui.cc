#include "ui.hh"

#include <cmath>
#include <ftxui/component/component.hpp>
#include <ftxui/component/event.hpp>
#include <ftxui/dom/canvas.hpp>
#include <ftxui/dom/elements.hpp>
#include <ftxui/screen/color.hpp>
#include <ftxui/screen/terminal.hpp>
#include <iomanip>
#include <sstream>

#include "constants.hh"

namespace tox::netprof {

using namespace ftxui;

NetProfUI::NetProfUI(CommandCallback on_command)
    : on_command_(std::move(on_command))
    , screen_(ScreenInteractive::Fullscreen())
{
    register_commands();

    command_palette_ = views::command_palette(
        model_,
        [this] {
            if (!model_.command_suggestions.empty() && model_.command_selected_index >= 0
                && model_.command_selected_index
                    < static_cast<int>(model_.command_suggestions.size())) {
                model_.command_input
                    = model_.command_suggestions[model_.command_selected_index].name;
            }
            this->execute_command(model_.command_input);
            model_.show_command_palette = false;
            main_stack_index_ = 0;
            model_.command_input = "";
        },
        [this] { this->update_command_suggestions(); });

    hud_comp_ = views::hud(model_);
    topology_comp_ = views::topology(model_);
    dht_topology_comp_ = views::dht_topology(model_);
    inspector_comp_ = views::inspector(model_);
    event_log_comp_ = views::event_log(model_);
    command_log_comp_ = views::command_log(model_);
    bottom_bar_comp_ = views::bottom_bar(model_);
    dht_filter_controls_ = views::dht_filter(model_);

    col1_comp_ = Container::Vertical({topology_comp_, command_log_comp_});
    col2_comp_ = Container::Vertical({dht_topology_comp_, dht_filter_controls_});
    col3_comp_ = Container::Vertical({inspector_comp_, event_log_comp_});

    // Container for focus-managed interactive components.
    interactive_container_ = Container::Horizontal({
        col1_comp_,
        col2_comp_,
        col3_comp_,
    });

    // Main application view renderer.
    auto main_renderer = Renderer(interactive_container_, [this]() -> Element {
        // Process any messages queued before UI activation.
        this->process_messages();

        {
            std::lock_guard<std::mutex> lock(ui_mutex_);
            ui_active_ = true;
        }

        if (!model_.manual_screen_size) {
            model_.screen_width = ftxui::Terminal::Size().dimx;
            model_.screen_height = ftxui::Terminal::Size().dimy;
        }

        auto topo_header = text(" 🏗️ PHYSICAL TOPOLOGY ") | bold | hcenter;
        if (topology_comp_->Focused())
            topo_header |= bgcolor(Color::Blue);

        auto cmd_log_header = text(" 📋 COMMAND LOG ") | bold | hcenter;
        if (command_log_comp_->Focused())
            cmd_log_header |= bgcolor(Color::Blue);

        auto dht_topo_header = text(" 🕸️ DHT TOPOLOGY (Kademlia Ring) ") | bold | hcenter;
        if (dht_topology_comp_->Focused())
            dht_topo_header |= bgcolor(Color::Blue);

        auto dht_header = text(" 🔍 DHT RING FILTERS ") | bold | hcenter;
        if (dht_filter_controls_->Focused())
            dht_header |= bgcolor(Color::Blue);

        auto inspector_header = text(" 🔎 NODE INSPECTOR ") | bold | hcenter;
        if (inspector_comp_->Focused())
            inspector_header |= bgcolor(Color::Blue);

        auto event_log_header = text(" 📝 EVENT LOG ") | bold | hcenter;
        if (event_log_comp_->Focused())
            event_log_header |= bgcolor(Color::Blue);

        auto col1_render = vbox({
                               topo_header,
                               topology_comp_->Render() | flex,
                               separator(),
                               cmd_log_header,
                               command_log_comp_->Render() | size(HEIGHT, EQUAL, kLogHeight),
                           })
            | flex;

        auto col2_render = vbox({
                               dht_topo_header,
                               dht_topology_comp_->Render() | flex,
                               separator(),
                               dht_header,
                               dht_filter_controls_->Render() | size(HEIGHT, EQUAL, kLogHeight),
                           })
            | flex;

        auto col3_render = vbox({
                               inspector_header,
                               inspector_comp_->Render() | flex,
                               separator(),
                               event_log_header,
                               event_log_comp_->Render() | size(HEIGHT, EQUAL, kLogHeight),
                           })
            | flex;

        if (model_.fast_mode) {
            return vbox({
                       hud_comp_->Render(),
                       separator(),
                       vbox({
                           filler(),
                           text(" FAST RENDERING MODE ENABLED ") | bold | hcenter
                               | color(Color::Yellow),
                           text(" All data is still being recorded. Press 'F' to restore full "
                                "view. ")
                               | hcenter | color(Color::GrayLight),
                           filler(),
                       }) | flex,
                       bottom_bar_comp_->Render() | size(HEIGHT, EQUAL, 1),
                   })
                | border | flex;
        }

        return vbox({
            vbox({
                hud_comp_->Render(),
                separator(),
                hbox({
                    col1_render,
                    separator(),
                    col2_render,
                    separator(),
                    col3_render,
                }) | flex,
            }) | border
                | flex,
            bottom_bar_comp_->Render() | size(HEIGHT, EQUAL, 1),
        });
    });

    // Stack comprising the main view and the modal command palette.
    main_stack_ = Container::Tab(
        {
            main_renderer,
            command_palette_,
        },
        &main_stack_index_);

    main_container_ = Renderer(main_stack_, [this, main_renderer] {
        if (model_.show_command_palette) {
            return dbox({
                main_renderer->Render(),
                command_palette_->Render() | center,
            });
        }
        return main_renderer->Render();
    });

    // Global input event handling.
    main_container_ |= CatchEvent([this](Event event) { return this->handle_event(event); });
}

bool NetProfUI::handle_command_palette_event(Event event)
{
    if (event == Event::Escape) {
        model_.show_command_palette = false;
        main_stack_index_ = 0;
        return true;
    }

    if (event == Event::ArrowUp) {
        if (!model_.command_suggestions.empty()) {
            model_.command_selected_index
                = (model_.command_selected_index - 1 + model_.command_suggestions.size())
                % model_.command_suggestions.size();
        }
        return true;
    }
    if (event == Event::ArrowDown) {
        if (!model_.command_suggestions.empty()) {
            model_.command_selected_index
                = (model_.command_selected_index + 1) % model_.command_suggestions.size();
        }
        return true;
    }

    if (event == Event::Tab) {
        if (!model_.command_suggestions.empty() && model_.command_selected_index >= 0
            && model_.command_selected_index
                < static_cast<int>(model_.command_suggestions.size())) {
            model_.command_input = model_.command_suggestions[model_.command_selected_index].name;
            update_command_suggestions();
            command_palette_->OnEvent(Event::End);
        }
        return true;
    }

    return false;  // Allow the input component to process the event.
}

bool NetProfUI::handle_tab_navigation(Event event) const
{
    if (event != Event::Tab && event != Event::TabReverse) {
        return false;
    }

    std::vector<ftxui::Component> components = {
        topology_comp_,
        command_log_comp_,
        dht_topology_comp_,
        dht_filter_controls_,
        inspector_comp_,
        event_log_comp_,
    };

    int current = -1;
    for (int i = 0; i < static_cast<int>(components.size()); ++i) {
        if (components[i]->Focused()) {
            current = i;
            break;
        }
    }

    if (current != -1) {
        int dir = (event == Event::Tab) ? 1 : -1;
        int count = static_cast<int>(components.size());
        int next = (current + dir + count) % count;
        components[next]->TakeFocus();
        return true;
    }

    return false;
}

bool NetProfUI::handle_global_hotkeys(Event event)
{
    if (!event.is_character()) {
        return false;
    }

    char c = event.character()[0];
    switch (c) {
    case 'q':
        on_command_({CmdType::Quit});
        screen_.ExitLoopClosure()();
        return true;
    case ' ':
        on_command_({CmdType::TogglePause});
        return true;
    case 's':
        on_command_({CmdType::Step});
        return true;
    case ':':
        model_.show_command_palette = true;
        main_stack_index_ = 1;
        model_.command_input = "";
        model_.command_selected_index = 0;
        update_command_suggestions();
        return true;
    case 'S':
        on_command_({CmdType::SaveSnapshot});
        return true;
    case 'L':
        on_command_({CmdType::LoadSnapshot});
        return true;
    case '+':
        if (model_.stats.real_time_factor > 0.0 && model_.stats.real_time_factor < 10.0) {
            on_command_({CmdType::SetSpeed, {std::to_string(model_.stats.real_time_factor + 0.5)}});
        } else if (model_.stats.real_time_factor >= 10.0) {
            on_command_({CmdType::SetSpeed, {"0.0"}});  // Max speed
        }
        return true;
    case '=':
        on_command_({CmdType::SetSpeed, {"1.0"}});
        return true;
    case '-':
        if (model_.stats.real_time_factor <= 0.0) {
            on_command_({CmdType::SetSpeed, {"10.0"}});
        } else if (model_.stats.real_time_factor > 0.5) {
            on_command_({CmdType::SetSpeed, {std::to_string(model_.stats.real_time_factor - 0.5)}});
        } else if (model_.stats.real_time_factor > 0.15) {
            on_command_({CmdType::SetSpeed, {std::to_string(model_.stats.real_time_factor - 0.1)}});
        }
        return true;
    case 'F':
        model_.fast_mode = !model_.fast_mode;
        return true;
    }
    return false;
}

bool NetProfUI::handle_node_operations(char c)
{
    switch (c) {
    case 'v':
        execute_command("dht");
        return true;
    case 'a':
        on_command_({CmdType::AddNode, {}});
        return true;
    case 'A':
        on_command_({CmdType::AddNode, {"tcp"}});
        return true;
    case 'm':
        if (model_.selected_node_id != 0) {
            on_command_({CmdType::MoveNode,
                {std::to_string(model_.selected_node_id), std::to_string(model_.cursor_x),
                    std::to_string(model_.cursor_y)}});
        }
        return true;
    case 'd':
        if (model_.selected_node_id != 0) {
            on_command_({CmdType::RemoveNode, {std::to_string(model_.selected_node_id)}});
        }
        return true;
    case 'f':
        if (model_.selected_node_id != 0) {
            if (model_.marked_node_id == 0) {
                model_.marked_node_id = model_.selected_node_id;
            } else if (model_.marked_node_id != model_.selected_node_id) {
                on_command_({CmdType::ConnectNodes,
                    {std::to_string(model_.marked_node_id),
                        std::to_string(model_.selected_node_id)}});
            }
        }
        return true;
    case 'u':
        if (model_.selected_node_id != 0 && model_.marked_node_id != 0
            && model_.marked_node_id != model_.selected_node_id) {
            on_command_({CmdType::DisconnectNodes,
                {std::to_string(model_.marked_node_id), std::to_string(model_.selected_node_id)}});
        }
        return true;
    case 'c':
        model_.cursor_mode = !model_.cursor_mode;
        if (!model_.cursor_mode)
            model_.grab_mode = false;
        return true;
    case 'g':
        if (model_.cursor_mode && model_.selected_node_id != 0) {
            model_.grab_mode = !model_.grab_mode;
        }
        return true;
    case 'l':
        switch (model_.layer_mode) {
        case LayerMode::Normal:
            model_.layer_mode = LayerMode::TrafficType;
            break;
        case LayerMode::TrafficType:
            model_.layer_mode = LayerMode::Normal;
            break;
        }
        return true;
    case 'o':
        if (model_.selected_node_id != 0) {
            on_command_({CmdType::ToggleOffline, {std::to_string(model_.selected_node_id)}});
        }
        return true;
    case 'p':
        if (model_.selected_node_id != 0) {
            on_command_({CmdType::TogglePin, {std::to_string(model_.selected_node_id)}});
        }
        return true;
    }
    return false;
}

bool NetProfUI::handle_cursor_movement(Event event)
{
    bool moved = false;
    if (event == Event::ArrowUp) {
        model_.cursor_y = std::max(0, model_.cursor_y - 2);
        moved = true;
    }
    if (event == Event::ArrowDown) {
        model_.cursor_y = std::min(100, model_.cursor_y + 2);
        moved = true;
    }
    if (event == Event::ArrowLeft) {
        model_.cursor_x = std::max(0, model_.cursor_x - 2);
        moved = true;
    }
    if (event == Event::ArrowRight) {
        model_.cursor_x = std::min(100, model_.cursor_x + 2);
        moved = true;
    }

    if (moved) {
        if (model_.grab_mode && model_.selected_node_id != 0) {
            on_command_({CmdType::MoveNode,
                {std::to_string(model_.selected_node_id), std::to_string(model_.cursor_x),
                    std::to_string(model_.cursor_y)}});
        } else {
            // Snap to and select the nearest node within proximity.
            for (const auto &kv : model_.nodes) {
                float dx = kv.second.x - static_cast<float>(model_.cursor_x);
                float dy = kv.second.y - static_cast<float>(model_.cursor_y);
                if (std::sqrt(dx * dx + dy * dy) < 5.0f) {
                    model_.selected_node_id = kv.first;
                    break;
                }
            }
        }
        return true;
    }
    return false;
}

bool NetProfUI::handle_topology_event(Event event)
{
    if (event == Event::Special("\033[3~")) {  // Delete key
        if (model_.selected_node_id != 0) {
            on_command_({CmdType::RemoveNode, {std::to_string(model_.selected_node_id)}});
        }
        return true;
    }

    if (event == Event::Escape) {
        model_.marked_node_id = 0;
        return true;
    }

    // Handle movement navigation.
    if (model_.cursor_mode) {
        return handle_cursor_movement(event);
    }

    if (event == Event::ArrowUp) {
        select_node_in_direction(0, -1);
        return true;
    }
    if (event == Event::ArrowDown) {
        select_node_in_direction(0, 1);
        return true;
    }
    if (event == Event::ArrowLeft) {
        select_node_in_direction(-1, 0);
        return true;
    }
    if (event == Event::ArrowRight) {
        select_node_in_direction(1, 0);
        return true;
    }

    return false;
}

bool NetProfUI::handle_event(Event event)
{
    if (model_.show_command_palette) {
        return handle_command_palette_event(event);
    }

    if (model_.fast_mode) {
        handle_global_hotkeys(event);
        return true;
    }

    if (handle_tab_navigation(event)) {
        return true;
    }

    bool topo_focused = topology_comp_->Focused();

    if (handle_global_hotkeys(event)) {
        return true;
    }

    if (event.is_character() && topo_focused) {
        if (handle_node_operations(event.character()[0])) {
            return true;
        }
    }

    if (topo_focused && handle_topology_event(event)) {
        return true;
    }

    if (event == Event::Special({16})) {  // Ctrl+P
        model_.show_command_palette = true;
        main_stack_index_ = 1;
        command_palette_->TakeFocus();
        model_.command_input = "";
        model_.command_selected_index = 0;
        update_command_suggestions();
        return true;
    }

    return false;
}

void NetProfUI::run()
{
    auto event_processor = CatchEvent(main_container_, [this](Event event) {
        if (event == Event::Custom) {
            this->process_messages();
            return true;  // Wakeup event consumed.
        }
        return false;
    });

    screen_.Loop(event_processor);

    {
        std::lock_guard<std::mutex> lock(ui_mutex_);
        ui_active_ = false;
    }
}

void NetProfUI::emit(UIMessage msg) { emit_batch({std::move(msg)}); }

void NetProfUI::emit_batch(std::vector<UIMessage> batch)
{
    {
        std::lock_guard<std::mutex> lock(queue_mutex_);
        message_queue_.push(std::move(batch));
    }

    std::lock_guard<std::mutex> lock(ui_mutex_);
    if (ui_active_) {
        auto now = std::chrono::steady_clock::now();
        const int interval = model_.fast_mode ? kUIFastRefreshIntervalMs : kUIRefreshIntervalMs;
        if (std::chrono::duration_cast<std::chrono::milliseconds>(now - last_refresh_time_).count()
            >= static_cast<long long>(interval)) {
            screen_.PostEvent(Event::Custom);
            last_refresh_time_ = now;
        }
    }
}

void NetProfUI::process_messages()
{
    std::lock_guard<std::mutex> lock(queue_mutex_);
    while (!message_queue_.empty()) {
        for (const auto &msg : message_queue_.front()) {
            apply(msg);
        }
        message_queue_.pop();
    }
}

template <class... Ts>
struct overloaded : Ts... {
    using Ts::operator()...;
};
template <class... Ts>
overloaded(Ts...) -> overloaded<Ts...>;

void NetProfUI::apply(const UIMessage &msg)
{
    std::visit(
        overloaded{
            [&](const MsgTick &m) {
                model_.stats = m.stats;

                // Advance layout simulation.
                layout_.step(0.5f);
                for (auto &kv : model_.nodes) {
                    if (layout_.nodes().count(kv.first)) {
                        kv.second.x = layout_.nodes().at(kv.first).x;
                        kv.second.y = layout_.nodes().at(kv.first).y;
                    }
                }

                // Remove expired DHT interactions based on virtual time.
                uint64_t current_time = model_.stats.virtual_time_ms;
                for (auto it = model_.dht_interactions.begin();
                     it != model_.dht_interactions.end();) {
                    if (current_time > it->second + kDHTInteractionLifetimeMs) {
                        it = model_.dht_interactions.erase(it);
                    } else {
                        ++it;
                    }
                }
            },
            [&](const MsgNodeAdded &m) {
                model_.nodes[m.id] = NodeInfo{m.id, m.name, true, m.dht_id};
                auto &node = model_.nodes[m.id];

                // Register node in the layout engine.
                layout_.add_node(m.id, m.x, m.y, false);
                node.x = layout_.nodes().at(m.id).x;
                node.y = layout_.nodes().at(m.id).y;

                // Automatically select the first node added.
                if (model_.nodes.size() == 1)
                    model_.selected_node_id = m.id;
            },
            [&](const MsgNodeRemoved &m) {
                if (model_.marked_node_id == m.id) {
                    model_.marked_node_id = 0;
                }

                float old_x = 50.0f, old_y = 50.0f;
                bool was_selected = (model_.selected_node_id == m.id);

                auto it = model_.nodes.find(m.id);
                if (it != model_.nodes.end()) {
                    old_x = it->second.x;
                    old_y = it->second.y;
                }

                model_.nodes.erase(m.id);
                layout_.remove_node(m.id);

                // Remove all links associated with this node.
                model_.links.erase(
                    std::remove_if(model_.links.begin(), model_.links.end(),
                        [&](const auto &link) { return link.from == m.id || link.to == m.id; }),
                    model_.links.end());

                if (was_selected) {
                    model_.selected_node_id = 0;
                    if (!model_.nodes.empty()) {
                        float min_dist = 1e10f;
                        uint32_t best_id = 0;
                        for (const auto &kv : model_.nodes) {
                            float dx = kv.second.x - old_x;
                            float dy = kv.second.y - old_y;
                            float d = dx * dx + dy * dy;
                            if (d < min_dist) {
                                min_dist = d;
                                best_id = kv.first;
                            }
                        }
                        model_.selected_node_id = best_id;
                    }
                }
            },
            [&](const MsgNodeMoved &m) {
                if (model_.nodes.count(m.id)) {
                    model_.nodes[m.id].x = m.x;
                    model_.nodes[m.id].y = m.y;
                    model_.nodes[m.id].is_pinned = true;
                    layout_.update_node(m.id, m.x, m.y, true);  // Pin moved nodes
                }
            },
            [&](const MsgNodePinned &m) {
                if (model_.nodes.count(m.id)) {
                    model_.nodes[m.id].is_pinned = m.pinned;
                    layout_.update_node(m.id, model_.nodes[m.id].x, model_.nodes[m.id].y, m.pinned);
                }
            },
            [&](const MsgLinkUpdated &m) {
                // Update existing link or add a new one.
                auto it
                    = std::find_if(model_.links.begin(), model_.links.end(), [&](const auto &link) {
                          return (link.from == m.from && link.to == m.to)
                              || (link.from == m.to && link.to == m.from);
                      });

                if (m.connected) {
                    if (it != model_.links.end()) {
                        it->connected = m.connected;
                        it->latency_ms = m.latency;
                        it->packet_loss = m.loss;
                        it->congestion = m.congestion;
                    } else {
                        model_.links.push_back(
                            {m.from, m.to, m.connected, m.latency, m.loss, m.congestion});
                        layout_.add_link(m.from, m.to);
                    }
                } else {
                    if (it != model_.links.end()) {
                        model_.links.erase(it);
                        layout_.remove_link(m.from, m.to);
                    }
                }
            },
            [&](const MsgNodeStats &m) {
                if (model_.nodes.count(m.id)) {
                    auto &n = model_.nodes[m.id];
                    // Update history buffers only if virtual time has progressed.
                    if (m.num_ticks > 0) {
                        const uint32_t ticks_to_push
                            = std::min(m.num_ticks, kMaxTicksToPushPerUpdate);

                        for (uint32_t j = 0; j < ticks_to_push; ++j) {
                            // Map virtual ticks to history samples using Bresenham-like
                            // distribution.
                            const uint32_t v_start = (j * m.num_ticks) / ticks_to_push;
                            const uint32_t v_end = ((j + 1) * m.num_ticks) / ticks_to_push;
                            const uint32_t v_count = v_end - v_start;

                            const uint32_t r_start
                                = (j * n.dht_responses_received_this_tick) / ticks_to_push;
                            const uint32_t r_end
                                = ((j + 1) * n.dht_responses_received_this_tick) / ticks_to_push;
                            const int r_count = static_cast<int>(r_end - r_start);

                            if (n.dht_neighbors_history.size() >= kHistoryBufferSize)
                                n.dht_neighbors_history.erase(n.dht_neighbors_history.begin());
                            n.dht_neighbors_history.push_back(m.dht_nodes);

                            if (n.dht_response_history.size() >= kHistoryBufferSize)
                                n.dht_response_history.erase(n.dht_response_history.begin());
                            n.dht_response_history.push_back(r_count);

                            // Apply scaled Exponential Moving Average (EMA).
                            // alpha_v = 1 - (1 - alpha)^v
                            const double alpha_v
                                = 1.0 - std::pow(1.0 - kEMAAlpha, static_cast<double>(v_count));
                            n.ema_bw_in = (alpha_v * m.bw_in) + ((1.0 - alpha_v) * n.ema_bw_in);
                            n.ema_bw_out = (alpha_v * m.bw_out) + ((1.0 - alpha_v) * n.ema_bw_out);

                            if (n.bw_in_history.size() >= kHistoryBufferSize)
                                n.bw_in_history.erase(n.bw_in_history.begin());
                            n.bw_in_history.push_back(static_cast<int>(std::round(n.ema_bw_in)));

                            if (n.bw_out_history.size() >= kHistoryBufferSize)
                                n.bw_out_history.erase(n.bw_out_history.begin());
                            n.bw_out_history.push_back(static_cast<int>(std::round(n.ema_bw_out)));
                        }
                        n.dht_responses_received_this_tick = 0;
                    }

                    n.dht.num_closelist = m.dht_nodes;
                    n.dht.num_friends = m.dht_friends;
                    n.dht.num_friends_udp = m.dht_friends_udp;
                    n.dht.num_friends_tcp = m.dht_friends_tcp;
                    n.dht.connection_status = m.connection_status;
                    n.is_online = m.is_online;
                    n.is_pinned = m.is_pinned;
                    n.protocol_breakdown = m.protocol_breakdown;

                    layout_.update_node(m.id, n.x, n.y, m.is_pinned);
                }
            },
            [&](const MsgLog &m) {
                model_.logs.push_back({m.message, m.level});
                if (model_.logs.size() > 100)
                    model_.logs.erase(model_.logs.begin());
            },
            [&](const MsgDHTResponse &m) {
                if (model_.nodes.count(m.receiver_id)) {
                    model_.nodes[m.receiver_id].dht_responses_received_this_tick++;

                    auto record_interaction = [&](uint32_t from, uint32_t to, bool discovery) {
                        if (from == 0 || to == 0 || !model_.nodes.count(from)
                            || !model_.nodes.count(to)) {
                            return;
                        }

                        // Normalize IDs for bidirectional deduplication.
                        uint32_t id1 = std::min(from, to);
                        uint32_t id2 = std::max(from, to);

                        UIModel::InteractionKey key{id1, id2, discovery};
                        model_.dht_interactions[key] = model_.stats.virtual_time_ms;
                    };

                    // Interaction from responder to receiver.
                    record_interaction(m.responder_id, m.receiver_id, false);
                    // Interaction from receiver to discovered node.
                    record_interaction(m.receiver_id, m.discovered_id, true);
                }
            },
            [&](const MsgResize &m) {
                model_.screen_width = m.width;
                model_.screen_height = m.height;
                model_.manual_screen_size = true;
            },
            [&](const MsgReset &) {
                model_.nodes.clear();
                model_.links.clear();
                model_.logs.clear();
                model_.dht_interactions.clear();
                model_.selected_node_id = 0;
                model_.marked_node_id = 0;
                model_.manual_screen_size = false;
                layout_ = LayoutEngine(100.0f, 100.0f);
            },
        },
        msg);
}

void NetProfUI::select_node_in_direction(int dx, int dy)
{
    if (model_.nodes.empty())
        return;

    // If no node is selected, default to the one closest to center.
    if (model_.nodes.count(model_.selected_node_id) == 0) {
        float min_dist = 1e10f;
        uint32_t best_id = 0;
        for (const auto &kv : model_.nodes) {
            float d
                = std::sqrt(std::pow(kv.second.x - 50.0f, 2) + std::pow(kv.second.y - 50.0f, 2));
            if (d < min_dist) {
                min_dist = d;
                best_id = kv.first;
            }
        }
        if (best_id != 0 || model_.nodes.count(0)) {
            // Note: Node IDs start at 1.
            // best_id will be non-zero if a suitable node is found.
            model_.selected_node_id = best_id;
        }
        return;
    }

    const auto &current = model_.nodes.at(model_.selected_node_id);
    uint32_t best_id = 0;
    float min_score = 1e10f;

    for (const auto &kv : model_.nodes) {
        if (kv.first == model_.selected_node_id)
            continue;

        float d_x = kv.second.x - current.x;
        float d_y = kv.second.y - current.y;

        // Verify the node is in the target direction.
        bool in_direction = false;
        if (dx > 0)
            in_direction = d_x > 0.1f;
        if (dx < 0)
            in_direction = d_x < -0.1f;
        if (dy > 0)
            in_direction = d_y > 0.1f;
        if (dy < 0)
            in_direction = d_y < -0.1f;

        if (!in_direction)
            continue;

        // Calculate distance score.
        // Prefer nodes that align more closely with the movement axis.
        float score;
        if (dx != 0) {
            score = std::sqrt(d_x * d_x + (2.0f * d_y) * (2.0f * d_y));
        } else {
            score = std::sqrt((2.0f * d_x) * (2.0f * d_x) + d_y * d_y);
        }

        if (score < min_score) {
            min_score = score;
            best_id = kv.first;
        }
    }

    if (best_id != 0) {
        model_.selected_node_id = best_id;
    }
}

void NetProfUI::update_command_suggestions()
{
    model_.command_suggestions.clear();
    std::string input = model_.command_input;
    std::transform(
        input.begin(), input.end(), input.begin(), [](unsigned char c) { return std::tolower(c); });

    auto all_commands = command_registry_.get_commands();
    for (const auto &kv : all_commands) {
        if (input.empty() || kv.first.find(input) != std::string::npos) {
            model_.command_suggestions.push_back({kv.first, kv.second});
        }
    }
    std::sort(model_.command_suggestions.begin(), model_.command_suggestions.end(),
        [](const auto &a, const auto &b) { return a.name < b.name; });

    model_.command_selected_index = 0;
}

void NetProfUI::register_commands()
{
    command_registry_.register_command("quit", "Exit the application", [this](auto) {
        {
            std::lock_guard<std::mutex> lock(ui_mutex_);
            ui_active_ = false;
        }
        on_command_({CmdType::Quit});
        screen_.ExitLoopClosure()();
    });
    command_registry_.register_command("exit", "Exit the application", [this](auto) {
        {
            std::lock_guard<std::mutex> lock(ui_mutex_);
            ui_active_ = false;
        }
        on_command_({CmdType::Quit});
        screen_.ExitLoopClosure()();
    });
    command_registry_.register_command(
        "pause", "Toggle simulation pause", [this](auto) { on_command_({CmdType::TogglePause}); });
    command_registry_.register_command(
        "resume", "Resume simulation", [this](auto) { on_command_({CmdType::TogglePause}); });
    command_registry_.register_command(
        "play", "Resume simulation", [this](auto) { on_command_({CmdType::TogglePause}); });
    command_registry_.register_command(
        "step", "Step simulation by 50ms", [this](auto) { on_command_({CmdType::Step}); });
    command_registry_.register_command(
        "add node", "Add a new node at cursor or random position", [this](auto args) {
            on_command_({CmdType::AddNode, args});
        });
    command_registry_.register_command(
        "dht", "Toggle physical DHT interaction overlay", [this](auto) {
            model_.show_dht_interactions_physical = !model_.show_dht_interactions_physical;
            emit(MsgLog{std::string("Physical DHT overlay: ")
                    + (model_.show_dht_interactions_physical ? "ENABLED" : "DISABLED"),
                LogLevel::Command});
        });
    command_registry_.register_command("save", "Save simulation state to netprof_save.json",
        [this](auto) { on_command_({CmdType::SaveSnapshot}); });
    command_registry_.register_command("load", "Load simulation state from netprof_save.json",
        [this](auto) { on_command_({CmdType::LoadSnapshot}); });
    command_registry_.register_command(
        "speed", "Set simulation speed (0 for max)", [this](auto args) {
            on_command_({CmdType::SetSpeed, args});
        });
    command_registry_.register_command(
        "connect", "Connect two nodes: connect <id1> <id2>", [this](auto args) {
            if (args.size() >= 2) {
                on_command_({CmdType::ConnectNodes, args});
            } else {
                emit(MsgLog{"Usage: connect <id1> <id2>", LogLevel::Warn});
            }
        });
    command_registry_.register_command("filter", "Set or clear log filter", [this](auto args) {
        if (args.empty()) {
            model_.log_filter = "";
            emit(MsgLog{"Filter cleared", LogLevel::Command});
        } else {
            model_.log_filter = args[0];
            emit(MsgLog{"Filter set to: " + args[0], LogLevel::Command});
        }
    });
    command_registry_.register_command(
        "layer normal", "Switch to normal topology layer", [this](auto) {
            model_.layer_mode = LayerMode::Normal;
            emit(MsgLog{"Layer set to NORMAL", LogLevel::Command});
        });
    command_registry_.register_command(
        "layer traffic", "Switch to traffic type heatmap layer", [this](auto) {
            model_.layer_mode = LayerMode::TrafficType;
            emit(MsgLog{"Layer set to TRAFFIC", LogLevel::Command});
        });

    // Calculate maximum widths for UI layout.
    for (const auto &kv : command_registry_.get_commands()) {
        model_.command_name_max_width
            = std::max(model_.command_name_max_width, static_cast<int>(kv.first.length()));
        model_.command_description_max_width
            = std::max(model_.command_description_max_width, static_cast<int>(kv.second.length()));
    }
}

void NetProfUI::execute_command(const std::string &cmd_str)
{
    // Trim leading and trailing whitespace.
    std::string cmd = cmd_str;
    cmd.erase(0, cmd.find_first_not_of(" \t\n\r"));
    cmd.erase(cmd.find_last_not_of(" \t\n\r") + 1);

    if (cmd.empty())
        return;

    if (!command_registry_.execute(cmd)) {
        emit(MsgLog{"Unknown command: " + cmd, LogLevel::Warn});
    }
}

}  // namespace tox::netprof
