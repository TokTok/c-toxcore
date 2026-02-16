#ifndef C_TOXCORE_TESTING_NETPROF_UI_H
#define C_TOXCORE_TESTING_NETPROF_UI_H

#include <ftxui/component/component.hpp>
#include <ftxui/component/screen_interactive.hpp>
#include <functional>
#include <map>
#include <mutex>
#include <queue>
#include <string>
#include <vector>

#include "../../toxcore/tox.h"
#include "command_registry.hh"
#include "layout_engine.hh"
#include "model.hh"
#include "views/bottom_bar.hh"
#include "views/command_log.hh"
#include "views/command_palette.hh"
#include "views/dht_filter.hh"
#include "views/dht_topology.hh"
#include "views/event_log.hh"
#include "views/hud.hh"
#include "views/inspector.hh"
#include "views/topology.hh"

namespace tox::netprof {

// --- The View Controller ---

class NetProfUI {
public:
    using CommandCallback = std::function<void(UICommand)>;

    explicit NetProfUI(CommandCallback on_command);
    ~NetProfUI() = default;

    // Main Entry Point (Blocking)
    void run();

    // Thread-safe input channel
    void emit(UIMessage msg);
    void emit_batch(std::vector<UIMessage> batch);

    const UIModel &get_model() const { return model_; }
    ftxui::Component get_main_container() const { return main_container_; }
    ftxui::Component get_interactive_container() const { return interactive_container_; }
    ftxui::Component get_topology_comp() const { return topology_comp_; }
    ftxui::Component get_dht_filter_controls() const { return dht_filter_controls_; }

    // MVU Logic
    void process_messages();
    void apply(const UIMessage &msg);
    void execute_command(const std::string &cmd_str);

    // Event Handling
    bool handle_event(ftxui::Event event);

    // Navigation
    void select_node_in_direction(int dx, int dy);

    void register_commands();

private:
    bool handle_command_palette_event(ftxui::Event event);
    bool handle_tab_navigation(ftxui::Event event) const;
    bool handle_global_hotkeys(ftxui::Event event);
    bool handle_topology_event(ftxui::Event event);
    bool handle_cursor_movement(ftxui::Event event);
    bool handle_node_operations(char c);

    void update_command_suggestions();

    // Interaction
    CommandCallback on_command_;
    ftxui::ScreenInteractive screen_;

    // State
    UIModel model_;
    LayoutEngine layout_;
    CommandRegistry command_registry_;
    std::mutex queue_mutex_;
    std::queue<std::vector<UIMessage>> message_queue_;

    // Components
    ftxui::Component main_container_;
    ftxui::Component main_stack_;
    ftxui::Component interactive_container_;
    ftxui::Component command_palette_;
    ftxui::Component dht_filter_controls_;

    ftxui::Component hud_comp_;
    ftxui::Component topology_comp_;
    ftxui::Component dht_topology_comp_;
    ftxui::Component inspector_comp_;
    ftxui::Component event_log_comp_;
    ftxui::Component command_log_comp_;
    ftxui::Component bottom_bar_comp_;

    ftxui::Component col1_comp_;
    ftxui::Component col2_comp_;
    ftxui::Component col3_comp_;

    int main_stack_index_ = 0;

    mutable std::mutex ui_mutex_;
    bool ui_active_{false};
    std::chrono::steady_clock::time_point last_refresh_time_;
};

}  // namespace tox::netprof

#endif  // C_TOXCORE_TESTING_NETPROF_UI_H
