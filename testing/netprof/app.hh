#ifndef C_TOXCORE_TESTING_NETPROF_APP_H
#define C_TOXCORE_TESTING_NETPROF_APP_H

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <map>
#include <mutex>
#include <thread>

#include "simulation_manager.hh"
#include "ui.hh"

namespace tox::netprof {

class NetProfApp {
public:
    explicit NetProfApp(uint64_t seed, bool verbose);
    ~NetProfApp();

    void run(bool headless, const std::string &load_path = "");

    // Internal command handlers exposed for testing
    void handle_command(UICommand cmd);

    void load_snapshot(const std::string &filename);

    const SimulationManager &manager() const { return manager_; }
    NetProfUI &ui() { return ui_; }

private:
    SimulationManager manager_;
    NetProfUI ui_;

    std::atomic<bool> running_{true};
    std::atomic<bool> auto_play_{false};
    std::atomic<double> simulation_speed_{1.0};
    std::atomic<uint64_t> last_sync_virtual_time_{0};
    std::mutex stats_mutex_;
    std::mutex pause_mutex_;
    std::condition_variable pause_cv_;
    std::map<uint32_t, NetProfStats> last_node_stats_;
    std::thread sim_thread_;

    void simulation_loop();
    void sync_stats();
    void resync_ui();

    void cmd_add_node(const std::vector<std::string> &args);
    void cmd_move_node(const std::vector<std::string> &args);
    void cmd_remove_node(const std::vector<std::string> &args);
    void cmd_connect_nodes(const std::vector<std::string> &args);
    void cmd_disconnect_nodes(const std::vector<std::string> &args);
    void cmd_toggle_offline(const std::vector<std::string> &args);
    void cmd_toggle_pin(const std::vector<std::string> &args);

    void run_headless();
};

}  // namespace tox::netprof

#endif  // C_TOXCORE_TESTING_NETPROF_APP_H
