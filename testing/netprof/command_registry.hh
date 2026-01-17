#ifndef C_TOXCORE_TESTING_NETPROF_COMMAND_REGISTRY_H
#define C_TOXCORE_TESTING_NETPROF_COMMAND_REGISTRY_H

#include <functional>
#include <map>
#include <string>
#include <vector>

namespace tox::netprof {

/**
 * @brief Represents a parsed command with its arguments.
 */
struct CommandContext {
    std::string name;
    std::vector<std::string> args;
};

/**
 * @brief A registry for UI commands to avoid long if-else chains.
 */
class CommandRegistry {
public:
    using Handler = std::function<void(const std::vector<std::string> &)>;

    void register_command(std::string name, std::string description, Handler handler);

    /**
     * @brief Parses and executes a command string.
     * @return true if command was found and executed.
     */
    bool execute(const std::string &cmd_line);

    /**
     * @brief Gets a list of all registered command names and descriptions.
     */
    std::map<std::string, std::string> get_commands() const { return descriptions_; }

private:
    std::map<std::string, Handler> handlers_;
    std::map<std::string, std::string> descriptions_;
};

}  // namespace tox::netprof

#endif  // C_TOXCORE_TESTING_NETPROF_COMMAND_REGISTRY_H
