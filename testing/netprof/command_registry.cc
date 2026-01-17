#include "command_registry.hh"

#include <algorithm>
#include <cctype>
#include <sstream>
#include <vector>

namespace tox::netprof {

void CommandRegistry::register_command(std::string name, std::string description, Handler handler)
{
    std::transform(
        name.begin(), name.end(), name.begin(), [](unsigned char c) { return std::tolower(c); });
    handlers_[name] = std::move(handler);
    descriptions_[name] = std::move(description);
}

bool CommandRegistry::execute(const std::string &cmd_line)
{
    std::stringstream ss(cmd_line);
    std::vector<std::string> tokens;
    std::string token;
    while (ss >> token) {
        tokens.push_back(token);
    }

    if (tokens.empty()) {
        return false;
    }

    // Find the longest matching command name greedily.
    std::string best_match;
    size_t tokens_consumed = 0;
    std::string current_prefix;

    auto to_lower = [](std::string s) {
        std::transform(
            s.begin(), s.end(), s.begin(), [](unsigned char c) { return std::tolower(c); });
        return s;
    };

    for (size_t i = 0; i < tokens.size(); ++i) {
        if (i > 0) {
            current_prefix += " ";
        }
        current_prefix += to_lower(tokens[i]);

        if (handlers_.count(current_prefix)) {
            best_match = current_prefix;
            tokens_consumed = i + 1;
        }
    }

    if (!best_match.empty()) {
        std::vector<std::string> args;
        for (size_t i = tokens_consumed; i < tokens.size(); ++i) {
            args.push_back(tokens[i]);
        }
        handlers_[best_match](args);
        return true;
    }

    return false;
}

}  // namespace tox::netprof
