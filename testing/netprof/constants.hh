#ifndef C_TOXCORE_TESTING_NETPROF_CONSTANTS_H
#define C_TOXCORE_TESTING_NETPROF_CONSTANTS_H

#include <cstdint>

namespace tox::netprof {

// Simulation constants.
static constexpr uint64_t kDefaultTickMs = 50;
static constexpr uint16_t kBasePort = 33445;
static constexpr int kMaxBootstrapNodes = 4;

// Layout hyperparameters.
static constexpr float kDefaultRepulsion = 50.0f;
static constexpr float kDefaultAttraction = 0.1f;
static constexpr float kDefaultIdealLength = 30.0f;
static constexpr float kDefaultFriction = 0.9f;
static constexpr float kDefaultStabilizationThreshold = 0.0001f;

// Visualization constants.
static constexpr size_t kHistoryBufferSize = 200;
/** @brief Maximum number of ticks to push to history in a single UI update to preserve visual flow.
 */
static constexpr uint32_t kMaxTicksToPushPerUpdate = 40;
static constexpr int kUIRefreshIntervalMs = 100;
static constexpr int kUIFastRefreshIntervalMs = 500;
static constexpr uint64_t kDHTInteractionLifetimeMs = 1000;
static constexpr float kDHTRingRadius = 42.0f;
static constexpr double kEMAAlpha = 0.3;

// UI Layout constants.
static constexpr int kLogHeight = 6;

// Nice names for nodes.
static constexpr const char *kNiceNames[] = {"Alice", "Bob", "Charlie", "Dave", "Eve", "Frank",
    "Grace", "Heidi", "Ivan", "Judy", "Kevin", "Linda", "Mike", "Nancy", "Oscar", "Peggy",
    "Quentin", "Rose", "Steve", "Trent", "Ursula", "Victor", "Wendy", "Xavier", "Yvonne", "Zelda"};
static constexpr size_t kNumNiceNames = sizeof(kNiceNames) / sizeof(kNiceNames[0]);

}  // namespace tox::netprof

#endif  // C_TOXCORE_TESTING_NETPROF_CONSTANTS_H
