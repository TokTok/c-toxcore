#ifndef C_TOXCORE_TESTING_NETPROF_MODEL_UTILS_H
#define C_TOXCORE_TESTING_NETPROF_MODEL_UTILS_H

#include "model.hh"

namespace tox::netprof {

/**
 * @brief Categorizes node traffic for visualization.
 */
enum class TrafficCategory { DHT, Data, Onion, None };

/**
 * @brief Analyzes node traffic and returns the dominant category.
 */
TrafficCategory get_dominant_traffic_category(const NodeInfo &node);

/**
 * @brief Projects a 32-byte DHT ID into a 0..2*PI theta angle.
 */
float project_dht_id_to_theta(const std::vector<uint8_t> &dht_id);

/**
 * @brief Safe numeric parsing functions that don't throw exceptions.
 * Returns true if parsing was successful.
 */
bool safe_stod(const std::string &s, double &out);
bool safe_stof(const std::string &s, float &out);
bool safe_stoul(const std::string &s, uint32_t &out);

bool case_insensitive_equal(const std::string &a, const std::string &b);

}  // namespace tox::netprof

#endif  // C_TOXCORE_TESTING_NETPROF_MODEL_UTILS_H
