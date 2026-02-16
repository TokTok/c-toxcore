#ifndef C_TOXCORE_TESTING_NETPROF_PACKET_UTILS_H
#define C_TOXCORE_TESTING_NETPROF_PACKET_UTILS_H

#include <string>

#include "../../toxcore/tox_private.h"

namespace tox::netprof {

/**
 * @brief Translates a low-level Tox packet ID into a human-readable string.
 *
 * @param protocol The protocol type (UDP, TCP, etc.)
 * @param id The 1-byte packet ID.
 * @return A descriptive name for the packet type.
 */
std::string get_packet_name(Tox_Netprof_Packet_Type protocol, uint8_t id);

}  // namespace tox::netprof

#endif  // C_TOXCORE_TESTING_NETPROF_PACKET_UTILS_H
