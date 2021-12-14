#include "tcp_connection.h"

#include <gtest/gtest.h>

namespace
{

// TODO(Jfreegman) make this useful or remove it after NGC is merged
TEST(TCP_connection, NullTest)
{
    (void)tcp_connections_count(nullptr);
    (void)tcp_connected_relays_count(nullptr);
    (void)tcp_send_oob_packet_using_relay(nullptr, nullptr, nullptr, nullptr, 0);
}

}  // namespace
