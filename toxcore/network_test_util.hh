#ifndef C_TOXCORE_TOXCORE_NETWORK_TEST_UTIL_H
#define C_TOXCORE_TOXCORE_NETWORK_TEST_UTIL_H

#include "../testing/support/public/network.hh"
#include "test_util.hh"
#include "network.h"

using tox::test::random_ip_port;
using tox::test::increasing_ip_port;

template <>
struct Deleter<Networking_Core> : Function_Deleter<Networking_Core, kill_networking> { };

#endif  // C_TOXCORE_TOXCORE_NETWORK_TEST_UTIL_H
