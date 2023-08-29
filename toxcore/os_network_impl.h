/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2022-2023 The TokTok team.
 */

#ifndef C_TOXCORE_TOXCORE_OS_NETWORK_IMPL_H
#define C_TOXCORE_TOXCORE_OS_NETWORK_IMPL_H

#include "tox_network.h"

#ifdef __cplusplus
extern "C" {
#endif

non_null() Network_Addr *net_addr_new(const void *data, size_t size, const Tox_Memory *mem);
non_null() void net_addr_free(Network_Addr *addr, const Tox_Memory *mem);

non_null() void net_addr_set(Network_Addr *addr, const void *data, size_t size);

non_null() void *net_addr_mut_addr(Network_Addr *addr);
non_null() const void *net_addr_get_addr(const Network_Addr *addr);

non_null() void net_addr_set_size(Network_Addr *addr, size_t size);
non_null() size_t net_addr_get_size(const Network_Addr *addr);

non_null() bool net_addr_is_ipv4(const Network_Addr *addr);
non_null() bool net_addr_is_ipv6(const Network_Addr *addr);

non_null() uint16_t net_addr_get_port(const Network_Addr *addr);

#ifdef __cplusplus
}
#endif

#endif // C_TOXCORE_TOXCORE_OS_NETWORK_IMPL_H
