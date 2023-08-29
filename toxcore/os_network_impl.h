/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2022-2023 The TokTok team.
 */

#ifndef C_TOXCORE_TOXCORE_OS_NETWORK_IMPL_H
#define C_TOXCORE_TOXCORE_OS_NETWORK_IMPL_H

#include "tox_network.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef OS_WIN32 // Put win32 includes here
// The mingw32/64 Windows library warns about including winsock2.h after
// windows.h even though with the above it's a valid thing to do. So, to make
// mingw32 headers happy, we include winsock2.h first.
#include <winsock2.h>
// Comment line here to avoid reordering by source code formatters.
#include <windows.h>
#include <ws2tcpip.h>
#endif

#if !defined(OS_WIN32)
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#ifdef __sun
#include <stropts.h>
#include <sys/filio.h>
#endif

#else
#ifndef IPV6_V6ONLY
#define IPV6_V6ONLY 27
#endif
#endif

struct Network_Addr {
    struct sockaddr_storage addr;
    size_t size;
};

#ifdef __cplusplus
}
#endif

#endif // C_TOXCORE_TOXCORE_OS_NETWORK_IMPL_H
