/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2021-2022 The TokTok team.
 */

#include "fuzz_support.h"

#include <arpa/inet.h>
#include <sys/socket.h>

#include <cstring>
#include <memory>

#include "../../toxcore/crypto_core.h"
#include "../../toxcore/network.h"
#include "../../toxcore/tox_private.h"

// TODO(iphydf): Put this somewhere shared.
struct Network_Addr {
    struct sockaddr_storage addr;
    size_t size;
};

static int recv_common(Fuzz_Data &input, void *buf, size_t buf_len)
{
    if (input.size < 2) {
        return -1;
    }

    uint16_t fuzz_len = (input.data[0] << 8) | input.data[1];
    input.data += 2;
    input.size -= 2;

    size_t available = input.size;

    size_t res = fuzz_len > available ? available : fuzz_len;
    res = buf_len > res ? res : buf_len;

    memcpy(buf, input.data, res);
    input.data += res;
    input.size -= res;

    return res;
}

static const Network_Funcs fuzz_network_funcs = {
    .close = [](void *obj, int sock) { return 0; },
    .accept = [](void *obj, int sock) { return 2; },
    .bind = [](void *obj, int sock, const Network_Addr *addr) { return 0; },
    .listen = [](void *obj, int sock, int backlog) { return 0; },
    .recvbuf =
        [](void *obj, int sock) {
            // TODO(iphydf): Return something sensible here (from the fuzzer): number of
            // bytes to be read from the socket.
            return 0;
        },
    .recv =
        [](void *obj, int sock, uint8_t *buf, size_t len) {
            // Receive data from the fuzzer.
            return recv_common(static_cast<Fuzz_System *>(obj)->data, buf, len);
        },
    .recvfrom =
        [](void *obj, int sock, uint8_t *buf, size_t len, Network_Addr *addr) {
            addr->addr = sockaddr_storage{};
            // Dummy Addr
            addr->addr.ss_family = AF_INET;

            // We want an AF_INET address with dummy values
            sockaddr_in *addr_in = reinterpret_cast<sockaddr_in *>(&addr->addr);
            addr_in->sin_port = 12356;
            addr_in->sin_addr.s_addr = INADDR_LOOPBACK + 1;
            addr->size = sizeof(struct sockaddr);

            return recv_common(static_cast<Fuzz_System *>(obj)->data, buf, len);
        },
    .send =
        [](void *obj, int sock, const uint8_t *buf, size_t len) {
            // Always succeed.
            return static_cast<int>(len);
        },
    .sendto =
        [](void *obj, int sock, const uint8_t *buf, size_t len, const Network_Addr *addr) {
            // Always succeed.
            return static_cast<int>(len);
        },
    .socket = [](void *obj, int domain, int type, int proto) { return 1; },
    .socket_nonblock = [](void *obj, int sock, bool nonblock) { return 0; },
    .getsockopt =
        [](void *obj, int sock, int level, int optname, void *optval, size_t *optlen) {
            memset(optval, 0, *optlen);
            return 0;
        },
    .setsockopt = [](void *obj, int sock, int level, int optname, const void *optval,
                      size_t optlen) { return 0; },
};

static const Random_Funcs fuzz_random_funcs = {
    .random_bytes =
        [](void *obj, uint8_t *bytes, size_t length) {
            Fuzz_System *sys = static_cast<Fuzz_System *>(obj);
            // Amount of data is limited
            size_t available = sys->data.size;
            size_t bytes_read = length > available ? available : length;
            // Initialize everything to make MSAN and others happy
            std::memset(bytes, 0, length);
            std::memcpy(bytes, sys->data.data, bytes_read);
            sys->data.data += bytes_read;
            sys->data.size -= bytes_read;
        },
    .random_uniform =
        [](void *obj, uint32_t upper_bound) {
            Fuzz_System *sys = static_cast<Fuzz_System *>(obj);
            uint32_t randnum;
            sys->rng->funcs->random_bytes(
                sys, reinterpret_cast<uint8_t *>(&randnum), sizeof(randnum));
            return randnum % upper_bound;
        },
};

Fuzz_System::Fuzz_System(Fuzz_Data &input)
    : clock(0)
    , data(input)
    , sys(std::make_unique<Tox_System>())
    , ns(std::make_unique<Network>(Network{&fuzz_network_funcs, this}))
    , rng(std::make_unique<Random>(Random{&fuzz_random_funcs, this}))
{
    sys->mono_time_callback
        = [](void *user_data) { return static_cast<Fuzz_System *>(user_data)->clock; };
    sys->mono_time_user_data = this;
    sys->ns = ns.get();
    sys->rng = rng.get();
}

Fuzz_System::~Fuzz_System() { }
