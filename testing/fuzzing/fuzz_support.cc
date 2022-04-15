/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2021-2022 The TokTok team.
 */

#include "fuzz_support.h"

#include <arpa/inet.h>
#include <sys/socket.h>

#include <algorithm>
#include <cassert>
#include <cerrno>
#include <climits>
#include <cstdio>
#include <cstring>
#include <memory>

#include "../../toxcore/crypto_core.h"
#include "../../toxcore/network.h"
#include "../../toxcore/tox_private.h"
#include "func_conversion.h"

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

    const size_t fuzz_len = (input.data[0] << 8) | input.data[1];
    input.data += 2;
    input.size -= 2;

    const size_t res = std::min(buf_len, std::min(fuzz_len, input.size));

    memcpy(buf, input.data, res);
    input.data += res;
    input.size -= res;

    return res;
}

static constexpr Network_Funcs fuzz_network_funcs = {
    /* .close = */ ![](Fuzz_System *self, int sock) { return 0; },
    /* .accept = */ ![](Fuzz_System *self, int sock) { return 2; },
    /* .bind = */ ![](Fuzz_System *self, int sock, const Network_Addr *addr) { return 0; },
    /* .listen = */ ![](Fuzz_System *self, int sock, int backlog) { return 0; },
    /* .recvbuf = */
    ![](Fuzz_System *self, int sock) {
        const size_t count = random_u16(self->rng.get());
        return static_cast<int>(std::min(count, self->data.size));
    },
    /* .recv = */
    ![](Fuzz_System *self, int sock, uint8_t *buf, size_t len) {
        // Receive data from the fuzzer.
        return recv_common(self->data, buf, len);
    },
    /* .recvfrom = */
    ![](Fuzz_System *self, int sock, uint8_t *buf, size_t len, Network_Addr *addr) {
        addr->addr = sockaddr_storage{};
        // Dummy Addr
        addr->addr.ss_family = AF_INET;

        // We want an AF_INET address with dummy values
        sockaddr_in *addr_in = reinterpret_cast<sockaddr_in *>(&addr->addr);
        addr_in->sin_port = htons(33446);
        addr_in->sin_addr.s_addr = htonl(0xc0a8007f);  // 192.168.0.127
        addr->size = sizeof(struct sockaddr);

        return recv_common(self->data, buf, len);
    },
    /* .send = */
    ![](Fuzz_System *self, int sock, const uint8_t *buf, size_t len) {
        // Always succeed.
        return static_cast<int>(len);
    },
    /* .sendto = */
    ![](Fuzz_System *self, int sock, const uint8_t *buf, size_t len, const Network_Addr *addr) {
        // Always succeed.
        return static_cast<int>(len);
    },
    /* .socket = */ ![](Fuzz_System *self, int domain, int type, int proto) { return 1; },
    /* .socket_nonblock = */ ![](Fuzz_System *self, int sock, bool nonblock) { return 0; },
    /* .getsockopt = */
    ![](Fuzz_System *self, int sock, int level, int optname, void *optval, size_t *optlen) {
        memset(optval, 0, *optlen);
        return 0;
    },
    /* .setsockopt = */
    ![](Fuzz_System *self, int sock, int level, int optname, const void *optval, size_t optlen) {
        return 0;
    },
};

static constexpr Random_Funcs fuzz_random_funcs = {
    /* .random_bytes = */
    ![](Fuzz_System *self, uint8_t *bytes, size_t length) {
        // Amount of data is limited
        const size_t bytes_read = std::min(length, self->data.size);
        // Initialize everything to make MSAN and others happy
        std::memset(bytes, 0, length);
        std::memcpy(bytes, self->data.data, bytes_read);
        self->data.data += bytes_read;
        self->data.size -= bytes_read;
    },
    /* .random_uniform = */
    ![](Fuzz_System *self, uint32_t upper_bound) {
        uint32_t randnum = 0;
        if (upper_bound > 0) {
            self->rng->funcs->random_bytes(
                self, reinterpret_cast<uint8_t *>(&randnum), sizeof(randnum));
            randnum %= upper_bound;
        }
        return randnum;
    },
};

Fuzz_System::Fuzz_System(Fuzz_Data &input)
    : System{
        std::make_unique<Tox_System>(),
        std::make_unique<Network>(Network{&fuzz_network_funcs, this}),
        std::make_unique<Random>(Random{&fuzz_random_funcs, this}),
    }
    , data(input)
{
    sys->mono_time_callback = ![](Fuzz_System *self) { return self->clock; };
    sys->mono_time_user_data = this;
    sys->ns = ns.get();
    sys->rng = rng.get();
}

Fuzz_System::~Fuzz_System() { }

static constexpr Network_Funcs null_network_funcs = {
    /* .close = */ ![](Null_System *self, int sock) { return 0; },
    /* .accept = */ ![](Null_System *self, int sock) { return 2; },
    /* .bind = */ ![](Null_System *self, int sock, const Network_Addr *addr) { return 0; },
    /* .listen = */ ![](Null_System *self, int sock, int backlog) { return 0; },
    /* .recvbuf = */ ![](Null_System *self, int sock) { return 0; },
    /* .recv = */
    ![](Null_System *self, int sock, uint8_t *buf, size_t len) {
        // Always fail.
        errno = ENOMEM;
        return -1;
    },
    /* .recvfrom = */
    ![](Null_System *self, int sock, uint8_t *buf, size_t len, Network_Addr *addr) {
        // Always fail.
        errno = ENOMEM;
        return -1;
    },
    /* .send = */
    ![](Null_System *self, int sock, const uint8_t *buf, size_t len) {
        // Always succeed.
        return static_cast<int>(len);
    },
    /* .sendto = */
    ![](Null_System *self, int sock, const uint8_t *buf, size_t len, const Network_Addr *addr) {
        // Always succeed.
        return static_cast<int>(len);
    },
    /* .socket = */ ![](Null_System *self, int domain, int type, int proto) { return 1; },
    /* .socket_nonblock = */ ![](Null_System *self, int sock, bool nonblock) { return 0; },
    /* .getsockopt = */
    ![](Null_System *self, int sock, int level, int optname, void *optval, size_t *optlen) {
        memset(optval, 0, *optlen);
        return 0;
    },
    /* .setsockopt = */
    ![](Null_System *self, int sock, int level, int optname, const void *optval, size_t optlen) {
        return 0;
    },
};

static uint64_t simple_rng(uint64_t &seed)
{
    // https://nuclear.llnl.gov/CNP/rng/rngman/node4.html
    seed = 2862933555777941757LL * seed + 3037000493LL;
    return seed;
}

static constexpr Random_Funcs null_random_funcs = {
    /* .random_bytes = */
    ![](Null_System *self, uint8_t *bytes, size_t length) {
        for (size_t i = 0; i < length; ++i) {
            bytes[i] = simple_rng(self->seed) & 0xff;
        }
    },
    /* .random_uniform = */
    ![](Null_System *self, uint32_t upper_bound) {
        return static_cast<uint32_t>(simple_rng(self->seed)) % upper_bound;
    },
};

Null_System::Null_System()
    : System{
        std::make_unique<Tox_System>(),
        std::make_unique<Network>(Network{&null_network_funcs, this}),
        std::make_unique<Random>(Random{&null_random_funcs, this}),
    }
{
    sys->mono_time_callback = ![](Fuzz_System *self) { return self->clock; };
    sys->mono_time_user_data = this;
    sys->ns = ns.get();
    sys->rng = rng.get();
}

Null_System::~Null_System() { }

static constexpr Network_Funcs record_network_funcs = {
    /* .close = */ ![](Record_System *self, int sock) { return 0; },
    /* .accept = */ ![](Record_System *self, int sock) { return 2; },
    /* .bind = */
    ![](Record_System *self, int sock, const Network_Addr *addr) {
        uint16_t port;
        if (addr->addr.ss_family == AF_INET6) {
            port = reinterpret_cast<const sockaddr_in6 *>(&addr->addr)->sin6_port;
        } else {
            assert(addr->addr.ss_family == AF_INET);
            port = reinterpret_cast<const sockaddr_in *>(&addr->addr)->sin_port;
        }
        if (std::find(self->global_.bound.begin(), self->global_.bound.end(), port)
            != self->global_.bound.end()) {
            errno = EADDRINUSE;
            return -1;
        }
        self->global_.bound.push_back(port);
        self->port = port;
        return 0;
    },
    /* .listen = */ ![](Record_System *self, int sock, int backlog) { return 0; },
    /* .recvbuf = */ ![](Record_System *self, int sock) { return 0; },
    /* .recv = */
    ![](Record_System *self, int sock, uint8_t *buf, size_t len) {
        // Always fail.
        errno = ENOMEM;
        return -1;
    },
    /* .recvfrom = */
    ![](Record_System *self, int sock, uint8_t *buf, size_t len, Network_Addr *addr) {
        assert(sock == 42);
        if (self->recvq.empty()) {
            return 0;
        }
        const auto [from, packet] = std::move(self->recvq.front());
        self->recvq.pop_front();
        const size_t recvlen = std::min(len, packet.size());
        std::copy(packet.begin(), packet.end(), buf);
        std::printf("%zu -> %s\n", recvlen, self->name_);

        addr->addr = sockaddr_storage{};
        // Dummy Addr
        addr->addr.ss_family = AF_INET;

        // We want an AF_INET address with dummy values
        sockaddr_in *addr_in = reinterpret_cast<sockaddr_in *>(&addr->addr);
        addr_in->sin_port = from;
        addr_in->sin_addr.s_addr = htonl(0xc0a8007f);  // 192.168.0.127
        addr->size = sizeof(struct sockaddr);

        assert(recvlen > 0 && recvlen <= INT_MAX);
        return static_cast<int>(recvlen);
    },
    /* .send = */
    ![](Record_System *self, int sock, const uint8_t *buf, size_t len) {
        // Always succeed.
        return static_cast<int>(len);
    },
    /* .sendto = */
    ![](Record_System *self, int sock, const uint8_t *buf, size_t len, const Network_Addr *addr) {
        assert(self->backend != nullptr);
        assert(sock == 42);
        std::printf("%s -> %zu\n", self->name_, len);
        self->backend->receive(self->port, buf, len);
        return static_cast<int>(len);
    },
    /* .socket = */ ![](Record_System *self, int domain, int type, int proto) { return 42; },
    /* .socket_nonblock = */ ![](Record_System *self, int sock, bool nonblock) { return 0; },
    /* .getsockopt = */
    ![](Record_System *self, int sock, int level, int optname, void *optval, size_t *optlen) {
        memset(optval, 0, *optlen);
        return 0;
    },
    /* .setsockopt = */
    ![](Record_System *self, int sock, int level, int optname, const void *optval, size_t optlen) {
        return 0;
    },
};

static constexpr Random_Funcs record_random_funcs = {
    /* .random_bytes = */
    ![](Record_System *self, uint8_t *bytes, size_t length) {
        for (size_t i = 0; i < length; ++i) {
            bytes[i] = simple_rng(self->seed_) & 0xff;
        }
    },
    /* .random_uniform = */
    fuzz_random_funcs.random_uniform,
};

Record_System::Record_System(Global &global, uint64_t seed, const char *name)
    : System{
        std::make_unique<Tox_System>(),
        std::make_unique<Network>(Network{&record_network_funcs, this}),
        std::make_unique<Random>(Random{&record_random_funcs, this}),
    }
    , global_(global)
    , seed_(seed)
    , name_(name)
{
    sys->mono_time_callback = ![](Fuzz_System *self) { return self->clock; };
    sys->mono_time_user_data = this;
    sys->ns = ns.get();
    sys->rng = rng.get();
}

Record_System::~Record_System() { }

void Record_System::setup(Record_System &other) { backend = &other; }

void Record_System::receive(uint16_t send_port, const uint8_t *buf, size_t len)
{
    assert(port != 0);
    recvq.emplace_back(send_port, std::vector<uint8_t>{buf, buf + len});
}
