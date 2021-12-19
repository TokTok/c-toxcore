/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2021 The TokTok team.
 */

#ifndef C_TOXCORE_TESTING_FUZZING_FUZZ_ADAPTER_H
#define C_TOXCORE_TESTING_FUZZING_FUZZ_ADAPTER_H

#include <stdint.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Init function for the fuzzing harness
 * @param buf Begin of fuzz data
 * @param length Length of buf
 */
void network_adapter_init(const uint8_t *buf, size_t length);

/* The following functions intercept calls to standard network functions for fuzzing purposes and return data from the fuzz buffer. */

ssize_t fuzz_sendto(int __fd, const void *__buf, size_t __n,
                    int __flags, __CONST_SOCKADDR_ARG __addr,
                    socklen_t __addr_len);

ssize_t fuzz_send(int __fd, const void *__buf, size_t __n, int __flags);

ssize_t fuzz_recvfrom(int __fd, void *__restrict __buf, size_t __n,
                      int __flags, __SOCKADDR_ARG __addr,
                      socklen_t *__restrict __addr_len);

ssize_t fuzz_recv(int __fd, void *__buf, size_t __n, int __flags);

/* The following functions intercept generation of random data */
void fuzz_random_bytes(uint8_t *rnd, size_t length);

/* The following function replaces all time bases with a monotonic counter */

uint64_t fuzz_get_cnt();

#ifdef __cplusplus
}
#endif

#endif // C_TOXCORE_TESTING_FUZZING_FUZZ_ADAPTER_H
