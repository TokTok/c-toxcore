#include "fuzz_adapter.h"

struct fuzz_buf {
    /* Monotonic counter for time replacement */
    uint64_t counter;
    /* Fuzz data buffer */
    const uint8_t *cur;
    const uint8_t *end;
};

static struct fuzz_buf data;

#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>


void network_adapter_init(const uint8_t *buf, size_t length)
{
    data.counter = 0;
    data.cur = buf;
    data.end = buf + length;
}

ssize_t fuzz_sendto(int __fd, const void *__buf, size_t __n,
                    int __flags, __CONST_SOCKADDR_ARG __addr,
                    socklen_t __addr_len)
{
    return __n;
}

ssize_t fuzz_send(int __fd, const void *__buf, size_t __n, int __flags)
{
    return __n;
}

static ssize_t recv_common(void *buf, size_t n)
{
    if (data.cur + 2 >= data.end) {
        return -1;
    }

    uint16_t fuzz_len = (data.cur[0] << 8) | data.cur[1];
    data.cur += 2;

    size_t available = data.end - data.cur;

    size_t res = fuzz_len > available ? available : fuzz_len;
    res = n > res ? res : n;

    memcpy(buf, data.cur, res);
    data.cur += res;

    return res;
}

ssize_t fuzz_recvfrom(int __fd, void *__restrict __buf, size_t __n,
                      int __flags, __SOCKADDR_ARG __addr,
                      socklen_t *__restrict __addr_len)
{
    struct sockaddr *addr = (struct sockaddr *) __addr;
    struct sockaddr_in *addr_in = (struct sockaddr_in *) __addr;

    if (__addr && __addr_len && (sizeof(struct sockaddr) <= *__addr_len)) {
        memset(__addr, 0, sizeof(struct sockaddr));
        // Dummy Addr
        addr->sa_family = AF_INET;

        addr_in->sin_port = 12356;
        addr_in->sin_addr.s_addr = INADDR_LOOPBACK + 1;
        *__addr_len = sizeof(struct sockaddr);
    }

    return recv_common(__buf, __n);
}

ssize_t fuzz_recv(int __fd, void *__buf, size_t __n, int __flags)
{
    return recv_common(__buf, __n);
}

void fuzz_random_bytes(uint8_t *rnd, size_t length)
{
    // Amount of data is limited
    size_t available = data.end - data.cur;
    size_t rd = length > available ? available : length;
    // Initialize everything to make MSAN and others happy
    memset(rnd, 0, length);
    memcpy(rnd, data.cur, rd);
    data.cur += rd;
}

uint64_t fuzz_get_cnt()
{
    return data.counter++;
}
