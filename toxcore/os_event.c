/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2026 The TokTok team.
 */

#include "os_event.h"

#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include <winsock2.h>
#include <winternl.h>
#else
#include <unistd.h>
#endif /* WIN32 */

#ifdef EV_USE_EPOLL
#include <sys/epoll.h>
#elif defined(ESP_PLATFORM)
#include <sys/poll.h>
#elif !defined(_WIN32)
#include <poll.h>
#endif /* EV_USE_EPOLL */

#include "ccompat.h"
#include "logger.h"
#include "mem.h"

#ifdef _WIN32
// Using the undocumented AFD driver directly (IOCTL_AFD_POLL).
// This bypasses the 64-handle limit of WaitForMultipleEvents and the bugs of WSAPoll.
// It provides true Level-Triggered notifications similar to poll/epoll.

#define IOCTL_AFD_POLL 0x00012024

typedef struct AFD_Poll_Handle_Info {
    void *_Nullable handle;
    unsigned long events;
    uint32_t status;
} AFD_Poll_Handle_Info;

typedef struct AFD_Poll_Info {
    int64_t timeout;
    unsigned long number_of_handles;
    unsigned long exclusive;
    AFD_Poll_Handle_Info handles[1];
} AFD_Poll_Info;

typedef enum Afd_Poll {
    AFD_POLL_RECEIVE = 0x0001,
    AFD_POLL_RECEIVE_EXPEDITED = 0x0002,
    AFD_POLL_SEND = 0x0004,
    AFD_POLL_DISCONNECT = 0x0008,
    AFD_POLL_ABORT = 0x0010,
    AFD_POLL_LOCAL_CLOSE = 0x0020,
    AFD_POLL_ACCEPT = 0x0080,
    AFD_POLL_CONNECT_FAIL = 0x0100,
} Afd_Poll;
#endif /* _WIN32 */

typedef struct OS_Ev {
    const Memory *_Nonnull mem;
    const Logger *_Nonnull log;

#ifdef EV_USE_EPOLL
    int epoll_fd;
#else
    /* The watches, and in the same order, what the system call is given for them. */
    Ev_Watch *_Nonnull *_Nullable watches;
    uint32_t watches_count;
    uint32_t watches_capacity;
    /* Where the next wait starts looking, so that every ready watch gets its turn. */
    uint32_t next_index;
#ifdef _WIN32
    AFD_Poll_Handle_Info *_Nullable handles;
    SOCKET helper_sock;
#else
    struct pollfd *_Nullable pfds;
#endif /* _WIN32 */
#endif /* EV_USE_EPOLL */
} OS_Ev;

#ifdef EV_USE_EPOLL

/** How many events one epoll_wait reports at most. */
#define OS_EV_MAX_EVENTS 64

static uint32_t events_to_epoll(Ev_Events events)
{
    uint32_t e = 0;

    if ((events & EV_READ) != 0) {
        // A peer that hung up is an error, not data: reads would find nothing to read.
        e |= EPOLLIN | EPOLLRDHUP;
    }

    if ((events & EV_WRITE) != 0) {
        e |= EPOLLOUT;
    }

    return e;
}

static Ev_Events epoll_to_events(uint32_t e)
{
    Ev_Events events = 0;

    if ((e & EPOLLIN) != 0) {
        events |= EV_READ;
    }

    if ((e & EPOLLOUT) != 0) {
        events |= EV_WRITE;
    }

    if ((e & (EPOLLERR | EPOLLHUP | EPOLLRDHUP)) != 0) {
        events |= EV_ERROR;
    }

    return events;
}

static bool os_ev_ctl(OS_Ev *_Nonnull os_ev, int op, Ev_Watch *_Nonnull watch, Socket sock, Ev_Events events)
{
    struct epoll_event ep_ev = {0};
    ep_ev.events = events_to_epoll(events);
    ep_ev.data.ptr = watch;

    if (epoll_ctl(os_ev->epoll_fd, op, net_socket_to_native(sock), &ep_ev) == -1) {
        Net_Strerror error_buf;
        LOGGER_ERROR(os_ev->log, "epoll_ctl(%d) failed for socket %d: %s", op, net_socket_to_native(sock),
                     net_strerror(errno, &error_buf));
        return false;
    }

    return true;
}

static bool os_ev_add(void *_Nonnull self, Ev_Watch *_Nonnull watch, Socket sock, Ev_Events events)
{
    OS_Ev *os_ev = (OS_Ev *)self;
    return os_ev_ctl(os_ev, EPOLL_CTL_ADD, watch, sock, events);
}

static bool os_ev_mod(void *_Nonnull self, Ev_Watch *_Nonnull watch, Socket sock, Ev_Events events)
{
    OS_Ev *os_ev = (OS_Ev *)self;
    return os_ev_ctl(os_ev, EPOLL_CTL_MOD, watch, sock, events);
}

static void os_ev_del(void *_Nonnull self, Ev_Watch *_Nonnull watch, Socket sock)
{
    OS_Ev *os_ev = (OS_Ev *)self;
    os_ev_ctl(os_ev, EPOLL_CTL_DEL, watch, sock, 0);
}

static int32_t os_ev_wait(void *_Nonnull self, Ev_Watch *_Nonnull *_Nonnull ready, Ev_Events *_Nonnull ready_events,
                          uint32_t max_ready, int32_t timeout_ms)
{
    OS_Ev *os_ev = (OS_Ev *)self;

    struct epoll_event events[OS_EV_MAX_EVENTS];
    const int max_events = max_ready < OS_EV_MAX_EVENTS ? (int)max_ready : OS_EV_MAX_EVENTS;
    const int n = epoll_wait(os_ev->epoll_fd, events, max_events, (int)timeout_ms);

    if (n < 0) {
        if (errno == EINTR) {
            return 0;
        }

        Net_Strerror error_buf;
        LOGGER_ERROR(os_ev->log, "epoll_wait failed: %s", net_strerror(errno, &error_buf));
        return -1;
    }

    for (int i = 0; i < n; ++i) {
        ready[i] = (Ev_Watch *)events[i].data.ptr;
        ready_events[i] = epoll_to_events(events[i].events);
    }

    return n;
}

#else

/** @brief Makes room for one more watch in the arrays. */
static bool os_ev_reserve(OS_Ev *_Nonnull os_ev)
{
    if (os_ev->watches_count >= EV_MAX_WATCHES) {
        return false;
    }

    if (os_ev->watches_count < os_ev->watches_capacity) {
        return true;
    }

    const uint32_t new_capacity = os_ev->watches_capacity == 0 ? 8 : os_ev->watches_capacity * 2;
    Ev_Watch **new_watches = (Ev_Watch **)mem_vrealloc(os_ev->mem, os_ev->watches, new_capacity, sizeof(Ev_Watch *));

    if (new_watches == nullptr) {
        return false;
    }

    os_ev->watches = new_watches;

#ifdef _WIN32
    AFD_Poll_Handle_Info *new_handles = (AFD_Poll_Handle_Info *)mem_vrealloc(
                                            os_ev->mem, os_ev->handles, new_capacity, sizeof(AFD_Poll_Handle_Info));

    if (new_handles == nullptr) {
        return false;
    }

    os_ev->handles = new_handles;
#else
    struct pollfd *new_pfds = (struct pollfd *)mem_vrealloc(os_ev->mem, os_ev->pfds, new_capacity, sizeof(struct pollfd));

    if (new_pfds == nullptr) {
        return false;
    }

    os_ev->pfds = new_pfds;
#endif /* _WIN32 */

    os_ev->watches_capacity = new_capacity;
    return true;
}

/** @brief Removes the watch at `index`, moving the last one into its place. */
static void os_ev_remove(OS_Ev *_Nonnull os_ev, uint32_t index)
{
    assert(index < os_ev->watches_count);
    const uint32_t last = os_ev->watches_count - 1;

    os_ev->watches[index] = os_ev->watches[last];
    ev_watch_set_backend_index(os_ev->watches[index], index);
#ifdef _WIN32
    os_ev->handles[index] = os_ev->handles[last];
#else
    os_ev->pfds[index] = os_ev->pfds[last];
#endif /* _WIN32 */

    --os_ev->watches_count;
}

#ifdef _WIN32

static uint32_t events_to_afd(Ev_Events events)
{
    uint32_t e = AFD_POLL_ABORT | AFD_POLL_LOCAL_CLOSE | AFD_POLL_CONNECT_FAIL;  // Always monitor errors

    if ((events & EV_READ) != 0) {
        e |= AFD_POLL_RECEIVE | AFD_POLL_RECEIVE_EXPEDITED | AFD_POLL_ACCEPT | AFD_POLL_DISCONNECT;
    }

    if ((events & EV_WRITE) != 0) {
        e |= AFD_POLL_SEND;
    }

    return e;
}

static Ev_Events afd_to_events(uint32_t e)
{
    Ev_Events events = 0;

    if ((e & (AFD_POLL_RECEIVE | AFD_POLL_RECEIVE_EXPEDITED | AFD_POLL_ACCEPT | AFD_POLL_DISCONNECT)) != 0) {
        events |= EV_READ;
    }

    if ((e & AFD_POLL_SEND) != 0) {
        events |= EV_WRITE;
    }

    if ((e & (AFD_POLL_ABORT | AFD_POLL_LOCAL_CLOSE | AFD_POLL_CONNECT_FAIL)) != 0) {
        events |= EV_ERROR;
    }

    return events;
}

static void os_ev_set(OS_Ev *_Nonnull os_ev, uint32_t index, Socket sock, Ev_Events events)
{
    AFD_Poll_Handle_Info *handle = &os_ev->handles[index];
    handle->handle = (HANDLE)(uintptr_t)net_socket_to_native(sock);
    handle->events = events_to_afd(events);
    handle->status = 0;
}

#else

static void os_ev_set(OS_Ev *_Nonnull os_ev, uint32_t index, Socket sock, Ev_Events events)
{
    struct pollfd *pfd = &os_ev->pfds[index];
    pfd->fd = net_socket_to_native(sock);
    pfd->events = 0;
    pfd->revents = 0;

    if ((events & EV_READ) != 0) {
        pfd->events |= POLLIN;
    }

    if ((events & EV_WRITE) != 0) {
        pfd->events |= POLLOUT;
    }
}

#endif /* _WIN32 */

static bool os_ev_add(void *_Nonnull self, Ev_Watch *_Nonnull watch, Socket sock, Ev_Events events)
{
    OS_Ev *os_ev = (OS_Ev *)self;

    if (!os_ev_reserve(os_ev)) {
        return false;
    }

    const uint32_t index = os_ev->watches_count;
    ev_watch_set_backend_index(watch, index);
    os_ev->watches[index] = watch;
    ++os_ev->watches_count;
    os_ev_set(os_ev, index, sock, events);
    return true;
}

static bool os_ev_mod(void *_Nonnull self, Ev_Watch *_Nonnull watch, Socket sock, Ev_Events events)
{
    OS_Ev *os_ev = (OS_Ev *)self;
    os_ev_set(os_ev, ev_watch_backend_index(watch), sock, events);
    return true;
}

static void os_ev_del(void *_Nonnull self, Ev_Watch *_Nonnull watch, Socket sock)
{
    OS_Ev *os_ev = (OS_Ev *)self;
    os_ev_remove(os_ev, ev_watch_backend_index(watch));
}

#ifdef _WIN32

/** @brief Finds the watch of a socket handle, looking at `hint` first. */
static Ev_Watch *_Nullable os_ev_find_watch(const OS_Ev *_Nonnull os_ev, const void *_Nullable handle, uint32_t hint)
{
    if (hint < os_ev->watches_count && os_ev->handles[hint].handle == handle) {
        return os_ev->watches[hint];
    }

    for (uint32_t i = 0; i < os_ev->watches_count; ++i) {
        if (os_ev->handles[i].handle == handle) {
            return os_ev->watches[i];
        }
    }

    return nullptr;
}

static int32_t os_ev_wait(void *_Nonnull self, Ev_Watch *_Nonnull *_Nonnull ready, Ev_Events *_Nonnull ready_events,
                          uint32_t max_ready, int32_t timeout_ms)
{
    OS_Ev *os_ev = (OS_Ev *)self;

    if (os_ev->watches_count == 0) {
        if (timeout_ms > 0) {
            Sleep(timeout_ms);
        }

        return 0;
    }

    const size_t info_size = sizeof(AFD_Poll_Info) + (os_ev->watches_count - 1) * sizeof(AFD_Poll_Handle_Info);
    AFD_Poll_Info *info = (AFD_Poll_Info *)HeapAlloc(GetProcessHeap(), 0, info_size);
    // AFD may leave the answer untouched when the poll times out, and may list only the ready
    // sockets, so it gets a zeroed buffer of its own and we find each socket by its handle.
    AFD_Poll_Info *out = (AFD_Poll_Info *)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, info_size);

    if (info == nullptr || out == nullptr) {
        if (info != nullptr) {
            HeapFree(GetProcessHeap(), 0, info);
        }

        if (out != nullptr) {
            HeapFree(GetProcessHeap(), 0, out);
        }

        return -1;
    }

    info->timeout = timeout_ms < 0 ? INT64_MAX : (int64_t)timeout_ms * -10000;
    info->number_of_handles = os_ev->watches_count;
    info->exclusive = 0;

    memcpy(info->handles, os_ev->handles, os_ev->watches_count * sizeof(AFD_Poll_Handle_Info));

    DWORD bytes_ret = 0;
    const BOOL ok = DeviceIoControl((HANDLE)os_ev->helper_sock, IOCTL_AFD_POLL, info, (DWORD)info_size, out,
                                    (DWORD)info_size, &bytes_ret, nullptr);
    HeapFree(GetProcessHeap(), 0, info);

    if (!ok) {
        const int err = net_error();
        HeapFree(GetProcessHeap(), 0, out);

        if (err == WAIT_TIMEOUT) {
            return 0;
        }

        Net_Strerror error_buf;
        LOGGER_ERROR(os_ev->log, "AFD_POLL failed: %s", net_strerror(err, &error_buf));
        return -1;
    }

    uint32_t count = 0;
    const uint32_t handles_count = out->number_of_handles < os_ev->watches_count ? out->number_of_handles : os_ev->watches_count;
    const uint32_t start = handles_count == 0 ? 0 : os_ev->next_index % handles_count;

    for (uint32_t k = 0; k < handles_count && count < max_ready; ++k) {
        const uint32_t i = (start + k) % handles_count;

        if (out->handles[i].events == 0) {
            continue;
        }

        os_ev->next_index = i + 1;

        Ev_Watch *watch = os_ev_find_watch(os_ev, out->handles[i].handle, i);

        if (watch != nullptr) {
            ready[count] = watch;
            ready_events[count] = afd_to_events(out->handles[i].events);
            ++count;
        }
    }

    HeapFree(GetProcessHeap(), 0, out);
    return (int32_t)count;
}

#else

static int32_t os_ev_wait(void *_Nonnull self, Ev_Watch *_Nonnull *_Nonnull ready, Ev_Events *_Nonnull ready_events,
                          uint32_t max_ready, int32_t timeout_ms)
{
    OS_Ev *os_ev = (OS_Ev *)self;

    const int n = poll(os_ev->pfds, (nfds_t)os_ev->watches_count, (int)timeout_ms);

    if (n < 0) {
        if (errno == EINTR) {
            return 0;
        }

        Net_Strerror error_buf;
        LOGGER_ERROR(os_ev->log, "poll failed: %s", net_strerror(errno, &error_buf));
        return -1;
    }

    uint32_t count = 0;
    const uint32_t start = os_ev->watches_count == 0 ? 0 : os_ev->next_index % os_ev->watches_count;

    for (uint32_t k = 0; k < os_ev->watches_count && count < max_ready; ++k) {
        const uint32_t i = (start + k) % os_ev->watches_count;
        const int revents = os_ev->pfds[i].revents;

        if (revents == 0) {
            continue;
        }

        os_ev->next_index = i + 1;

        Ev_Events events = 0;

        if ((revents & POLLIN) != 0) {
            events |= EV_READ;
        }

        if ((revents & POLLOUT) != 0) {
            events |= EV_WRITE;
        }

        if ((revents & (POLLERR | POLLHUP | POLLNVAL)) != 0) {
            events |= EV_ERROR;
        }

        ready[count] = os_ev->watches[i];
        ready_events[count] = events;

        ++count;
    }

    return (int32_t)count;
}

#endif /* _WIN32 */
#endif /* EV_USE_EPOLL */

static void os_ev_kill(void *_Nonnull self)
{
    OS_Ev *os_ev = (OS_Ev *)self;
    const Memory *mem = os_ev->mem;

#ifdef EV_USE_EPOLL
    close(os_ev->epoll_fd);
#else
    assert(os_ev->watches_count == 0);
    mem_delete(mem, os_ev->watches);
#ifdef _WIN32
    closesocket(os_ev->helper_sock);
    mem_delete(mem, os_ev->handles);
#else
    mem_delete(mem, os_ev->pfds);
#endif /* _WIN32 */
#endif /* EV_USE_EPOLL */

    mem_delete(mem, os_ev);
}

static const Ev_Funcs os_ev_funcs = {
    os_ev_add,
    os_ev_mod,
    os_ev_del,
    os_ev_wait,
    os_ev_kill,
};

Ev *os_event_new(const Memory *mem, const Logger *log)
{
    OS_Ev *os_ev = (OS_Ev *)mem_alloc(mem, sizeof(OS_Ev));

    if (os_ev == nullptr) {
        return nullptr;
    }

    os_ev->mem = mem;
    os_ev->log = log;

#ifdef EV_USE_EPOLL
    os_ev->epoll_fd = epoll_create1(EPOLL_CLOEXEC);

    if (os_ev->epoll_fd == -1) {
        Net_Strerror error_buf;
        LOGGER_ERROR(log, "Failed to create epoll fd: %s", net_strerror(errno, &error_buf));
        mem_delete(mem, os_ev);
        return nullptr;
    }
#elif defined(_WIN32)
    // Create a dummy socket for AFD communication
    os_ev->helper_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);

    if (os_ev->helper_sock == INVALID_SOCKET) {
        Net_Strerror error_buf;
        LOGGER_ERROR(log, "Failed to create helper socket: %s", net_strerror(net_error(), &error_buf));
        mem_delete(mem, os_ev);
        return nullptr;
    }
#endif /* EV_USE_EPOLL */

    Ev *ev = ev_new(mem, &os_ev_funcs, os_ev);

    if (ev == nullptr) {
        os_ev_kill(os_ev);
        return nullptr;
    }

    LOGGER_DEBUG(log, "Created new os_event loop");

    return ev;
}
