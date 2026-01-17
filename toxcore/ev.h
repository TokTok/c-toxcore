/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2026 The TokTok team.
 */

#ifndef C_TOXCORE_TOXCORE_EV_H
#define C_TOXCORE_TOXCORE_EV_H

#include <stdbool.h>
#include <stdint.h>

#include "attributes.h"
#include "mem.h"
#include "net.h"  // For Socket

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief An event loop: waits for sockets to become ready and calls their
 *   handlers.
 */
typedef struct Ev Ev;

/** @brief A watched socket. */
typedef struct Ev_Watch Ev_Watch;

/** @brief Event types to monitor. */
typedef uint8_t Ev_Events;

#define EV_READ  (1U << 0)
#define EV_WRITE (1U << 1)
#define EV_ERROR (1U << 2)

/**
 * @brief How many sockets one event loop watches at most: enough for a TCP
 *   relay's connections, and as many again for everything else.
 */
#define EV_MAX_WATCHES 65536

/**
 * @brief Handles the events of a ready socket.
 *
 * @param obj The object passed to `ev_add`.
 * @param key The key the socket was added or last modified with.
 * @param events The events that occurred. EV_ERROR is reported even if not
 *   asked for.
 */
typedef void ev_handler_cb(void *_Nullable obj, uint32_t key, Ev_Events events);

/**
 * @brief Starts watching a socket.
 *
 * @param handler Called by `ev_run` when the socket is ready. Without one, a
 *   ready socket only ends the wait.
 *
 * @return The watch, to pass to `ev_mod` and `ev_del`, or null on failure.
 *   Delete it with `ev_del` before closing the socket.
 */
Ev_Watch *_Nullable ev_add(Ev *_Nonnull ev, Socket sock, Ev_Events events, ev_handler_cb *_Nullable handler,
                           void *_Nullable obj, uint32_t key);

/** @brief Changes the events and key of a watch. */
bool ev_mod(Ev *_Nonnull ev, Ev_Watch *_Nonnull watch, Ev_Events events, uint32_t key);

/** @brief Stops watching a socket. Can be called from a handler. */
void ev_del(Ev *_Nonnull ev, Ev_Watch *_Nullable watch);

/**
 * @brief Waits for sockets to become ready and calls their handlers.
 *
 * @param timeout_ms How long to wait: 0 doesn't wait, -1 waits until a socket
 *   is ready.
 *
 * Handles every socket that is ready, each at least once. One whose handler
 * leaves it ready may be handled again in the same call.
 *
 * @return The number of times a socket was found ready, or -1 on error.
 */
int32_t ev_run(Ev *_Nonnull ev, int32_t timeout_ms);

/** @brief Frees the event loop. All its watches must have been deleted. */
void ev_kill(Ev *_Nullable ev);

/*
 * The interface for event loop backends.
 */

typedef bool ev_add_cb(void *_Nullable self, Ev_Watch *_Nonnull watch, Socket sock, Ev_Events events);
typedef bool ev_mod_cb(void *_Nullable self, Ev_Watch *_Nonnull watch, Socket sock, Ev_Events events);
typedef void ev_del_cb(void *_Nullable self, Ev_Watch *_Nonnull watch, Socket sock);

/**
 * @brief Waits up to `timeout_ms` and reports at most `max_ready` ready
 *   watches, with the events of `ready[i]` in `ready_events[i]`.
 *
 * When more are ready, the next call must go on with the others, so that
 * repeated calls get to all of them.
 *
 * @return The number of ready watches, or -1 on error.
 */
typedef int32_t ev_wait_cb(void *_Nullable self, Ev_Watch *_Nonnull ready[_Nonnull], Ev_Events ready_events[_Nonnull],
                           uint32_t max_ready, int32_t timeout_ms);
typedef void ev_kill_cb(void *_Nullable self);

/** @brief The functions an event loop backend implements. */
typedef struct Ev_Funcs {
    ev_add_cb *_Nonnull add_callback;
    ev_mod_cb *_Nonnull mod_callback;
    ev_del_cb *_Nonnull del_callback;
    ev_wait_cb *_Nonnull wait_callback;
    ev_kill_cb *_Nonnull kill_callback;
} Ev_Funcs;

/** @brief Creates an event loop on a backend, which `ev_kill` frees with its kill callback. */
Ev *_Nullable ev_new(const Memory *_Nonnull mem, const Ev_Funcs *_Nonnull funcs, void *_Nullable self);

/** @brief A number the backend keeps for a watch, e.g. its index in the backend's arrays. */
uint32_t ev_watch_backend_index(const Ev_Watch *_Nonnull watch);
void ev_watch_set_backend_index(Ev_Watch *_Nonnull watch, uint32_t index);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* C_TOXCORE_TOXCORE_EV_H */
