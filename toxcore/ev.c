/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2026 The TokTok team.
 */

#include "ev.h"

#include <assert.h>

#include "ccompat.h"
#include "mem.h"

/** How many ready sockets the backend reports at a time. */
#define EV_MAX_READY 64

struct Ev_Watch {
    Socket sock;
    Ev_Events events;
    ev_handler_cb *_Nullable handler;
    void *_Nullable obj;
    uint32_t key;

    uint32_t backend_index;

    /** Deleted during `ev_run`; freed when it returns. */
    bool deleted;
    Ev_Watch *_Nullable next_deleted;
};

struct Ev {
    const Memory *_Nonnull mem;
    const Ev_Funcs *_Nonnull funcs;
    void *_Nullable self;

    uint32_t watches_count;
    bool running;
    Ev_Watch *_Nullable deleted;
};

Ev *ev_new(const Memory *mem, const Ev_Funcs *funcs, void *self)
{
    Ev *ev = (Ev *)mem_alloc(mem, sizeof(Ev));

    if (ev == nullptr) {
        return nullptr;
    }

    ev->mem = mem;
    ev->funcs = funcs;
    ev->self = self;
    return ev;
}

Ev_Watch *ev_add(Ev *ev, Socket sock, Ev_Events events, ev_handler_cb *handler, void *obj, uint32_t key)
{
    if (ev->watches_count >= EV_MAX_WATCHES) {
        return nullptr;
    }

    Ev_Watch *watch = (Ev_Watch *)mem_alloc(ev->mem, sizeof(Ev_Watch));

    if (watch == nullptr) {
        return nullptr;
    }

    watch->sock = sock;
    watch->events = events;
    watch->handler = handler;
    watch->obj = obj;
    watch->key = key;

    if (!ev->funcs->add_callback(ev->self, watch, sock, events)) {
        mem_delete(ev->mem, watch);
        return nullptr;
    }

    ++ev->watches_count;
    return watch;
}

bool ev_mod(Ev *ev, Ev_Watch *watch, Ev_Events events, uint32_t key)
{
    assert(!watch->deleted);
    watch->key = key;

    if (events == watch->events) {
        return true;
    }

    if (!ev->funcs->mod_callback(ev->self, watch, watch->sock, events)) {
        return false;
    }

    watch->events = events;
    return true;
}

void ev_del(Ev *ev, Ev_Watch *watch)
{
    if (watch == nullptr) {
        return;
    }

    assert(!watch->deleted);
    ev->funcs->del_callback(ev->self, watch, watch->sock);
    --ev->watches_count;

    if (ev->running) {
        // A later ready watch in this run may be this one.
        watch->deleted = true;
        watch->next_deleted = ev->deleted;
        ev->deleted = watch;
        return;
    }

    mem_delete(ev->mem, watch);
}

int32_t ev_run(Ev *ev, int32_t timeout_ms)
{
    assert(!ev->running);

    Ev_Watch *ready[EV_MAX_READY];
    Ev_Events ready_events[EV_MAX_READY];

    // A full batch may not be all that's ready, so we ask again, but no more often than it
    // takes to report every watch once: a socket nobody reads from stays ready.
    const uint32_t max_batches = ev->watches_count / EV_MAX_READY + 1;
    int32_t total = 0;

    ev->running = true;

    for (uint32_t batch = 0; batch < max_batches; ++batch) {
        const int32_t count = ev->funcs->wait_callback(ev->self, ready, ready_events, EV_MAX_READY,
                              batch == 0 ? timeout_ms : 0);

        if (count < 0) {
            if (total == 0) {
                total = -1;
            }

            break;
        }

        for (int32_t i = 0; i < count; ++i) {
            const Ev_Watch *watch = ready[i];

            if (!watch->deleted && watch->handler != nullptr) {
                watch->handler(watch->obj, watch->key, ready_events[i] & (watch->events | EV_ERROR));
            }
        }

        total += count;

        if (count < EV_MAX_READY) {
            break;
        }
    }

    ev->running = false;

    while (ev->deleted != nullptr) {
        Ev_Watch *next = ev->deleted->next_deleted;
        mem_delete(ev->mem, ev->deleted);
        ev->deleted = next;
    }

    return total;
}

void ev_kill(Ev *ev)
{
    if (ev == nullptr) {
        return;
    }

    assert(ev->watches_count == 0);
    ev->funcs->kill_callback(ev->self);
    mem_delete(ev->mem, ev);
}

uint32_t ev_watch_backend_index(const Ev_Watch *watch)
{
    return watch->backend_index;
}

void ev_watch_set_backend_index(Ev_Watch *watch, uint32_t index)
{
    watch->backend_index = index;
}
