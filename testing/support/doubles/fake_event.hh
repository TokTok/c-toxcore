#ifndef C_TOXCORE_TESTING_SUPPORT_DOUBLES_FAKE_EVENT_H
#define C_TOXCORE_TESTING_SUPPORT_DOUBLES_FAKE_EVENT_H

#include <cstddef>
#include <cstdint>
#include <vector>

#include "../../../toxcore/attributes.h"
#include "../../../toxcore/ev.h"
#include "../../../toxcore/mem.h"
#include "../../../toxcore/tox_private.h"
#include "fake_network_stack.hh"

namespace tox::test {

/**
 * @brief An event loop backend for the sockets of a fake network stack.
 *
 * It never waits: the simulation advances time itself.
 */
class FakeEvent {
public:
    /** @brief Creates an event loop on `net`'s sockets, which `ev_kill` frees. */
    static Ev *_Nullable create(FakeNetworkStack &net, const Memory *_Nonnull mem);

    /** @brief The same, as a `tox_ev_new_cb`: `user_data` is the FakeNetworkStack. */
    static Ev *_Nullable tox_ev_new(
        void *_Nullable user_data, const Memory *_Nonnull mem, const Logger *_Nonnull log);

    // The backend functions, called by the event loop.
    bool add(Ev_Watch *_Nonnull watch, Socket sock, Ev_Events events);
    bool mod(Ev_Watch *_Nonnull watch, Ev_Events events);
    void del(Ev_Watch *_Nonnull watch);
    int32_t wait(
        Ev_Watch *_Nonnull *_Nonnull ready, Ev_Events *_Nonnull ready_events, uint32_t max_ready);

private:
    explicit FakeEvent(FakeNetworkStack &net);

    struct Watched {
        Ev_Watch *_Nonnull watch;
        Socket sock;
        Ev_Events events;
    };

    static const Ev_Funcs kFuncs;

    FakeNetworkStack &net_;
    std::vector<Watched> watched_;
    // Where the next wait starts looking, so that every ready socket gets its turn.
    std::size_t next_index_ = 0;
};

}  // namespace tox::test

#endif  // C_TOXCORE_TESTING_SUPPORT_DOUBLES_FAKE_EVENT_H
