#ifndef C_TOXCORE_TESTING_SUPPORT_DOUBLES_FAKE_EVENT_H
#define C_TOXCORE_TESTING_SUPPORT_DOUBLES_FAKE_EVENT_H

#include <map>
#include <mutex>
#include <vector>

#include "../../../toxcore/ev.h"
#include "fake_network_stack.hh"

namespace tox::test {

class FakeEvent {
public:
    explicit FakeEvent(FakeNetworkStack &net);
    ~FakeEvent();

    struct Ev *c_event();

    bool add(Socket sock, Ev_Events events, void *data);
    bool mod(Socket sock, Ev_Events events, void *data);
    bool del(Socket sock);
    int32_t run(Ev_Result results[], uint32_t max_results, int32_t timeout_ms);

private:
    FakeNetworkStack &net_;
    struct MonitoredSocket {
        Ev_Events events;
        void *data;
    };
    std::map<int, MonitoredSocket> monitored_;
    std::mutex mutex_;
    struct Ev c_ev_;
};

}  // namespace tox::test

#endif  // C_TOXCORE_TESTING_SUPPORT_DOUBLES_FAKE_EVENT_H
