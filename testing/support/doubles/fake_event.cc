#include "fake_event.hh"

#include <algorithm>
#include <iostream>

#include "../../../toxcore/net.h"

namespace tox::test {

static const Ev_Funcs kEventVtable = {
    .add_callback
    = [](void *self, Socket sock, Ev_Events events,
          void *data) { return static_cast<FakeEvent *>(self)->add(sock, events, data); },
    .mod_callback
    = [](void *self, Socket sock, Ev_Events events,
          void *data) { return static_cast<FakeEvent *>(self)->mod(sock, events, data); },
    .del_callback
    = [](void *self, Socket sock) { return static_cast<FakeEvent *>(self)->del(sock); },
    .run_callback =
        [](void *self, Ev_Result results[], uint32_t max_results, int32_t timeout_ms) {
            return static_cast<FakeEvent *>(self)->run(results, max_results, timeout_ms);
        },
    .kill_callback = [](Ev *ev) { delete static_cast<FakeEvent *>(ev->user_data); },
};

FakeEvent::FakeEvent(FakeNetworkStack &net)
    : net_(net)
{
    c_ev_.funcs = &kEventVtable;
    c_ev_.user_data = this;
}

FakeEvent::~FakeEvent() = default;

struct Ev *FakeEvent::c_event() { return &c_ev_; }

bool FakeEvent::add(Socket sock, Ev_Events events, void *data)
{
    std::lock_guard<std::mutex> lock(mutex_);
    int fd = net_socket_to_native(sock);
    if (monitored_.find(fd) != monitored_.end()) {
        return false;
    }
    monitored_[fd] = {events, data};
    return true;
}

bool FakeEvent::mod(Socket sock, Ev_Events events, void *data)
{
    std::lock_guard<std::mutex> lock(mutex_);
    int fd = net_socket_to_native(sock);
    auto it = monitored_.find(fd);
    if (it == monitored_.end()) {
        return false;
    }
    it->second = {events, data};
    return true;
}

bool FakeEvent::del(Socket sock)
{
    std::lock_guard<std::mutex> lock(mutex_);
    int fd = net_socket_to_native(sock);
    return monitored_.erase(fd) > 0;
}

int32_t FakeEvent::run(Ev_Result results[], uint32_t max_results, int32_t timeout_ms)
{
    std::lock_guard<std::mutex> lock(mutex_);
    uint32_t count = 0;

    for (const auto &pair : monitored_) {
        if (count >= max_results)
            break;

        int fd = pair.first;
        const auto &mon = pair.second;
        Socket sock = net_socket_from_native(fd);

        Ev_Events triggered = 0;

        FakeSocket *fs = net_.get_sock(sock);
        if (!fs) {
            // Socket closed?
            triggered |= EV_ERROR;
        } else {
            if ((mon.events & EV_READ) && fs->is_readable()) {
                triggered |= EV_READ;
            }
            if ((mon.events & EV_WRITE) && fs->is_writable()) {
                triggered |= EV_WRITE;
            }
        }

        if (triggered) {
            results[count].sock = sock;
            results[count].events = triggered;
            results[count].data = mon.data;
            count++;
        }
    }

    return count;
}

}  // namespace tox::test
