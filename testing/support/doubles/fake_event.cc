#include "fake_event.hh"

#include <algorithm>

namespace tox::test {

const Ev_Funcs FakeEvent::kFuncs = {
    [](void *self, Ev_Watch *watch, Socket sock, Ev_Events events) {
        return static_cast<FakeEvent *>(self)->add(watch, sock, events);
    },
    [](void *self, Ev_Watch *watch, Socket sock, Ev_Events events) {
        return static_cast<FakeEvent *>(self)->mod(watch, events);
    },
    [](void *self, Ev_Watch *watch, Socket sock) { static_cast<FakeEvent *>(self)->del(watch); },
    [](void *self, Ev_Watch *ready[], Ev_Events ready_events[], uint32_t max_ready,
        int32_t timeout_ms) {
        return static_cast<FakeEvent *>(self)->wait(ready, ready_events, max_ready);
    },
    [](void *self) { delete static_cast<FakeEvent *>(self); },
};

Ev *FakeEvent::create(FakeNetworkStack &net, const Memory *mem)
{
    auto *fake = new FakeEvent(net);
    Ev *ev = ev_new(mem, &kFuncs, fake);

    if (ev == nullptr) {
        delete fake;
    }

    return ev;
}

Ev *FakeEvent::tox_ev_new(void *user_data, const Memory *mem, const Logger *log)
{
    return create(*static_cast<FakeNetworkStack *>(user_data), mem);
}

FakeEvent::FakeEvent(FakeNetworkStack &net)
    : net_(net)
{
}

bool FakeEvent::add(Ev_Watch *watch, Socket sock, Ev_Events events)
{
    if (net_.get_sock(sock) == nullptr) {
        return false;
    }

    watched_.push_back({watch, sock, events});
    return true;
}

bool FakeEvent::mod(Ev_Watch *watch, Ev_Events events)
{
    const auto it = std::find_if(
        watched_.begin(), watched_.end(), [watch](const Watched &w) { return w.watch == watch; });

    if (it == watched_.end()) {
        return false;
    }

    it->events = events;
    return true;
}

void FakeEvent::del(Ev_Watch *watch)
{
    watched_.erase(std::remove_if(watched_.begin(), watched_.end(),
                       [watch](const Watched &w) { return w.watch == watch; }),
        watched_.end());
}

int32_t FakeEvent::wait(Ev_Watch **ready, Ev_Events *ready_events, uint32_t max_ready)
{
    uint32_t count = 0;
    const std::size_t start = watched_.empty() ? 0 : next_index_ % watched_.size();

    for (std::size_t k = 0; k < watched_.size() && count < max_ready; ++k) {
        const std::size_t index = (start + k) % watched_.size();
        const Watched &w = watched_[index];

        FakeSocket *sock = net_.get_sock(w.sock);
        Ev_Events events = 0;

        const auto *tcp_sock = sock != nullptr && sock->type() == SOCK_STREAM
            ? static_cast<const FakeTcpSocket *>(sock)
            : nullptr;

        if (sock == nullptr
            || (tcp_sock != nullptr
                && (tcp_sock->state() == FakeTcpSocket::CLOSED
                    || tcp_sock->state() == FakeTcpSocket::CLOSE_WAIT))) {
            // Like epoll's EPOLLRDHUP: a peer that hung up is an error.
            events |= EV_ERROR;
        } else {
            if ((w.events & EV_READ) != 0 && sock->is_readable()) {
                events |= EV_READ;
            }

            if ((w.events & EV_WRITE) != 0 && sock->is_writable()) {
                events |= EV_WRITE;
            }
        }

        if (events != 0) {
            next_index_ = index + 1;
            ready[count] = w.watch;
            ready_events[count] = events;
            ++count;
        }
    }

    return static_cast<int32_t>(count);
}

}  // namespace tox::test
