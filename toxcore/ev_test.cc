/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2026 The TokTok team.
 */

#include "ev.h"

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <cstddef>
#include <vector>

#include "ev_test_util.hh"
#include "logger.h"
#include "net.h"
#include "os_event.h"
#include "os_memory.h"
#include "os_network.h"

#ifndef _WIN32
#include <unistd.h>
#endif

namespace {

class EvTest : public ::testing::Test {
    static void logger_cb_stderr(void *context, Logger_Level level, const char *file, uint32_t line,
        const char *func, const char *message, void *userdata)
    {
        fprintf(stderr, "[%d] %s:%u: %s: %s\n", level, file, line, func, message);
    }

protected:
    struct Call {
        uint32_t key;
        Ev_Events events;

        bool operator==(const Call &other) const
        {
            return key == other.key && events == other.events;
        }
    };

    void SetUp() override
    {
        ASSERT_NE(os_network(), nullptr);  // WSAStartup
        mem = os_memory();
        log = logger_new(mem);
        logger_callback_log(log, logger_cb_stderr, nullptr, nullptr);
        ev = os_event_new(mem, log);
        ASSERT_NE(ev, nullptr);
    }

    void TearDown() override
    {
        ev_kill(ev);
        logger_kill(log);
    }

    static void record(void *obj, uint32_t key, Ev_Events events)
    {
        static_cast<EvTest *>(obj)->calls.push_back({key, events});
    }

    Ev_Watch *add(Socket sock, Ev_Events events, uint32_t key)
    {
        return ev_add(ev, sock, events, record, this, key);
    }

    const Memory *mem;
    Logger *log;
    Ev *ev;
    std::vector<Call> calls;
};

TEST_F(EvTest, AddDel)
{
    Socket s1{}, s2{};
    ASSERT_EQ(create_pair(&s1, &s2), 0);

    Ev_Watch *w1 = add(s1, EV_READ, 1);
    Ev_Watch *w2 = add(s2, EV_WRITE, 2);
    EXPECT_NE(w1, nullptr);
    EXPECT_NE(w2, nullptr);

    ev_del(ev, w1);
    ev_del(ev, w2);
    ev_del(ev, nullptr);

    close_pair(s1, s2);
}

TEST_F(EvTest, RunPipe)
{
    Socket rs{}, ws{};
    ASSERT_EQ(create_pair(&rs, &ws), 0);

    Ev_Watch *w = add(rs, EV_READ, 4);
    ASSERT_NE(w, nullptr);

    // Should timeout immediately
    EXPECT_EQ(ev_run(ev, 0), 0);
    EXPECT_TRUE(calls.empty());

    // Write something to the pipe/socket
    char buf = 'x';
    ASSERT_EQ(write_socket(ws, &buf, 1), 1);

    // Should now be readable
    EXPECT_EQ(ev_run(ev, 100), 1);
    EXPECT_EQ(calls, (std::vector<Call>{{4, EV_READ}}));

    ev_del(ev, w);
    close_pair(rs, ws);
}

TEST_F(EvTest, WriteEvent)
{
    Socket rs{}, ws{};
    ASSERT_EQ(create_pair(&rs, &ws), 0);

    // Register write end for EV_WRITE
    Ev_Watch *w = add(ws, EV_WRITE, 1);
    ASSERT_NE(w, nullptr);

    // Should be immediately writable
    EXPECT_EQ(ev_run(ev, 100), 1);
    EXPECT_EQ(calls, (std::vector<Call>{{1, EV_WRITE}}));

    ev_del(ev, w);
    close_pair(rs, ws);
}

TEST_F(EvTest, Mod)
{
    Socket rs{}, ws{};
    ASSERT_EQ(create_pair(&rs, &ws), 0);

    Ev_Watch *w = add(rs, EV_WRITE, 1);
    ASSERT_NE(w, nullptr);
    EXPECT_TRUE(ev_mod(ev, w, EV_READ, 2));

    // Write something to the pipe/socket to make it readable
    char buf = 'x';
    ASSERT_EQ(write_socket(ws, &buf, 1), 1);

    EXPECT_EQ(ev_run(ev, 100), 1);
    EXPECT_EQ(calls, (std::vector<Call>{{2, EV_READ}}));

    ev_del(ev, w);
    close_pair(rs, ws);
}

TEST_F(EvTest, MultipleEvents)
{
    Socket rs1{}, ws1{};
    Socket rs2{}, ws2{};
    ASSERT_EQ(create_pair(&rs1, &ws1), 0);
    ASSERT_EQ(create_pair(&rs2, &ws2), 0);

    Ev_Watch *w1 = add(rs1, EV_READ, 1);
    Ev_Watch *w2 = add(rs2, EV_READ, 2);

    char buf = 'x';
    ASSERT_EQ(write_socket(ws1, &buf, 1), 1);
    ASSERT_EQ(write_socket(ws2, &buf, 1), 1);

    EXPECT_EQ(ev_run(ev, 100), 2);
    EXPECT_THAT(calls, ::testing::UnorderedElementsAre(Call{1, EV_READ}, Call{2, EV_READ}));

    ev_del(ev, w1);
    ev_del(ev, w2);
    close_pair(rs1, ws1);
    close_pair(rs2, ws2);
}

TEST_F(EvTest, StaysReadyUntilRead)
{
    Socket rs{}, ws{};
    ASSERT_EQ(create_pair(&rs, &ws), 0);
    Ev_Watch *w = add(rs, EV_READ, 1);

    char buf = 'x';
    ASSERT_EQ(write_socket(ws, &buf, 1), 1);

    EXPECT_EQ(ev_run(ev, 100), 1);
    EXPECT_EQ(ev_run(ev, 100), 1);

    ev_del(ev, w);
    close_pair(rs, ws);
}

TEST_F(EvTest, EmptyLoop)
{
    // Should timeout immediately
    EXPECT_EQ(ev_run(ev, 10), 0);
}

TEST_F(EvTest, WithoutHandlerOnlyEndsTheWait)
{
    Socket rs{}, ws{};
    ASSERT_EQ(create_pair(&rs, &ws), 0);
    Ev_Watch *w = ev_add(ev, rs, EV_READ, nullptr, nullptr, 0);
    ASSERT_NE(w, nullptr);

    char buf = 'x';
    ASSERT_EQ(write_socket(ws, &buf, 1), 1);

    EXPECT_EQ(ev_run(ev, 100), 1);

    ev_del(ev, w);
    close_pair(rs, ws);
}

TEST_F(EvTest, ErrorEvent)
{
    Socket rs{}, ws{};
    ASSERT_EQ(create_pair(&rs, &ws), 0);

    Ev_Watch *w = add(rs, EV_READ, 1);

    // Close the write end to potentially trigger something on the read end
    close_socket(ws);

    // On Linux, closing the write end of a pipe makes the read end readable (EOF).
    EXPECT_EQ(ev_run(ev, 100), 1);
    ASSERT_EQ(calls.size(), 1);
    EXPECT_EQ(calls[0].key, 1);

    ev_del(ev, w);
    close_socket(rs);
}

// A handler can delete a watch that is also ready in the same run.
TEST_F(EvTest, HandlerDeletesAnotherReadyWatch)
{
    Socket rs1{}, ws1{};
    Socket rs2{}, ws2{};
    ASSERT_EQ(create_pair(&rs1, &ws1), 0);
    ASSERT_EQ(create_pair(&rs2, &ws2), 0);

    struct Deleter {
        Ev *ev;
        Ev_Watch *watches[2];
        int calls;
    } deleter{ev, {}, 0};

    const auto delete_both = [](void *obj, uint32_t key, Ev_Events events) {
        Deleter *d = static_cast<Deleter *>(obj);
        ++d->calls;
        ev_del(d->ev, d->watches[0]);
        ev_del(d->ev, d->watches[1]);
        d->watches[0] = nullptr;
        d->watches[1] = nullptr;
    };
    deleter.watches[0] = ev_add(ev, rs1, EV_READ, delete_both, &deleter, 1);
    deleter.watches[1] = ev_add(ev, rs2, EV_READ, delete_both, &deleter, 2);

    char buf = 'x';
    ASSERT_EQ(write_socket(ws1, &buf, 1), 1);
    ASSERT_EQ(write_socket(ws2, &buf, 1), 1);

    EXPECT_EQ(ev_run(ev, 100), 2);
    EXPECT_EQ(deleter.calls, 1);

    close_pair(rs1, ws1);
    close_pair(rs2, ws2);
}

TEST_F(EvTest, ManyWatches)
{
    Socket rs{}, ws{};
    ASSERT_EQ(create_pair(&rs, &ws), 0);
    Ev_Watch *w = add(rs, EV_READ, 1);

    // Enough watches for the backend to grow its arrays.
    std::vector<Socket> extra_sockets_r;
    std::vector<Socket> extra_sockets_w;
    std::vector<Ev_Watch *> extra_watches;

    for (uint32_t i = 0; i < 20; ++i) {
        Socket r{}, wr{};
        ASSERT_EQ(create_pair(&r, &wr), 0);
        extra_sockets_r.push_back(r);
        extra_sockets_w.push_back(wr);
        extra_watches.push_back(add(r, EV_READ, 100 + i));
        ASSERT_NE(extra_watches.back(), nullptr);
    }

    // Deleting from the middle moves another watch into its place.
    ev_del(ev, extra_watches[5]);
    extra_watches[5] = nullptr;

    char buf = 'x';
    ASSERT_EQ(write_socket(ws, &buf, 1), 1);
    ASSERT_EQ(write_socket(extra_sockets_w[19], &buf, 1), 1);

    EXPECT_EQ(ev_run(ev, 100), 2);
    EXPECT_THAT(calls, ::testing::UnorderedElementsAre(Call{1, EV_READ}, Call{119, EV_READ}));

    ev_del(ev, w);
    close_pair(rs, ws);
    for (std::size_t i = 0; i < extra_sockets_r.size(); ++i) {
        ev_del(ev, extra_watches[i]);
        close_pair(extra_sockets_r[i], extra_sockets_w[i]);
    }
}

// A relay has far more connections than the backend reports at a time. None of them may
// have to wait for a later run.
TEST_F(EvTest, HandlesEveryReadySocketInOneRun)
{
    constexpr uint32_t kSockets = 200;

    struct Handled {
        Ev *ev;
        std::vector<Ev_Watch *> watches;
        std::vector<uint32_t> handled;
    } ctx{ev, {}, {}};

    // Stops watching the socket, so that it's not found ready again.
    const auto handle = [](void *obj, uint32_t key, Ev_Events events) {
        auto *c = static_cast<Handled *>(obj);
        ev_del(c->ev, c->watches[key]);
        c->watches[key] = nullptr;
        c->handled.push_back(key);
    };

    std::vector<Socket> sockets_r;
    std::vector<Socket> sockets_w;

    for (uint32_t i = 0; i < kSockets; ++i) {
        Socket r{}, w{};
        ASSERT_EQ(create_pair(&r, &w), 0);
        sockets_r.push_back(r);
        sockets_w.push_back(w);
        ctx.watches.push_back(ev_add(ev, r, EV_READ, handle, &ctx, i));
        ASSERT_NE(ctx.watches.back(), nullptr);

        char buf = 'x';
        ASSERT_EQ(write_socket(w, &buf, 1), 1);
    }

    EXPECT_EQ(ev_run(ev, 100), static_cast<int32_t>(kSockets));

    std::vector<uint32_t> all(kSockets);
    for (uint32_t i = 0; i < kSockets; ++i) {
        all[i] = i;
    }
    EXPECT_THAT(ctx.handled, ::testing::UnorderedElementsAreArray(all));

    for (uint32_t i = 0; i < kSockets; ++i) {
        ev_del(ev, ctx.watches[i]);
        close_pair(sockets_r[i], sockets_w[i]);
    }
}

#ifdef EV_USE_EPOLL
TEST(EvManualTest, ExhaustFds)
{
    ASSERT_NE(os_network(), nullptr);
    const Memory *mem = os_memory();
    Logger *log = logger_new(mem);

    // Consume all file descriptors
    std::vector<int> fds;
    while (true) {
        int fd = dup(0);
        if (fd < 0) {
            break;
        }
        fds.push_back(fd);
    }

    // New event loop creation should fail gracefully
    Ev *ev = os_event_new(mem, log);
    EXPECT_EQ(ev, nullptr);

    // Release one FD and try again (epoll_create needs 1 FD)
    if (!fds.empty()) {
        close(fds.back());
        fds.pop_back();

        ev = os_event_new(mem, log);
        EXPECT_NE(ev, nullptr);
        ev_kill(ev);
    }

    // Cleanup
    for (int fd : fds) {
        close(fd);
    }
    logger_kill(log);
}
#endif  // EV_USE_EPOLL

}  // namespace
