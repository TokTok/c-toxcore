/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2026 The TokTok team.
 * Copyright © 2013 Tox project.
 */

#include "ev.h"

#include <fcntl.h>
#include <gtest/gtest.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <unistd.h>
#endif

#include "logger.h"
#include "net.h"
#include "os_event.h"
#include "os_memory.h"
#include "os_network.h"

namespace {

class EvTest : public ::testing::Test {
    static void logger_cb_stderr(void *context, Logger_Level level, const char *file, uint32_t line, const char *func,
        const char *message, void *userdata)
    {
        fprintf(stderr, "[%d] %s:%u: %s: %s\n", level, file, line, func, message);
    }

protected:
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

    const Memory *mem;
    Logger *log;
    Ev *ev;
    int tag1;
    int tag2;
    int tag3;
    int tag4;
};

#ifdef _WIN32
static int create_pair(Socket *rs, Socket *ws)
{
    SOCKET listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listener == INVALID_SOCKET)
        return -1;

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = 0;

    if (bind(listener, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        closesocket(listener);
        return -1;
    }

    if (listen(listener, 1) != 0) {
        closesocket(listener);
        return -1;
    }

    socklen_t len = sizeof(addr);
    if (getsockname(listener, (struct sockaddr *)&addr, &len) != 0) {
        closesocket(listener);
        return -1;
    }

    SOCKET client = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (client == INVALID_SOCKET) {
        closesocket(listener);
        return -1;
    }

    if (connect(client, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        closesocket(client);
        closesocket(listener);
        return -1;
    }

    SOCKET server = accept(listener, nullptr, nullptr);
    if (server == INVALID_SOCKET) {
        closesocket(client);
        closesocket(listener);
        return -1;
    }

    closesocket(listener);

    *rs = net_socket_from_native((int)client);
    *ws = net_socket_from_native((int)server);
    return 0;
}

static void close_pair(Socket s1, Socket s2)
{
    closesocket(net_socket_to_native(s1));
    closesocket(net_socket_to_native(s2));
}

static int write_socket(Socket s, const void *buf, size_t count)
{
    return send(net_socket_to_native(s), (const char *)buf, (int)count, 0);
}
#else
static int create_pair(Socket *rs, Socket *ws)
{
    int pipefds[2];
    if (pipe(pipefds) != 0)
        return -1;
    *rs = net_socket_from_native(pipefds[0]);
    *ws = net_socket_from_native(pipefds[1]);
    return 0;
}

static void close_pair(Socket s1, Socket s2)
{
    close(net_socket_to_native(s1));
    close(net_socket_to_native(s2));
}

static int write_socket(Socket s, const void *buf, size_t count) { return write(net_socket_to_native(s), buf, count); }
#endif

TEST_F(EvTest, Lifecycle)
{
    // Already covered by SetUp/TearDown
}

TEST_F(EvTest, AddDel)
{
    Socket s1{}, s2{};
    ASSERT_EQ(create_pair(&s1, &s2), 0);

    EXPECT_TRUE(ev_add(ev, s1, EV_READ, &tag1));
    EXPECT_TRUE(ev_add(ev, s2, EV_WRITE, &tag2));

    // Adding same socket again should fail
    EXPECT_FALSE(ev_add(ev, s1, EV_READ, &tag3));

    EXPECT_TRUE(ev_del(ev, s1));
    EXPECT_TRUE(ev_del(ev, s2));

    // Deleting non-existent socket should fail
    EXPECT_FALSE(ev_del(ev, s1));

    close_pair(s1, s2);
}

TEST_F(EvTest, RunPipe)
{
    Socket rs{}, ws{};
    ASSERT_EQ(create_pair(&rs, &ws), 0);

    EXPECT_TRUE(ev_add(ev, rs, EV_READ, &tag4));

    Ev_Result results[1];
    // Should timeout immediately
    EXPECT_EQ(ev_run(ev, results, 1, 0), 0);

    // Write something to the pipe/socket
    char buf = 'x';
    ASSERT_EQ(write_socket(ws, &buf, 1), 1);

    // Should now be readable
    int32_t n = ev_run(ev, results, 1, 100);
    EXPECT_EQ(n, 1);
    EXPECT_EQ(net_socket_to_native(results[0].sock), net_socket_to_native(rs));
    EXPECT_EQ(results[0].events, EV_READ);
    EXPECT_EQ(results[0].data, &tag4);

    close_pair(rs, ws);
}

TEST_F(EvTest, Mod)
{
    Socket rs{}, ws{};
    ASSERT_EQ(create_pair(&rs, &ws), 0);

    EXPECT_TRUE(ev_add(ev, rs, EV_READ, &tag1));
    EXPECT_TRUE(ev_mod(ev, rs, EV_READ, &tag2));

    // Write something to the pipe/socket to make it readable
    char buf = 'x';
    ASSERT_EQ(write_socket(ws, &buf, 1), 1);

    Ev_Result results[1];
    int32_t n = ev_run(ev, results, 1, 100);
    EXPECT_EQ(n, 1);
    EXPECT_EQ(net_socket_to_native(results[0].sock), net_socket_to_native(rs));
    EXPECT_EQ(results[0].events, EV_READ);
    EXPECT_EQ(results[0].data, &tag2);

    close_pair(rs, ws);
}

TEST_F(EvTest, MultipleEvents)
{
    Socket rs1{}, ws1{};
    Socket rs2{}, ws2{};
    ASSERT_EQ(create_pair(&rs1, &ws1), 0);
    ASSERT_EQ(create_pair(&rs2, &ws2), 0);

    EXPECT_TRUE(ev_add(ev, rs1, EV_READ, &tag1));
    EXPECT_TRUE(ev_add(ev, rs2, EV_READ, &tag2));

    char buf = 'x';
    ASSERT_EQ(write_socket(ws1, &buf, 1), 1);
    ASSERT_EQ(write_socket(ws2, &buf, 1), 1);

    Ev_Result results[2];
    int32_t n = ev_run(ev, results, 2, 100);
    EXPECT_EQ(n, 2);

    bool found1 = false;
    bool found2 = false;
    for (int i = 0; i < 2; ++i) {
        if (results[i].data == &tag1)
            found1 = true;
        if (results[i].data == &tag2)
            found2 = true;
    }
    EXPECT_TRUE(found1);
    EXPECT_TRUE(found2);

    close_pair(rs1, ws1);
    close_pair(rs2, ws2);
}

TEST_F(EvTest, MaxResults)
{
    Socket rs1{}, ws1{};
    Socket rs2{}, ws2{};
    ASSERT_EQ(create_pair(&rs1, &ws1), 0);
    ASSERT_EQ(create_pair(&rs2, &ws2), 0);

    EXPECT_TRUE(ev_add(ev, rs1, EV_READ, &tag1));
    EXPECT_TRUE(ev_add(ev, rs2, EV_READ, &tag2));

    char buf = 'x';
    ASSERT_EQ(write_socket(ws1, &buf, 1), 1);
    ASSERT_EQ(write_socket(ws2, &buf, 1), 1);

    Ev_Result results[1];
    int32_t n = ev_run(ev, results, 1, 100);
    EXPECT_EQ(n, 1);

    // The second event should still be there for the next run
    n = ev_run(ev, results, 1, 100);
    EXPECT_EQ(n, 1);

    close_pair(rs1, ws1);
    close_pair(rs2, ws2);
}

TEST_F(EvTest, EmptyLoop)
{
    Ev_Result results[1];
    // Should timeout immediately
    EXPECT_EQ(ev_run(ev, results, 1, 10), 0);
}

TEST_F(EvTest, ZeroMaxResults)
{
    Socket rs{}, ws{};
    ASSERT_EQ(create_pair(&rs, &ws), 0);
    EXPECT_TRUE(ev_add(ev, rs, EV_READ, nullptr));

    char buf = 'x';
    ASSERT_EQ(write_socket(ws, &buf, 1), 1);

    Ev_Result results[1];
    // If max_results is 0, it should return 0 (or error?)
    // epoll_wait returns error if maxevents <= 0
    // Let's see what our implementation does.
    int32_t n = ev_run(ev, results, 0, 100);
    EXPECT_LE(n, 0);

    close_pair(rs, ws);
}

TEST_F(EvTest, ErrorEvent)
{
    Socket rs{}, ws{};
    ASSERT_EQ(create_pair(&rs, &ws), 0);

    EXPECT_TRUE(ev_add(ev, rs, EV_READ, &tag1));

    // Close the write end to potentially trigger something on the read end
#ifdef _WIN32
    closesocket(net_socket_to_native(ws));
#else
    close(net_socket_to_native(ws));
#endif

    Ev_Result results[1];
    int32_t n = ev_run(ev, results, 1, 100);
    // On Linux, closing the write end of a pipe makes the read end readable (EOF).
    EXPECT_EQ(n, 1);
    EXPECT_EQ(net_socket_to_native(results[0].sock), net_socket_to_native(rs));
    // It might be EV_READ (EOF) or EV_ERROR depending on implementation.
    // Actually, EOF is often EV_READ in poll/epoll.

#ifdef _WIN32
    closesocket(net_socket_to_native(rs));
#else
    close(net_socket_to_native(rs));
#endif
}

}  // namespace
