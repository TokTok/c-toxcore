/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2026 The TokTok team.
 */

#include "TCP_server.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <chrono>
#include <cstring>
#include <thread>
#include <vector>

#include "TCP_client.h"
#include "TCP_common.h"
#include "os_event.h"
#include "os_memory.h"
#include "os_network.h"
#include "os_random.h"
#include "test_util.hh"
#include "util.h"

[[maybe_unused]] static std::ostream &operator<<(std::ostream &os, const IP &ip)
{
    Ip_Ntoa ntoa;
    return os << net_ip_ntoa(&ip, &ntoa);
}

[[maybe_unused]] static std::ostream &operator<<(std::ostream &os, const IP_Port &ipp)
{
    Ip_Ntoa ntoa;
    return os << net_ip_ntoa(&ipp.ip, &ntoa) << ":" << net_ntohs(ipp.port);
}

[[maybe_unused]] static std::ostream &operator<<(std::ostream &os, TCP_Client_Status status)
{
    switch (status) {
        case TCP_CLIENT_NO_STATUS:
            return os << "TCP_CLIENT_NO_STATUS";
        case TCP_CLIENT_PROXY_HTTP_CONNECTING:
            return os << "TCP_CLIENT_PROXY_HTTP_CONNECTING";
        case TCP_CLIENT_PROXY_SOCKS5_CONNECTING:
            return os << "TCP_CLIENT_PROXY_SOCKS5_CONNECTING";
        case TCP_CLIENT_PROXY_SOCKS5_UNCONFIRMED:
            return os << "TCP_CLIENT_PROXY_SOCKS5_UNCONFIRMED";
        case TCP_CLIENT_CONNECTING:
            return os << "TCP_CLIENT_CONNECTING";
        case TCP_CLIENT_UNCONFIRMED:
            return os << "TCP_CLIENT_UNCONFIRMED";
        case TCP_CLIENT_CONFIRMED:
            return os << "TCP_CLIENT_CONFIRMED";
        case TCP_CLIENT_DISCONNECTED:
            return os << "TCP_CLIENT_DISCONNECTED";
    }
    return os << "TCP_CLIENT_UNKNOWN(" << static_cast<int>(status) << ")";
}

[[maybe_unused]] static std::ostream &operator<<(std::ostream &os, TCP_Status status)
{
    switch (status) {
        case TCP_STATUS_NO_STATUS:
            return os << "TCP_STATUS_NO_STATUS";
        case TCP_STATUS_CONNECTED:
            return os << "TCP_STATUS_CONNECTED";
        case TCP_STATUS_UNCONFIRMED:
            return os << "TCP_STATUS_UNCONFIRMED";
        case TCP_STATUS_CONFIRMED:
            return os << "TCP_STATUS_CONFIRMED";
    }
    return os << "TCP_STATUS_UNKNOWN(" << static_cast<int>(status) << ")";
}

namespace {

void c_sleep(uint32_t ms) { std::this_thread::sleep_for(std::chrono::milliseconds(ms)); }

class TCPServerTest : public ::testing::Test {
protected:
    const Memory *_Nonnull mem = REQUIRE_NOT_NULL(os_memory());
    const Network *_Nonnull ns = REQUIRE_NOT_NULL(os_network());
    const Random *_Nonnull rng = REQUIRE_NOT_NULL(os_random());

    std::uint64_t current_time_ms = 1000000;

    static void log_cb(void *_Nullable context, Logger_Level level, const char *_Nonnull file,
        std::uint32_t line, const char *_Nonnull func, const char *_Nonnull message,
        void *_Nullable userdata)
    {
        const char *name = userdata ? static_cast<const char *>(userdata) : "Unknown";
        if (level >= LOGGER_LEVEL_DEBUG) {
            fprintf(stderr, "[%s][%d] %s:%u %s: %s\n", name, level, file, line, func, message);
        }
    }

    Mono_Time *create_mono_time()
    {
        Mono_Time *mt = REQUIRE_NOT_NULL(mono_time_new(mem, nullptr, nullptr));
        mono_time_set_current_time_callback(
            mt, [](void *userdata) -> uint64_t { return *static_cast<uint64_t *>(userdata); },
            &current_time_ms);
        return mt;
    }

    IP get_loopback()
    {
        IP ip;
        ip.family = net_family_ipv4();
        ip.ip.v4 = net_get_ip4_loopback();
        return ip;
    }
};

TEST_F(TCPServerTest, BasicStartup)
{
    Logger *log = logger_new(mem);
    logger_callback_log(log, &TCPServerTest::log_cb, nullptr, const_cast<char *>("Server"));
    Ev *ev = os_event_new(mem, log);

    std::uint8_t sk[CRYPTO_SECRET_KEY_SIZE];
    std::uint8_t pk[CRYPTO_PUBLIC_KEY_SIZE];
    crypto_new_keypair(rng, pk, sk);

    std::uint16_t ports[] = {33441};
    TCP_Server *server
        = new_tcp_server(log, mem, rng, ns, ev, false, 1, ports, sk, nullptr, nullptr);
    ASSERT_NE(server, nullptr);
    EXPECT_EQ(tcp_server_listen_count(server), 1);

    kill_tcp_server(server);
    ev_kill(ev);
    logger_kill(log);
}

TEST_F(TCPServerTest, MultipleClients)
{
    Logger *server_log = logger_new(mem);
    logger_callback_log(server_log, &TCPServerTest::log_cb, nullptr, const_cast<char *>("Server"));
    Ev *server_ev = os_event_new(mem, server_log);
    Mono_Time *server_time = create_mono_time();

    std::uint8_t server_sk[CRYPTO_SECRET_KEY_SIZE];
    std::uint8_t server_pk[CRYPTO_PUBLIC_KEY_SIZE];
    crypto_new_keypair(rng, server_pk, server_sk);

    std::uint16_t ports[] = {33443};
    TCP_Server *server = new_tcp_server(
        server_log, mem, rng, ns, server_ev, false, 1, ports, server_sk, nullptr, nullptr);
    ASSERT_NE(server, nullptr);

    const int NUM_CLIENTS = 10;
    struct Client {
        Logger *log;
        Ev *ev;
        Mono_Time *time;
        TCP_Client_Connection *conn;
        std::uint8_t pk[CRYPTO_PUBLIC_KEY_SIZE];
        std::uint8_t sk[CRYPTO_SECRET_KEY_SIZE];
        char name[32];
    };
    std::vector<Client> clients(NUM_CLIENTS);

    IP_Port server_ip_port;
    server_ip_port.ip = get_loopback();
    server_ip_port.port = net_htons(33443);

    for (int i = 0; i < NUM_CLIENTS; ++i) {
        clients[i].log = logger_new(mem);
        snprintf(clients[i].name, sizeof(clients[i].name), "Client %d", i);
        logger_callback_log(clients[i].log, &TCPServerTest::log_cb, nullptr, clients[i].name);
        clients[i].ev = os_event_new(mem, clients[i].log);
        clients[i].time = create_mono_time();
        crypto_new_keypair(rng, clients[i].pk, clients[i].sk);

        clients[i].conn
            = new_tcp_connection(clients[i].log, mem, clients[i].time, rng, ns, clients[i].ev,
                &server_ip_port, server_pk, clients[i].pk, clients[i].sk, nullptr, nullptr);
        ASSERT_NE(clients[i].conn, nullptr);
    }

    // Run simulation for handshakes
    for (int i = 0; i < 1000; ++i) {
        current_time_ms += 10;
        mono_time_update(server_time);
        do_tcp_server(server, server_time);
        for (int j = 0; j < NUM_CLIENTS; ++j) {
            mono_time_update(clients[j].time);
            do_tcp_connection(clients[j].log, clients[j].time, clients[j].conn, nullptr);
        }
        bool all_connected = true;
        for (int j = 0; j < NUM_CLIENTS; ++j) {
            if (tcp_con_status(clients[j].conn) != TCP_CLIENT_CONFIRMED) {
                all_connected = false;
                break;
            }
        }
        if (all_connected)
            break;
        c_sleep(1);
    }

    for (int i = 0; i < NUM_CLIENTS; ++i) {
        EXPECT_EQ(tcp_con_status(clients[i].conn), TCP_CLIENT_CONFIRMED)
            << "Client " << i << " failed to connect";
    }

    // Cleanup
    for (int i = 0; i < NUM_CLIENTS; ++i) {
        kill_tcp_connection(clients[i].conn);
        ev_kill(clients[i].ev);
        logger_kill(clients[i].log);
        mono_time_free(mem, clients[i].time);
    }
    kill_tcp_server(server);
    ev_kill(server_ev);
    logger_kill(server_log);
    mono_time_free(mem, server_time);
}

TEST_F(TCPServerTest, RelayRoutingRealNet)
{
    Logger *server_log = logger_new(mem);
    logger_callback_log(server_log, &TCPServerTest::log_cb, nullptr, const_cast<char *>("Server"));
    Ev *server_ev = os_event_new(mem, server_log);
    Mono_Time *server_time = create_mono_time();

    std::uint8_t server_sk[CRYPTO_SECRET_KEY_SIZE];
    std::uint8_t server_pk[CRYPTO_PUBLIC_KEY_SIZE];
    crypto_new_keypair(rng, server_pk, server_sk);

    // Fixed port for now, similar to TCP_test.c
    uint16_t test_port = 33445;
    TCP_Server *server = new_tcp_server(
        server_log, mem, rng, ns, server_ev, false, 1, &test_port, server_sk, nullptr, nullptr);
    if (!server) {
        test_port = 33446;
        server = new_tcp_server(
            server_log, mem, rng, ns, server_ev, false, 1, &test_port, server_sk, nullptr, nullptr);
    }
    ASSERT_NE(server, nullptr) << "Could not bind to a test port";

    IP_Port server_ip_port;
    server_ip_port.ip = get_loopback();
    server_ip_port.port = net_htons(test_port);

    // Setup two clients
    struct Client {
        Logger *log;
        Ev *ev;
        Mono_Time *time;
        TCP_Client_Connection *conn;
        std::uint8_t pk[CRYPTO_PUBLIC_KEY_SIZE];
        std::uint8_t sk[CRYPTO_SECRET_KEY_SIZE];
        std::vector<std::vector<std::uint8_t>> received_data;
        std::uint8_t response_id = 255;
        bool status_connected = false;
        const char *name;
    } c1, c2;

    auto setup_client = [&](Client &c, const char *name) {
        c.name = name;
        c.log = logger_new(mem);
        logger_callback_log(c.log, &TCPServerTest::log_cb, nullptr, const_cast<char *>(c.name));
        c.ev = os_event_new(mem, c.log);
        c.time = create_mono_time();
        crypto_new_keypair(rng, c.pk, c.sk);
        c.conn = new_tcp_connection(c.log, mem, c.time, rng, ns, c.ev,
            &server_ip_port, server_pk, c.pk, c.sk, nullptr, nullptr);

        routing_response_handler(
            c.conn,
            [](void *obj, std::uint8_t id, const std::uint8_t *pk) -> int {
                static_cast<Client *>(obj)->response_id = id;
                return 0;
            },
            &c);

        routing_status_handler(
            c.conn,
            [](void *obj, std::uint32_t number, std::uint8_t connection_id,
                std::uint8_t status) -> int {
                if (status == 2)
                    static_cast<Client *>(obj)->status_connected = true;
                return 0;
            },
            &c);

        routing_data_handler(
            c.conn,
            [](void *obj, std::uint32_t number, std::uint8_t connection_id,
                const std::uint8_t *data, std::uint16_t length, void *userdata) -> int {
                static_cast<Client *>(obj)->received_data.push_back(
                    std::vector<std::uint8_t>(data, data + length));
                return 0;
            },
            &c);
    };

    setup_client(c1, "C1");
    setup_client(c2, "C2");

    // Handshakes
    for (int i = 0; i < 1000; ++i) {
        current_time_ms += 10;
        mono_time_update(server_time);
        mono_time_update(c1.time);
        mono_time_update(c2.time);
        do_tcp_server(server, server_time);
        do_tcp_connection(c1.log, c1.time, c1.conn, nullptr);
        do_tcp_connection(c2.log, c2.time, c2.conn, nullptr);
        if (tcp_con_status(c1.conn) == TCP_CLIENT_CONFIRMED
            && tcp_con_status(c2.conn) == TCP_CLIENT_CONFIRMED)
            break;
        c_sleep(1);
    }
    ASSERT_EQ(tcp_con_status(c1.conn), TCP_CLIENT_CONFIRMED);
    ASSERT_EQ(tcp_con_status(c2.conn), TCP_CLIENT_CONFIRMED);

    fprintf(stderr, "Clients connected to relay. Requesting routing...\n");

    // C1 requests to route to C2
    send_routing_request(c1.log, c1.conn, c2.pk);
    // C2 requests to route to C1
    send_routing_request(c2.log, c2.conn, c1.pk);

    for (int i = 0; i < 1000; ++i) {
        current_time_ms += 10;
        mono_time_update(server_time);
        mono_time_update(c1.time);
        mono_time_update(c2.time);
        do_tcp_server(server, server_time);
        do_tcp_connection(c1.log, c1.time, c1.conn, nullptr);
        do_tcp_connection(c2.log, c2.time, c2.conn, nullptr);
        if (c1.status_connected && c2.status_connected)
            break;
        c_sleep(1);
    }

    EXPECT_EQ(c1.response_id, 0);
    EXPECT_EQ(c2.response_id, 0);
    ASSERT_TRUE(c1.status_connected);
    ASSERT_TRUE(c2.status_connected);

    fprintf(stderr, "Clients routed to each other. Sending data...\n");

    // Send data C1 -> C2
    std::uint8_t test_data[] = "Hello C2";
    send_data(c1.log, c1.conn, c1.response_id, test_data, sizeof(test_data));

    for (int i = 0; i < 500; ++i) {
        current_time_ms += 10;
        mono_time_update(server_time);
        mono_time_update(c1.time);
        mono_time_update(c2.time);
        do_tcp_server(server, server_time);
        do_tcp_connection(c1.log, c1.time, c1.conn, nullptr);
        do_tcp_connection(c2.log, c2.time, c2.conn, nullptr);
        if (!c2.received_data.empty())
            break;
        c_sleep(1);
    }

    ASSERT_FALSE(c2.received_data.empty());
    EXPECT_EQ(c2.received_data[0].size(), sizeof(test_data));
    EXPECT_EQ(0, std::memcmp(c2.received_data[0].data(), test_data, sizeof(test_data)));

    // Cleanup
    kill_tcp_connection(c1.conn);
    kill_tcp_connection(c2.conn);
    ev_kill(c1.ev);
    ev_kill(c2.ev);
    logger_kill(c1.log);
    logger_kill(c2.log);
    mono_time_free(mem, c1.time);
    mono_time_free(mem, c2.time);
    kill_tcp_server(server);
    ev_kill(server_ev);
    logger_kill(server_log);
    mono_time_free(mem, server_time);
}

TEST_F(TCPServerTest, DuplicateConnection)
{
    Logger *server_log = logger_new(mem);
    logger_callback_log(server_log, &TCPServerTest::log_cb, nullptr, const_cast<char *>("Server"));
    Ev *server_ev = os_event_new(mem, server_log);
    Mono_Time *server_time = create_mono_time();

    std::uint8_t server_sk[CRYPTO_SECRET_KEY_SIZE];
    std::uint8_t server_pk[CRYPTO_PUBLIC_KEY_SIZE];
    crypto_new_keypair(rng, server_pk, server_sk);

    uint16_t test_port = 33447;
    TCP_Server *server = new_tcp_server(
        server_log, mem, rng, ns, server_ev, false, 1, &test_port, server_sk, nullptr, nullptr);
    if (!server) {
        test_port = 33448;
        server = new_tcp_server(
            server_log, mem, rng, ns, server_ev, false, 1, &test_port, server_sk, nullptr, nullptr);
    }
    ASSERT_NE(server, nullptr);

    IP_Port server_ip_port;
    server_ip_port.ip = get_loopback();
    server_ip_port.port = net_htons(test_port);

    std::uint8_t client_pk[CRYPTO_PUBLIC_KEY_SIZE];
    std::uint8_t client_sk[CRYPTO_SECRET_KEY_SIZE];
    crypto_new_keypair(rng, client_pk, client_sk);

    Logger *client_log1 = logger_new(mem);
    logger_callback_log(client_log1, &TCPServerTest::log_cb, nullptr, const_cast<char *>("C1"));
    Ev *client_ev1 = os_event_new(mem, client_log1);

    Mono_Time *client_time1 = create_mono_time();
    TCP_Client_Connection *conn1 = new_tcp_connection(client_log1, mem, client_time1, rng, ns,
        client_ev1, &server_ip_port, server_pk, client_pk, client_sk, nullptr, nullptr);

    for (int i = 0; i < 1000; ++i) {
        current_time_ms += 10;
        mono_time_update(server_time);
        mono_time_update(client_time1);
        do_tcp_server(server, server_time);
        do_tcp_connection(client_log1, client_time1, conn1, nullptr);
        if (tcp_con_status(conn1) == TCP_CLIENT_CONFIRMED)
            break;
        c_sleep(1);
    }
    ASSERT_EQ(tcp_con_status(conn1), TCP_CLIENT_CONFIRMED);

    Logger *client_log2 = logger_new(mem);
    logger_callback_log(client_log2, &TCPServerTest::log_cb, nullptr, const_cast<char *>("C2"));
    Ev *client_ev2 = os_event_new(mem, client_log2);
    Mono_Time *client_time2 = create_mono_time();
    TCP_Client_Connection *conn2 = new_tcp_connection(client_log2, mem, client_time2, rng, ns,
        client_ev2, &server_ip_port, server_pk, client_pk, client_sk, nullptr, nullptr);

    // Handshake for second connection
    for (int i = 0; i < 1000; ++i) {
        current_time_ms += 10;
        mono_time_update(server_time);
        mono_time_update(client_time2);
        do_tcp_server(server, server_time);
        do_tcp_connection(client_log2, client_time2, conn2, nullptr);
        if (tcp_con_status(conn2) == TCP_CLIENT_CONFIRMED)
            break;
        c_sleep(1);
    }
    ASSERT_EQ(tcp_con_status(conn2), TCP_CLIENT_CONFIRMED);

    send_routing_request(client_log2, conn2, server_pk);

    // Now pump both to let C1 notice it was dropped.
    for (int i = 0; i < 1000; ++i) {
        current_time_ms += 1000;
        mono_time_update(server_time);
        mono_time_update(client_time1);
        mono_time_update(client_time2);
        do_tcp_server(server, server_time);
        do_tcp_connection(client_log1, client_time1, conn1, nullptr);
        do_tcp_connection(client_log2, client_time2, conn2, nullptr);
        if (tcp_con_status(conn1) == TCP_CLIENT_DISCONNECTED)
            break;
        c_sleep(1);
    }
    EXPECT_EQ(tcp_con_status(conn1), TCP_CLIENT_DISCONNECTED);

    kill_tcp_connection(conn1);
    kill_tcp_connection(conn2);
    kill_tcp_server(server);
    ev_kill(client_ev1);
    ev_kill(client_ev2);
    ev_kill(server_ev);
    logger_kill(client_log1);
    logger_kill(client_log2);
    logger_kill(server_log);
    mono_time_free(mem, client_time1);
    mono_time_free(mem, client_time2);
    mono_time_free(mem, server_time);
}

TEST_F(TCPServerTest, OOBData)
{
    Logger *server_log = logger_new(mem);
    logger_callback_log(server_log, &TCPServerTest::log_cb, nullptr, const_cast<char *>("Server"));
    Ev *server_ev = os_event_new(mem, server_log);
    Mono_Time *server_time = create_mono_time();

    std::uint8_t server_sk[CRYPTO_SECRET_KEY_SIZE];
    std::uint8_t server_pk[CRYPTO_PUBLIC_KEY_SIZE];
    crypto_new_keypair(rng, server_pk, server_sk);

    uint16_t test_port = 33449;
    TCP_Server *server = new_tcp_server(
        server_log, mem, rng, ns, server_ev, false, 1, &test_port, server_sk, nullptr, nullptr);
    if (!server) {
        test_port = 33450;
        server = new_tcp_server(
            server_log, mem, rng, ns, server_ev, false, 1, &test_port, server_sk, nullptr, nullptr);
    }
    ASSERT_NE(server, nullptr);

    IP_Port server_ip_port;
    server_ip_port.ip = get_loopback();
    server_ip_port.port = net_htons(test_port);

    struct Client {
        Logger *log;
        Ev *ev;
        Mono_Time *time;
        TCP_Client_Connection *conn;
        std::uint8_t pk[CRYPTO_PUBLIC_KEY_SIZE];
        std::uint8_t sk[CRYPTO_SECRET_KEY_SIZE];
        std::vector<std::vector<std::uint8_t>> received_oob;
        const char *name;
    } c1, c2;

    auto setup_client = [&](Client &c, const char *name) {
        c.name = name;
        c.log = logger_new(mem);
        logger_callback_log(c.log, &TCPServerTest::log_cb, nullptr, const_cast<char *>(c.name));
        c.ev = os_event_new(mem, c.log);
        c.time = create_mono_time();
        crypto_new_keypair(rng, c.pk, c.sk);
        c.conn = new_tcp_connection(c.log, mem, c.time, rng, ns, c.ev,
            &server_ip_port, server_pk, c.pk, c.sk, nullptr, nullptr);

        oob_data_handler(
            c.conn,
            [](void *obj, const std::uint8_t *pk, const std::uint8_t *data, std::uint16_t length,
                void *userdata) -> int {
                static_cast<Client *>(obj)->received_oob.push_back(
                    std::vector<std::uint8_t>(data, data + length));
                return 0;
            },
            &c);
    };

    setup_client(c1, "C1");
    setup_client(c2, "C2");

    for (int i = 0; i < 500; ++i) {
        current_time_ms += 10;
        mono_time_update(server_time);
        mono_time_update(c1.time);
        mono_time_update(c2.time);
        do_tcp_server(server, server_time);
        do_tcp_connection(c1.log, c1.time, c1.conn, nullptr);
        do_tcp_connection(c2.log, c2.time, c2.conn, nullptr);
        if (tcp_con_status(c1.conn) == TCP_CLIENT_CONFIRMED
            && tcp_con_status(c2.conn) == TCP_CLIENT_CONFIRMED)
            break;
        c_sleep(1);
    }

    // Server only knows about keys after they send something.
    send_routing_request(c1.log, c1.conn, server_pk);
    send_routing_request(c2.log, c2.conn, server_pk);

    for (int i = 0; i < 200; ++i) {
        current_time_ms += 10;
        mono_time_update(server_time);
        mono_time_update(c1.time);
        mono_time_update(c2.time);
        do_tcp_server(server, server_time);
        do_tcp_connection(c1.log, c1.time, c1.conn, nullptr);
        do_tcp_connection(c2.log, c2.time, c2.conn, nullptr);
        c_sleep(1);
    }

    std::uint8_t oob_msg[] = "OOB message";
    send_oob_packet(c1.log, c1.conn, c2.pk, oob_msg, sizeof(oob_msg));

    for (int i = 0; i < 200; ++i) {
        current_time_ms += 10;
        mono_time_update(server_time);
        mono_time_update(c1.time);
        mono_time_update(c2.time);
        do_tcp_server(server, server_time);
        do_tcp_connection(c1.log, c1.time, c1.conn, nullptr);
        do_tcp_connection(c2.log, c2.time, c2.conn, nullptr);
        if (!c2.received_oob.empty())
            break;
        c_sleep(1);
    }

    ASSERT_FALSE(c2.received_oob.empty());
    EXPECT_EQ(c2.received_oob[0].size(), sizeof(oob_msg));
    EXPECT_EQ(0, std::memcmp(c2.received_oob[0].data(), oob_msg, sizeof(oob_msg)));

    kill_tcp_connection(c1.conn);
    kill_tcp_connection(c2.conn);
    kill_tcp_server(server);
    ev_kill(c1.ev);
    ev_kill(c2.ev);
    ev_kill(server_ev);
    logger_kill(c1.log);
    logger_kill(c2.log);
    logger_kill(server_log);
    mono_time_free(mem, c1.time);
    mono_time_free(mem, c2.time);
    mono_time_free(mem, server_time);
}

TEST_F(TCPServerTest, DisconnectNotification)
{
    Logger *server_log = logger_new(mem);
    logger_callback_log(server_log, &TCPServerTest::log_cb, nullptr, const_cast<char *>("Server"));
    Ev *server_ev = os_event_new(mem, server_log);
    Mono_Time *server_time = create_mono_time();

    std::uint8_t server_sk[CRYPTO_SECRET_KEY_SIZE];
    std::uint8_t server_pk[CRYPTO_PUBLIC_KEY_SIZE];
    crypto_new_keypair(rng, server_pk, server_sk);

    uint16_t test_port = 33451;
    TCP_Server *server = new_tcp_server(
        server_log, mem, rng, ns, server_ev, false, 1, &test_port, server_sk, nullptr, nullptr);
    ASSERT_NE(server, nullptr);

    IP_Port server_ip_port;
    server_ip_port.ip = get_loopback();
    server_ip_port.port = net_htons(test_port);

    struct Client {
        Logger *log;
        Ev *ev;
        Mono_Time *time;
        TCP_Client_Connection *conn;
        std::uint8_t pk[CRYPTO_PUBLIC_KEY_SIZE];
        std::uint8_t sk[CRYPTO_SECRET_KEY_SIZE];
        bool status_disconnected = false;
        const char *name;
    } c1, c2;

    auto setup_client = [&](Client &c, const char *name) {
        c.name = name;
        c.log = logger_new(mem);
        logger_callback_log(c.log, &TCPServerTest::log_cb, nullptr, const_cast<char *>(c.name));
        c.ev = os_event_new(mem, c.log);
        c.time = create_mono_time();
        crypto_new_keypair(rng, c.pk, c.sk);
        c.conn = new_tcp_connection(c.log, mem, c.time, rng, ns, c.ev,
            &server_ip_port, server_pk, c.pk, c.sk, nullptr, nullptr);

        routing_status_handler(
            c.conn,
            [](void *obj, std::uint32_t number, std::uint8_t connection_id,
                std::uint8_t status) -> int {
                fprintf(stderr,
                    "Callback: DisconnectNotification Status received for %s, id=%u, status=%u\n",
                    static_cast<Client *>(obj)->name, connection_id, status);
                if (status == 1)
                    static_cast<Client *>(obj)->status_disconnected = true;
                return 0;
            },
            &c);
    };

    setup_client(c1, "C1");
    setup_client(c2, "C2");

    for (int i = 0; i < 500; ++i) {
        current_time_ms += 10;
        mono_time_update(server_time);
        mono_time_update(c1.time);
        mono_time_update(c2.time);
        do_tcp_server(server, server_time);
        do_tcp_connection(c1.log, c1.time, c1.conn, nullptr);
        do_tcp_connection(c2.log, c2.time, c2.conn, nullptr);
        if (tcp_con_status(c1.conn) == TCP_CLIENT_CONFIRMED
            && tcp_con_status(c2.conn) == TCP_CLIENT_CONFIRMED)
            break;
        c_sleep(1);
    }

    send_routing_request(c1.log, c1.conn, c2.pk);
    send_routing_request(c2.log, c2.conn, c1.pk);

    for (int i = 0; i < 500; ++i) {
        current_time_ms += 10;
        mono_time_update(server_time);
        mono_time_update(c1.time);
        mono_time_update(c2.time);
        do_tcp_server(server, server_time);
        do_tcp_connection(c1.log, c1.time, c1.conn, nullptr);
        do_tcp_connection(c2.log, c2.time, c2.conn, nullptr);
        c_sleep(1);
    }

    // Now C2 disconnects
    fprintf(stderr, "C2 disconnecting...\n");
    kill_tcp_connection(c2.conn);
    c2.conn = nullptr;

    for (int i = 0; i < 1000; ++i) {
        current_time_ms += 1000;
        mono_time_update(server_time);
        mono_time_update(c1.time);
        do_tcp_server(server, server_time);
        do_tcp_connection(c1.log, c1.time, c1.conn, nullptr);
        if (c1.status_disconnected)
            break;
        c_sleep(1);
    }

    EXPECT_TRUE(c1.status_disconnected);

    kill_tcp_connection(c1.conn);
    kill_tcp_server(server);
    ev_kill(c1.ev);
    ev_kill(c2.ev);
    ev_kill(server_ev);
    logger_kill(c1.log);
    logger_kill(c2.log);
    logger_kill(server_log);
    mono_time_free(mem, c1.time);
    mono_time_free(mem, c2.time);
    mono_time_free(mem, server_time);
}

TEST_F(TCPServerTest, InvalidHandshakeGarbage)
{
    Logger *server_log = logger_new(mem);
    logger_callback_log(server_log, &TCPServerTest::log_cb, nullptr, const_cast<char *>("Server"));
    Ev *server_ev = os_event_new(mem, server_log);
    Mono_Time *server_time = create_mono_time();

    std::uint8_t server_sk[CRYPTO_SECRET_KEY_SIZE];
    std::uint8_t server_pk[CRYPTO_PUBLIC_KEY_SIZE];
    crypto_new_keypair(rng, server_pk, server_sk);

    uint16_t test_port = 33453;
    TCP_Server *server = new_tcp_server(
        server_log, mem, rng, ns, server_ev, false, 1, &test_port, server_sk, nullptr, nullptr);
    ASSERT_NE(server, nullptr);

    IP_Port server_ip_port;
    server_ip_port.ip = get_loopback();
    server_ip_port.port = net_htons(test_port);

    Socket client_sock = net_socket(ns, net_family_ipv4(), TOX_SOCK_STREAM, TOX_PROTO_TCP);
    Net_Err_Connect conn_err;
    bool ok = net_connect(ns, mem, server_log, client_sock, &server_ip_port, &conn_err);
    ASSERT_TRUE(ok);

    std::uint8_t garbage[TCP_CLIENT_HANDSHAKE_SIZE];
    std::memset(garbage, 0x42, sizeof(garbage));
    net_send(ns, server_log, client_sock, garbage, sizeof(garbage), &server_ip_port, nullptr);

    for (int i = 0; i < 50; ++i) {
        current_time_ms += 10;
        mono_time_update(server_time);
        do_tcp_server(server, server_time);
        c_sleep(1);
    }

    std::uint8_t dummy;
    int res = net_recv(ns, server_log, client_sock, &dummy, 1, &server_ip_port);
    EXPECT_LE(res, 0);

    kill_sock(ns, client_sock);
    kill_tcp_server(server);
    ev_kill(server_ev);
    logger_kill(server_log);
    mono_time_free(mem, server_time);
}

TEST_F(TCPServerTest, DISABLED_HandshakeTimeout)
{
    Logger *server_log = logger_new(mem);
    logger_callback_log(server_log, &TCPServerTest::log_cb, nullptr, const_cast<char *>("Server"));
    Ev *server_ev = os_event_new(mem, server_log);
    Mono_Time *server_time = create_mono_time();

    std::uint8_t server_sk[CRYPTO_SECRET_KEY_SIZE];
    std::uint8_t server_pk[CRYPTO_PUBLIC_KEY_SIZE];
    crypto_new_keypair(rng, server_pk, server_sk);

    uint16_t test_port = 33455;
    TCP_Server *server = new_tcp_server(
        server_log, mem, rng, ns, server_ev, false, 1, &test_port, server_sk, nullptr, nullptr);
    ASSERT_NE(server, nullptr);

    IP_Port server_ip_port;
    server_ip_port.ip = get_loopback();
    server_ip_port.port = net_htons(test_port);

    Socket client_sock = net_socket(ns, net_family_ipv4(), TOX_SOCK_STREAM, TOX_PROTO_TCP);
    Net_Err_Connect conn_err;
    bool ok = net_connect(ns, mem, server_log, client_sock, &server_ip_port, &conn_err);
    ASSERT_TRUE(ok);

    for (int i = 0; i < 20; ++i) {
        current_time_ms += 1000;
        mono_time_update(server_time);
        do_tcp_server(server, server_time);
        c_sleep(1);
    }

    std::uint8_t dummy;
    int res = net_recv(ns, server_log, client_sock, &dummy, 1, &server_ip_port);
    EXPECT_LE(res, 0);

    kill_sock(ns, client_sock);
    kill_tcp_server(server);
    ev_kill(server_ev);
    logger_kill(server_log);
    mono_time_free(mem, server_time);
}

TEST_F(TCPServerTest, RoutingToSelf)
{
    Logger *server_log = logger_new(mem);
    logger_callback_log(server_log, &TCPServerTest::log_cb, nullptr, const_cast<char *>("Server"));
    Ev *server_ev = os_event_new(mem, server_log);
    Mono_Time *server_time = create_mono_time();

    std::uint8_t server_sk[CRYPTO_SECRET_KEY_SIZE];
    std::uint8_t server_pk[CRYPTO_PUBLIC_KEY_SIZE];
    crypto_new_keypair(rng, server_pk, server_sk);

    uint16_t test_port = 33457;
    TCP_Server *server = new_tcp_server(
        server_log, mem, rng, ns, server_ev, false, 1, &test_port, server_sk, nullptr, nullptr);
    ASSERT_NE(server, nullptr);

    IP_Port server_ip_port;
    server_ip_port.ip = get_loopback();
    server_ip_port.port = net_htons(test_port);

    Logger *client_log = logger_new(mem);
    logger_callback_log(client_log, &TCPServerTest::log_cb, nullptr, const_cast<char *>("Client"));
    Ev *client_ev = os_event_new(mem, client_log);
    Mono_Time *client_time = create_mono_time();
    std::uint8_t client_pk[CRYPTO_PUBLIC_KEY_SIZE];
    std::uint8_t client_sk[CRYPTO_SECRET_KEY_SIZE];
    crypto_new_keypair(rng, client_pk, client_sk);

    TCP_Client_Connection *conn = new_tcp_connection(client_log, mem, client_time, rng, ns,
        client_ev, &server_ip_port, server_pk, client_pk, client_sk, nullptr, nullptr);

    struct ResponseData {
        int response_called = 0;
        std::uint8_t response_id = 255;
    } rd;

    routing_response_handler(
        conn,
        [](void *obj, std::uint8_t id, const std::uint8_t *pk) -> int {
            auto *response_data = static_cast<ResponseData *>(obj);
            fprintf(stderr, "Callback: Routing Response received, id=%u\n", id);
            response_data->response_called++;
            response_data->response_id = id;
            return 0;
        },
        &rd);

    for (int i = 0; i < 500; ++i) {
        current_time_ms += 10;
        mono_time_update(server_time);
        mono_time_update(client_time);
        do_tcp_server(server, server_time);
        do_tcp_connection(client_log, client_time, conn, nullptr);
        if (tcp_con_status(conn) == TCP_CLIENT_CONFIRMED)
            break;
        c_sleep(1);
    }
    ASSERT_EQ(tcp_con_status(conn), TCP_CLIENT_CONFIRMED);

    send_routing_request(client_log, conn, client_pk);

    for (int i = 0; i < 500; ++i) {
        current_time_ms += 10;
        mono_time_update(server_time);
        mono_time_update(client_time);
        do_tcp_server(server, server_time);
        do_tcp_connection(client_log, client_time, conn, nullptr);
        c_sleep(1);
    }

    EXPECT_EQ(rd.response_called, 0);

    kill_tcp_connection(conn);
    kill_tcp_server(server);
    ev_kill(client_ev);
    ev_kill(server_ev);
    logger_kill(client_log);
    logger_kill(server_log);
    mono_time_free(mem, client_time);
    mono_time_free(mem, server_time);
}

}  // namespace
