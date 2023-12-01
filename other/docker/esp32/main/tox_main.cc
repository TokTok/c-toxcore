#include "../main/tox_main.h"

#include <assert.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>

#include <memory>

#include "../../../../toxcore/ccompat.h"
#include "../../../../toxcore/tox.h"
#include "../../../../toxcore/tox_events.h"

static char tox_log_level_name(Tox_Log_Level level)
{
    switch (level) {
    case TOX_LOG_LEVEL_TRACE:
        return 'T';
    case TOX_LOG_LEVEL_DEBUG:
        return 'D';
    case TOX_LOG_LEVEL_INFO:
        return 'I';
    case TOX_LOG_LEVEL_WARNING:
        return 'W';
    case TOX_LOG_LEVEL_ERROR:
        return 'E';
    }

    return '?';
}

static const char *tox_err_new_name(Tox_Err_New err)
{
    switch (err) {
    case TOX_ERR_NEW_OK:
        return "OK";
    case TOX_ERR_NEW_NULL:
        return "NULL";
    case TOX_ERR_NEW_MALLOC:
        return "MALLOC";
    case TOX_ERR_NEW_PORT_ALLOC:
        return "PORT_ALLOC";
    case TOX_ERR_NEW_PROXY_BAD_TYPE:
        return "PROXY_BAD_TYPE";
    case TOX_ERR_NEW_PROXY_BAD_HOST:
        return "PROXY_BAD_HOST";
    case TOX_ERR_NEW_PROXY_BAD_PORT:
        return "PROXY_BAD_PORT";
    case TOX_ERR_NEW_PROXY_NOT_FOUND:
        return "PROXY_NOT_FOUND";
    case TOX_ERR_NEW_LOAD_ENCRYPTED:
        return "LOAD_ENCRYPTED";
    case TOX_ERR_NEW_LOAD_BAD_FORMAT:
        return "LOAD_BAD_FORMAT";
    }

    return "<unknown>";
}

static const char *color(int index)
{
    switch (index) {
    case 0:
        return "\033[35m";
    case 1:
        return "\033[36m";
    }

    return "\033[0m";
}

static tox_log_cb log_handler;
static void log_handler(Tox *tox, Tox_Log_Level level, const char *file, uint32_t line,
    const char *func, const char *msg, void *user_data)
{
    const int *index = (const int *)user_data;
    const uint16_t udp_port = tox_self_get_udp_port(tox, nullptr);
    printf("%s#%d (:%d) [%c] %s:%u(%s): %s\n", color(*index), *index, udp_port,
        tox_log_level_name(level), file, (unsigned int)line, func, msg);
}

using Tox_Options_Ptr = std::unique_ptr<Tox_Options, void (*)(Tox_Options *)>;
using Tox_Ptr = std::unique_ptr<Tox, void (*)(Tox *)>;

void tox_main()
{
    printf("Hello Tox!\n");

    Tox_Options_Ptr opts(tox_options_new(nullptr), tox_options_free);
    assert(opts != nullptr);

    tox_options_set_ipv6_enabled(opts.get(), false);
    tox_options_set_local_discovery_enabled(opts.get(), false);

    tox_options_set_log_callback(opts.get(), log_handler);

    Tox_Err_New err;

    int index[] = {0, 1};

    tox_options_set_log_user_data(opts.get(), &index[0]);
    Tox_Ptr tox0(tox_new(opts.get(), &err), tox_kill);
    printf("tox_new(#0): %p\n", (void *)tox0.get());

    if (err != TOX_ERR_NEW_OK) {
        printf("tox_new(#0): %s\n", tox_err_new_name(err));
        return;
    }

    tox_options_set_log_user_data(opts.get(), &index[1]);
    Tox_Ptr tox1(tox_new(opts.get(), &err), tox_kill);
    printf("tox_new(#1): %p\n", (void *)tox1.get());

    if (err != TOX_ERR_NEW_OK) {
        printf("tox_new(#1): %s\n", tox_err_new_name(err));
        return;
    }

    uint8_t pk[TOX_PUBLIC_KEY_SIZE];
    tox_self_get_dht_id(tox0.get(), pk);
    tox_bootstrap(tox1.get(), "localhost", tox_self_get_udp_port(tox0.get(), nullptr), pk, nullptr);

#if 0
    tox_self_get_public_key(tox0.get(), pk);
    tox_friend_add_norequest(tox1.get(), pk, nullptr);

    tox_self_get_public_key(tox1.get(), pk);
    tox_friend_add_norequest(tox0.get(), pk, nullptr);
#endif

    printf("bootstrapping and connecting 2 toxes\n");

    while (tox_self_get_connection_status(tox1.get()) == TOX_CONNECTION_NONE
        || tox_self_get_connection_status(tox0.get()) == TOX_CONNECTION_NONE) {
        tox_events_free(tox_events_iterate(tox0.get(), true, nullptr));
        tox_events_free(tox_events_iterate(tox1.get(), true, nullptr));

        usleep(tox_iteration_interval(tox0.get()) * 1000);
        usleep(250);  // a bit less noise in the log
    }
}
