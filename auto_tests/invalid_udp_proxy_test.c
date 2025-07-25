// Test that if UDP is enabled, and a proxy is provided that does not support
// UDP proxying, we disable UDP.

#include <stdio.h>

#include "../testing/misc_tools.h"
#include "auto_test_support.h"
#include "check_compat.h"

// Try to bootstrap for 20 seconds.
#define NUM_ITERATIONS (unsigned)(20.0 / (ITERATION_INTERVAL / 1000.0))

int main(void)
{
    setvbuf(stdout, nullptr, _IONBF, 0);

    struct Tox_Options *opts = tox_options_new(nullptr);
    tox_options_set_udp_enabled(opts, true);
    tox_options_set_proxy_type(opts, TOX_PROXY_TYPE_SOCKS5);
    tox_options_set_proxy_host(opts, "127.0.0.1");
    tox_options_set_proxy_port(opts, 51724);
    Tox *tox = tox_new_log(opts, nullptr, nullptr);
    tox_options_free(opts);

    bootstrap_tox_live_network(tox, true);

    printf("Waiting for connection...");

    for (uint16_t i = 0; i < NUM_ITERATIONS; i++) {
        tox_iterate(tox, nullptr);
        c_sleep(ITERATION_INTERVAL);
        // None of the iterations should have a connection.
        const Tox_Connection status = tox_self_get_connection_status(tox);
        ck_assert_msg(status == TOX_CONNECTION_NONE,
                      "unexpectedly got a connection (%u)", status);
    }

    tox_kill(tox);
    return 0;
}
