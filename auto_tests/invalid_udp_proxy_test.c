// Test that if UDP is enabled, and a proxy is provided that does not support
// UDP proxying, we disable UDP.

#include <stdio.h>

#include "../testing/misc_tools.h"
#include "check_compat.h"

static uint8_t const key[] = {
    0x15, 0xE9, 0xC3, 0x09, 0xCF, 0xCB, 0x79, 0xFD,
    0xDF, 0x0E, 0xBA, 0x05, 0x7D, 0xAB, 0xB4, 0x9F,
    0xE1, 0x5F, 0x38, 0x03, 0xB1, 0xBF, 0xF0, 0x65,
    0x36, 0xAE, 0x2E, 0x5B, 0xA5, 0xE4, 0x69, 0x0E,
};

// Try to bootstrap for 30 seconds.
#define NUM_ITERATIONS (unsigned)(30.0 / (ITERATION_INTERVAL / 1000.0))

int main(void)
{
    setvbuf(stdout, nullptr, _IONBF, 0);

    struct Tox_Options *opts = tox_options_new(nullptr);
    tox_options_set_udp_enabled(opts, true);
    tox_options_set_proxy_type(opts, TOX_PROXY_TYPE_SOCKS5);
    const char proxy[] = "localhost";
    bool res = tox_options_set_proxy_host(opts, proxy, sizeof(proxy));
    ck_assert(res == true);

    tox_options_set_proxy_port(opts, 51724);
    Tox *tox = tox_new_log(opts, nullptr, nullptr);
    tox_options_free(opts);

    tox_add_tcp_relay(tox, "tox.ngc.zone", 33445, key, nullptr);
    tox_bootstrap(tox, "tox.ngc.zone", 33445, key, nullptr);

    printf("Waiting for connection...");

    for (uint16_t i = 0; i < NUM_ITERATIONS; i++) {
        tox_iterate(tox, nullptr);
        c_sleep(ITERATION_INTERVAL);
        // None of the iterations should have a connection.
        const Tox_Connection status = tox_self_get_connection_status(tox);
        ck_assert_msg(status == TOX_CONNECTION_NONE,
                      "unexpectedly got a connection (%d)", status);
    }

    tox_kill(tox);
    return 0;
}
