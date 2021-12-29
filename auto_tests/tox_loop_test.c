#include <pthread.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#include "../toxcore/tox.h"

#include "check_compat.h"

#define TCP_RELAY_PORT 33448
/* The Travis-CI container responds poorly to ::1 as a localhost address
 * You're encouraged to -D FORCE_TESTS_IPV6 on a local test  */
#ifdef FORCE_TESTS_IPV6
#define TOX_LOCALHOST "::1"
#else
#define TOX_LOCALHOST "127.0.0.1"
#endif

typedef struct {
    int start_count, stop_count;
    pthread_mutex_t mutex;
    Tox *tox;
} loop_test;

static void tox_loop_cb_start(Tox *tox, void *user_data)
{
    loop_test *userdata = (loop_test *) user_data;
    pthread_mutex_lock(&userdata->mutex);
    userdata->start_count++;
}

static void tox_loop_cb_stop(Tox *tox, void *user_data)
{
    loop_test *userdata = (loop_test *) user_data;
    userdata->stop_count++;
    pthread_mutex_unlock(&userdata->mutex);
}

static void *tox_loop_worker(void *data)
{
    loop_test *userdata = (loop_test *) data;
    tox_loop(userdata->tox, data, NULL);
    return NULL;
}

static void test_tox_loop(void)
{
    pthread_t worker, worker_tcp;
    struct Tox_Options *opts = tox_options_new(NULL);
    loop_test userdata;
    uint8_t dpk[TOX_PUBLIC_KEY_SIZE];
    int retval;

    userdata.start_count = 0;
    userdata.stop_count = 0;
    pthread_mutex_init(&userdata.mutex, NULL);

    tox_options_set_tcp_port(opts, TCP_RELAY_PORT);
    userdata.tox = tox_new(opts, NULL);
    tox_callback_loop_begin(userdata.tox, tox_loop_cb_start);
    tox_callback_loop_end(userdata.tox, tox_loop_cb_stop);
    pthread_create(&worker, NULL, tox_loop_worker, &userdata);

    tox_self_get_dht_id(userdata.tox, dpk);

    tox_options_default(opts);
    loop_test userdata_tcp;
    userdata_tcp.start_count = 0;
    userdata_tcp.stop_count = 0;
    pthread_mutex_init(&userdata_tcp.mutex, NULL);
    userdata_tcp.tox = tox_new(opts, NULL);
    tox_callback_loop_begin(userdata_tcp.tox, tox_loop_cb_start);
    tox_callback_loop_end(userdata_tcp.tox, tox_loop_cb_stop);
    pthread_create(&worker_tcp, NULL, tox_loop_worker, &userdata_tcp);

    pthread_mutex_lock(&userdata_tcp.mutex);
    TOX_ERR_BOOTSTRAP error;
    ck_assert_msg(tox_add_tcp_relay(userdata_tcp.tox, TOX_LOCALHOST, TCP_RELAY_PORT, dpk, &error), "Add relay error, %i",
                  error);
    ck_assert_msg(tox_bootstrap(userdata_tcp.tox, TOX_LOCALHOST, 33445, dpk, &error), "Bootstrap error, %i", error);
    pthread_mutex_unlock(&userdata_tcp.mutex);

    sleep(10);

    tox_loop_stop(userdata.tox);
    pthread_join(worker, (void **)(void *)&retval);
    ck_assert_msg(retval == 0, "tox_loop didn't return 0");

    tox_kill(userdata.tox);
    ck_assert_msg(userdata.start_count == userdata.stop_count, "start and stop must match");

    tox_loop_stop(userdata_tcp.tox);
    pthread_join(worker_tcp, (void **)(void *)&retval);
    ck_assert_msg(retval == 0, "tox_loop didn't return 0");

    tox_kill(userdata_tcp.tox);
    ck_assert_msg(userdata_tcp.start_count == userdata_tcp.stop_count, "start and stop must match");
}

int main(int argc, char *argv[])
{
    test_tox_loop();
    return 0;
}
