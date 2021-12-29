#include <pthread.h>
#include <stdlib.h>
#include <time.h>

#include "../toxcore/tox.h"

#include "check_compat.h"
#include "../testing/misc_tools.h"

/* The CI containers respond poorly to ::1 as a localhost address
 * You're encouraged to -D FORCE_TESTS_IPV6 on a local test  */
#ifdef TOX_LOCALHOST
#undef TOX_LOCALHOST
#endif
#ifdef FORCE_TESTS_IPV6
#define TOX_LOCALHOST "::1"
#else
#define TOX_LOCALHOST "127.0.0.1"
#endif

#ifdef TCP_RELAY_PORT
#undef TCP_RELAY_PORT
#endif
#define TCP_RELAY_PORT 33431

typedef struct Loop_Test {
    int start_count;
    int stop_count;
    pthread_mutex_t mutex;
    Tox *tox;
} Loop_Test;

static void tox_loop_cb_start(Tox *tox, void *data)
{
    Loop_Test *userdata = (Loop_Test *)data;
    pthread_mutex_lock(&userdata->mutex);
    ++userdata->start_count;
}

static void tox_loop_cb_stop(Tox *tox, void *data)
{
    Loop_Test *userdata = (Loop_Test *)data;
    ++userdata->stop_count;
    pthread_mutex_unlock(&userdata->mutex);
}

static void *tox_loop_worker(void *data)
{
    Loop_Test *userdata = (Loop_Test *)data;
    Tox_Err_Loop err;
    tox_loop(userdata->tox, userdata, &err);
    ck_assert_msg(err == TOX_ERR_LOOP_OK, "tox_loop error: %d", err);
    return nullptr;
}

static void test_tox_loop(void)
{
    pthread_t worker, worker_tcp;
    Tox_Err_Options_New err_opts;
    struct Tox_Options *opts = tox_options_new(&err_opts);
    ck_assert_msg(err_opts == TOX_ERR_OPTIONS_NEW_OK, "tox_options_new: %d\n", err_opts);
    tox_options_set_experimental_thread_safety(opts, true);

    Loop_Test *userdata = (Loop_Test *)calloc(1, sizeof(Loop_Test));
    ck_assert(userdata != nullptr);
    uint8_t dpk[TOX_PUBLIC_KEY_SIZE];

    userdata->start_count = 0;
    userdata->stop_count = 0;
    pthread_mutex_init(&userdata->mutex, nullptr);

    tox_options_set_tcp_port(opts, TCP_RELAY_PORT);
    Tox_Err_New err_new;
    userdata->tox = tox_new(opts, &err_new);
    ck_assert_msg(err_new == TOX_ERR_NEW_OK, "tox_new: %d\n", err_new);
    tox_callback_loop_begin(userdata->tox, tox_loop_cb_start);
    tox_callback_loop_end(userdata->tox, tox_loop_cb_stop);
    pthread_create(&worker, nullptr, tox_loop_worker, userdata);

    tox_self_get_dht_id(userdata->tox, dpk);

    tox_options_default(opts);
    tox_options_set_experimental_thread_safety(opts, true);
    Loop_Test userdata_tcp;
    userdata_tcp.start_count = 0;
    userdata_tcp.stop_count = 0;
    pthread_mutex_init(&userdata_tcp.mutex, nullptr);
    userdata_tcp.tox = tox_new(opts, &err_new);
    ck_assert_msg(err_new == TOX_ERR_NEW_OK, "tox_new: %d\n", err_new);
    tox_callback_loop_begin(userdata_tcp.tox, tox_loop_cb_start);
    tox_callback_loop_end(userdata_tcp.tox, tox_loop_cb_stop);
    pthread_create(&worker_tcp, nullptr, tox_loop_worker, &userdata_tcp);

    pthread_mutex_lock(&userdata_tcp.mutex);
    Tox_Err_Bootstrap error;
    ck_assert_msg(tox_add_tcp_relay(userdata_tcp.tox, TOX_LOCALHOST, TCP_RELAY_PORT, dpk, &error), "Add relay error, %i",
                  error);
    ck_assert_msg(tox_bootstrap(userdata_tcp.tox, TOX_LOCALHOST, 33445, dpk, &error), "Bootstrap error, %i", error);
    pthread_mutex_unlock(&userdata_tcp.mutex);

    c_sleep(1000);

    tox_loop_stop(userdata->tox);
    void *retval = nullptr;
    pthread_join(worker, &retval);
    ck_assert_msg((uintptr_t)retval == 0, "tox_loop didn't return 0");

    tox_kill(userdata->tox);
    ck_assert_msg(userdata->start_count == userdata->stop_count, "start and stop must match (start = %d, stop = %d)",
                  userdata->start_count, userdata->stop_count);

    tox_loop_stop(userdata_tcp.tox);
    pthread_join(worker_tcp, &retval);
    ck_assert_msg((uintptr_t)retval == 0, "tox_loop didn't return 0");

    tox_kill(userdata_tcp.tox);
    ck_assert_msg(userdata_tcp.start_count == userdata_tcp.stop_count, "start and stop must match (start = %d, stop = %d)",
                  userdata_tcp.start_count, userdata_tcp.stop_count);

    tox_options_free(opts);
    free(userdata);
}

int main(int argc, char *argv[])
{
    test_tox_loop();
    return 0;
}
