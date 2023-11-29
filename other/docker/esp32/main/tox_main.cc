#include "../main/tox_main.h"

#include <assert.h>
#include <stdio.h>

#include "../../../../toxcore/ccompat.h"
#include "../../../../toxcore/tox.h"
#include "../../../../toxcore/tox_events.h"

static char tox_log_level_name(Tox_Log_Level level)
{
    switch (level) {
        case TOX_LOG_LEVEL_TRACE: return 'T';
        case TOX_LOG_LEVEL_DEBUG: return 'D';
        case TOX_LOG_LEVEL_INFO: return 'I';
        case TOX_LOG_LEVEL_WARNING: return 'W';
        case TOX_LOG_LEVEL_ERROR: return 'E';
    }

    return '?';
}

static const char *tox_err_new_name(Tox_Err_New err)
{
    switch (err) {
        case TOX_ERR_NEW_OK: return "OK";
        case TOX_ERR_NEW_NULL: return "NULL";
        case TOX_ERR_NEW_MALLOC: return "MALLOC";
        case TOX_ERR_NEW_PORT_ALLOC: return "PORT_ALLOC";
        case TOX_ERR_NEW_PROXY_BAD_TYPE: return "PROXY_BAD_TYPE";
        case TOX_ERR_NEW_PROXY_BAD_HOST: return "PROXY_BAD_HOST";
        case TOX_ERR_NEW_PROXY_BAD_PORT: return "PROXY_BAD_PORT";
        case TOX_ERR_NEW_PROXY_NOT_FOUND: return "PROXY_NOT_FOUND";
        case TOX_ERR_NEW_LOAD_ENCRYPTED: return "LOAD_ENCRYPTED";
        case TOX_ERR_NEW_LOAD_BAD_FORMAT: return "LOAD_BAD_FORMAT";
    }

    return "<unknown>";
}

static tox_log_cb log_handler;
static void log_handler(Tox *tox, Tox_Log_Level level, const char *file, uint32_t line, const char *func, const char *msg, void *user_data)
{
    printf("[%c] %s:%u(%s): %s\n", tox_log_level_name(level), file, (unsigned int)line, func, msg);
}

void tox_main()
{
    printf("Hello Tox!\n");

    Tox_Options *opts = tox_options_new(nullptr);
    assert(opts != nullptr);

    tox_options_set_log_callback(opts, log_handler);

    Tox_Err_New err;
    Tox *tox = tox_new(opts, &err);

    if (err == TOX_ERR_NEW_OK) {
        tox_events_free(tox_events_iterate(tox, true, nullptr));
    } else {
        printf("tox_new(): %s\n", tox_err_new_name(err));
    }

    tox_kill(tox);

    tox_options_free(opts);
}
