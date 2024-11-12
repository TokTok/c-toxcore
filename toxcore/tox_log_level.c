#include "tox_log_level.h"

const char *tox_log_level_to_string(Tox_Log_Level value)
{
    switch (value) {
    case TOX_LOG_LEVEL_TRACE:
        return "TOX_LOG_LEVEL_TRACE";

    case TOX_LOG_LEVEL_DEBUG:
        return "TOX_LOG_LEVEL_DEBUG";

    case TOX_LOG_LEVEL_INFO:
        return "TOX_LOG_LEVEL_INFO";

    case TOX_LOG_LEVEL_WARNING:
        return "TOX_LOG_LEVEL_WARNING";

    case TOX_LOG_LEVEL_ERROR:
        return "TOX_LOG_LEVEL_ERROR";
    }

    return "<invalid Tox_Log_Level>";
}
