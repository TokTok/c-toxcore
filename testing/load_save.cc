// Tests to make sure new save code is compatible with old save files

#include <fstream>
#include <vector>

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>

#include "../toxcore/tox.h"
#include "../toxcore/ccompat.h"

static const char *tox_log_level_name(Tox_Log_Level level)
{
    switch (level) {
        case TOX_LOG_LEVEL_TRACE:
            return "TRACE";

        case TOX_LOG_LEVEL_DEBUG:
            return "DEBUG";

        case TOX_LOG_LEVEL_INFO:
            return "INFO";

        case TOX_LOG_LEVEL_WARNING:
            return "WARNING";

        case TOX_LOG_LEVEL_ERROR:
            return "ERROR";
    }

    return "<unknown>";
}

static void print_debug_log(Tox *m, Tox_Log_Level level, const char *file, uint32_t line, const char *func,
                            const char *message, void *user_data)
{
    fprintf(stderr, "%s %s:%u\t%s:\t%s\n", tox_log_level_name(level), file, line, func, message);
}

static std::vector<uint8_t> read_save(const char *save_path)
{
    std::ifstream input(save_path, std::ios::binary);
    return std::vector<uint8_t>(std::istreambuf_iterator<char>(input), {});
}

static void load_save(const char *save_path)
{
    struct Tox_Options options = {0};
    tox_options_default(&options);

    std::vector<uint8_t> save_data = read_save(save_path);

    options.savedata_data = save_data.data();
    options.savedata_length = save_data.size();
    options.savedata_type = TOX_SAVEDATA_TYPE_TOX_SAVE;
    options.log_callback = print_debug_log;

    Tox *tox = tox_new(&options, nullptr);

    if (tox == nullptr) {
        return;
    }

    /* Giving the tox a chance to error on iterate due to corrupted loaded structures */
    tox_iterate(tox, nullptr);

    tox_kill(tox);
}

int main(int argc, char *argv[])
{
    for (int i = 1; i < argc; ++i) {
        load_save(argv[i]);
    }

    return 0;
}
