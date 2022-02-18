// Tests to make sure new save code is compatible with old save files

#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <vector>

#include "../toxcore/tox.h"
#include "misc_tools.h"

static std::vector<uint8_t> read_save(const char *save_path) {
  std::ifstream input(save_path, std::ios::binary);
  return std::vector<uint8_t>(std::istreambuf_iterator<char>(input), {});
}

static void load_save(const char *save_path) {
  struct Tox_Options options = {0};
  tox_options_default(&options);

  const std::vector<uint8_t> save_data = read_save(save_path);

  options.savedata_data = save_data.data();
  options.savedata_length = save_data.size();
  options.savedata_type = TOX_SAVEDATA_TYPE_TOX_SAVE;
  options.log_callback = [](Tox *m, Tox_Log_Level level, const char *file, uint32_t line,
                            const char *func, const char *message, void *user_data) {
    std::fprintf(stderr, "%s %s:%u\t%s:\t%s\n", tox_log_level_name(level), file, line, func,
                 message);
  };

  Tox *tox = tox_new(&options, nullptr);

  if (tox == nullptr) {
    return;
  }

  /* Giving the tox a chance to error on iterate due to corrupted loaded structures */
  tox_iterate(tox, nullptr);

  tox_kill(tox);
}

int main(int argc, char *argv[]) {
  for (int i = 1; i < argc; ++i) {
    load_save(argv[i]);
  }

  return 0;
}
