#include <cassert>
#include <cstdint>
#include <vector>

#include "../../toxcore/tox.h"
#include "../../toxcore/tox_struct.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    Tox_Err_Options_New error_options;

    struct Tox_Options *tox_options = tox_options_new(&error_options);

    assert(tox_options != nullptr);
    assert(error_options == TOX_ERR_OPTIONS_NEW_OK);

    // pass test data to Tox
    tox_options_set_savedata_data(tox_options, data, size);
    tox_options_set_savedata_type(tox_options, TOX_SAVEDATA_TYPE_TOX_SAVE);

    Tox *tox = tox_new(tox_options, nullptr);

    tox_options_free(tox_options);
    if (tox == nullptr) {
        // Tox save was invalid, we're finished here
        return 0;
    }

    uint64_t clock = 0;
    mono_time_set_current_time_callback(
        tox->mono_time,
        [](Mono_Time *mono_time, void *user_data) { return *static_cast<uint64_t *>(user_data); },
        &clock);

    // verify that the file can be saved again
    std::vector<uint8_t> new_savedata(tox_get_savedata_size(tox));
    tox_get_savedata(tox, new_savedata.data());

    tox_kill(tox);
    return 0;  // Non-zero return values are reserved for future use.
}
