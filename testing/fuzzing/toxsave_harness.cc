#include <cassert>
#include <cstdint>
#include <vector>

#include "../../toxcore/tox.h"
#include "../../toxcore/tox_private.h"
#include "fuzz_support.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    Tox_Err_Options_New error_options;

    struct Tox_Options *tox_options = tox_options_new(&error_options);

    assert(tox_options != nullptr);
    assert(error_options == TOX_ERR_OPTIONS_NEW_OK);

    Fuzz_Data input{data + size, 0};  // empty data, since we use it all for savedata.
    Fuzz_System sys(input);
    tox_options_set_operating_system(tox_options, sys.sys.get());

    // pass test data to Tox
    tox_options_set_savedata_data(tox_options, data, size);
    tox_options_set_savedata_type(tox_options, TOX_SAVEDATA_TYPE_TOX_SAVE);

    Tox *tox = tox_new(tox_options, nullptr);
    tox_options_free(tox_options);
    if (tox == nullptr) {
        // Tox save was invalid, we're finished here
        return 0;
    }

    // verify that the file can be saved again
    std::vector<uint8_t> new_savedata(tox_get_savedata_size(tox));
    tox_get_savedata(tox, new_savedata.data());

    tox_kill(tox);
    return 0;  // Non-zero return values are reserved for future use.
}
