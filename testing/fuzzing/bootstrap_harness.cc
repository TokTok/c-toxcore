#include "../../toxcore/tox.h"
#include "fuzz_adapter.h"

#include <cstring>
#include <cassert>


extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    network_adapter_init(Data, Size);

    Tox_Err_New error_new;
    Tox *tox = tox_new(NULL, &error_new);

    if (tox == nullptr || error_new != TOX_ERR_NEW_OK) {
        return 0;
    }

    uint8_t pub_key[TOX_PUBLIC_KEY_SIZE] = {0};

    assert(tox_bootstrap(tox, "127.0.0.1", 12345, pub_key, nullptr));

    for (uint32_t i = 0; i < 100; i++) {
        tox_iterate(tox, nullptr);
    }

    tox_kill(tox);
    return 0;  // Non-zero return values are reserved for future use.
}
