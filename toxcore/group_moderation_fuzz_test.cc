#include "group_moderation.h"

namespace
{

void TestUnpackFunctions(const uint8_t *data, size_t size)
{
    if (size < 1) {
        return;
    }

    uint8_t func = data[0];
    ++data;
    --size;

    const uint8_t NUM_FUNCS = 3;

    switch (func % NUM_FUNCS) {
        case 0: {
            if (size < 1) {
                return;
            }

            const uint16_t num_mods = data[0];
            ++data;
            --size;
            Moderation mods{};
            mod_list_unpack(&mods, data, size, num_mods);
            mod_list_cleanup(&mods);
            break;
        }

        case 1: {
            Mod_Sanction sanctions[10];
            Mod_Sanction_Creds creds;
            uint16_t processed_data_len;
            sanctions_list_unpack(sanctions, &creds, 10, data, size, &processed_data_len);
            break;
        }

        case 2: {
            Mod_Sanction_Creds creds;
            sanctions_creds_unpack(&creds, data);
            break;
        }
    }
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    TestUnpackFunctions(data, size);
    return 0;
}
