/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2025 The TokTok team.
 * Copyright © 2016 Tox project.
 */

/*
 * Small test for checking if obtaining savedata, saving it to disk and using
 * works correctly.
 */

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../toxcore/ccompat.h"
#include "../toxcore/tox.h"
#include "auto_test_support.h"
#include "check_compat.h"

#include "../toxcore/ccompat.h"
#include "../toxcore/tox.h"
#include "../toxencryptsave/toxencryptsave.h"

static const char *pphrase = "bar";
static const char *name = "foo";
static const char *savefile = "./save";

static void save_data_encrypted(void)
{
    struct Tox_Options *options = tox_options_new(nullptr);
    ck_assert(options != nullptr);
    Tox *t = tox_new_log(options, nullptr, nullptr);
    ck_assert(t != nullptr);
    tox_options_free(options);

    tox_self_set_name(t, (const uint8_t *)name, strlen(name), nullptr);

    FILE *f = fopen(savefile, "wb");
    ck_assert(f != nullptr);

    size_t size = tox_get_savedata_size(t);
    uint8_t *clear = (uint8_t *)malloc(size);
    ck_assert(clear != nullptr);

    /*this function does not write any data at all*/
    tox_get_savedata(t, clear);

    size += TOX_PASS_ENCRYPTION_EXTRA_LENGTH;
    uint8_t *cipher = (uint8_t *)malloc(size);
    ck_assert(cipher != nullptr);

    Tox_Err_Encryption eerr;

    ck_assert_msg(tox_pass_encrypt(clear, size - TOX_PASS_ENCRYPTION_EXTRA_LENGTH, (const uint8_t *)pphrase,
                                   strlen(pphrase), cipher,
                                   &eerr), "Could not encrypt, error code %u.", eerr);

    size_t written_value = fwrite(cipher, sizeof(*cipher), size, f);
    printf("written written_value = %u of %u\n", (unsigned)written_value, (unsigned)size);

    free(cipher);
    free(clear);
    fclose(f);
    tox_kill(t);
}

static void load_data_decrypted(void)
{
    FILE *f = fopen(savefile, "rb");
    ck_assert(f != nullptr);
    fseek(f, 0, SEEK_END);
    int64_t size = ftell(f);
    fseek(f, 0, SEEK_SET);

    ck_assert_msg(TOX_PASS_ENCRYPTION_EXTRA_LENGTH <= size && size <= UINT_MAX, "file size out of range");

    uint8_t *cipher = (uint8_t *)malloc(size);
    ck_assert(cipher != nullptr);
    const size_t clear_size = size - TOX_PASS_ENCRYPTION_EXTRA_LENGTH;
    uint8_t *clear = (uint8_t *)malloc(clear_size);
    ck_assert(clear != nullptr);
    size_t read_value = fread(cipher, sizeof(*cipher), size, f);
    printf("Read read_value = %u of %u\n", (unsigned)read_value, (unsigned)size);

    Tox_Err_Decryption derr;

    ck_assert_msg(tox_pass_decrypt(cipher, size, (const uint8_t *)pphrase, strlen(pphrase), clear, &derr),
                  "Could not decrypt, error code %s.", tox_err_decryption_to_string(derr));

    struct Tox_Options *options = tox_options_new(nullptr);
    ck_assert(options != nullptr);

    tox_options_set_experimental_owned_data(options, true);
    tox_options_set_savedata_type(options, TOX_SAVEDATA_TYPE_TOX_SAVE);
    ck_assert(tox_options_set_savedata_data(options, clear, clear_size));
    free(clear);

    Tox_Err_New err;

    Tox *t = tox_new_log(options, &err, nullptr);
    ck_assert_msg(t != nullptr, "tox_new returned the error value %s", tox_err_new_to_string(err));

    tox_options_free(options);

    uint8_t *readname = (uint8_t *)malloc(tox_self_get_name_size(t));
    ck_assert(readname != nullptr);
    tox_self_get_name(t, readname);

    ck_assert_msg(memcmp(readname, name, tox_self_get_name_size(t)) == 0,
                  "name returned by tox_self_get_name does not match expected result");

    tox_kill(t);
    free(cipher);
    free(readname);
    fclose(f);
}

int main(void)
{
    setvbuf(stdout, nullptr, _IONBF, 0);
    save_data_encrypted();
    load_data_decrypted();

    ck_assert_msg(remove(savefile) == 0, "Could not remove the savefile.");

    return 0;
}
