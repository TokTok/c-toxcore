/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2024 The TokTok team.
 * Copyright © 2013 Tox project.
 */

#include "crypto_core_pack.h"

#include <string.h>

#include "crypto_core.h"
#include "bin_pack.h"
#include "bin_unpack.h"

bool pack_extended_public_key(const Extended_Public_Key *key, Bin_Pack *bp)
{
    uint8_t ext_key[EXT_PUBLIC_KEY_SIZE];
    memcpy(ext_key, key->enc.data, CRYPTO_PUBLIC_KEY_SIZE);
    memcpy(ext_key + CRYPTO_PUBLIC_KEY_SIZE, key->sig.data, CRYPTO_SIGN_PUBLIC_KEY_SIZE);

    return bin_pack_bin(bp, ext_key, EXT_PUBLIC_KEY_SIZE);
}

bool pack_extended_secret_key(const Extended_Secret_Key *key, Bin_Pack *bp)
{
    uint8_t ext_key[EXT_SECRET_KEY_SIZE];
    memcpy(ext_key, key->enc.data, CRYPTO_SECRET_KEY_SIZE);
    memcpy(ext_key + CRYPTO_SECRET_KEY_SIZE, key->sig.data, CRYPTO_SIGN_SECRET_KEY_SIZE);

    return bin_pack_bin(bp, ext_key, EXT_SECRET_KEY_SIZE);
}

bool unpack_extended_public_key(Extended_Public_Key *key, Bin_Unpack *bu)
{
    uint8_t ext_key[EXT_PUBLIC_KEY_SIZE];

    if (!bin_unpack_bin_fixed(bu, ext_key, EXT_PUBLIC_KEY_SIZE)) {
        return false;
    }

    memcpy(key->enc.data, ext_key, CRYPTO_PUBLIC_KEY_SIZE);
    memcpy(key->sig.data, ext_key + CRYPTO_PUBLIC_KEY_SIZE, CRYPTO_SIGN_PUBLIC_KEY_SIZE);

    return true;
}

bool unpack_extended_secret_key(Extended_Secret_Key *key, Bin_Unpack *bu)
{
    uint8_t ext_key[EXT_SECRET_KEY_SIZE];

    if (!bin_unpack_bin_fixed(bu, ext_key, EXT_SECRET_KEY_SIZE)) {
        return false;
    }

    memcpy(key->enc.data, ext_key, CRYPTO_SECRET_KEY_SIZE);
    memcpy(key->sig.data, ext_key + CRYPTO_SECRET_KEY_SIZE, CRYPTO_SIGN_SECRET_KEY_SIZE);

    return true;
}
