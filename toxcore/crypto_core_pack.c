/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2024 The TokTok team.
 * Copyright © 2013 Tox project.
 */

#include "crypto_core_pack.h"

#include <string.h>

#include "bin_pack.h"
#include "bin_unpack.h"
#include "ccompat.h"
#include "crypto_core.h"

static_assert(EXT_PUBLIC_KEY_SIZE == CRYPTO_PUBLIC_KEY_SIZE + CRYPTO_SIGN_PUBLIC_KEY_SIZE,
    "extended public key size is not the sum of the encryption and sign public key sizes");
static_assert(EXT_SECRET_KEY_SIZE == CRYPTO_SECRET_KEY_SIZE + CRYPTO_SIGN_SECRET_KEY_SIZE,
    "extended secret key size is not the sum of the encryption and sign secret key sizes");

bool pack_extended_public_key(const Extended_Public_Key *key, Bin_Pack *bp)
{
    uint8_t ext_key[EXT_PUBLIC_KEY_SIZE];
    memcpy(ext_key, key->enc, CRYPTO_PUBLIC_KEY_SIZE);
    memcpy(&ext_key[CRYPTO_PUBLIC_KEY_SIZE], key->sig, CRYPTO_SIGN_PUBLIC_KEY_SIZE);

    const bool result = bin_pack_bin(bp, ext_key, EXT_PUBLIC_KEY_SIZE);
    crypto_memzero(ext_key, EXT_PUBLIC_KEY_SIZE);
    return result;
}

bool pack_extended_secret_key(const Extended_Secret_Key *key, Bin_Pack *bp)
{
    uint8_t ext_key[EXT_SECRET_KEY_SIZE];
    memcpy(ext_key, key->enc, CRYPTO_SECRET_KEY_SIZE);
    memcpy(&ext_key[CRYPTO_SECRET_KEY_SIZE], key->sig, CRYPTO_SIGN_SECRET_KEY_SIZE);

    const bool result = bin_pack_bin(bp, ext_key, EXT_SECRET_KEY_SIZE);
    crypto_memzero(ext_key, EXT_SECRET_KEY_SIZE);
    return result;
}

bool unpack_extended_public_key(Extended_Public_Key *key, Bin_Unpack *bu)
{
    uint8_t ext_key[EXT_PUBLIC_KEY_SIZE];

    if (!bin_unpack_bin_fixed(bu, ext_key, EXT_PUBLIC_KEY_SIZE)) {
        return false;
    }

    memcpy(key->enc, ext_key, CRYPTO_PUBLIC_KEY_SIZE);
    memcpy(key->sig, &ext_key[CRYPTO_PUBLIC_KEY_SIZE], CRYPTO_SIGN_PUBLIC_KEY_SIZE);
    crypto_memzero(ext_key, EXT_PUBLIC_KEY_SIZE);

    return true;
}

bool unpack_extended_secret_key(Extended_Secret_Key *key, Bin_Unpack *bu)
{
    uint8_t ext_key[EXT_SECRET_KEY_SIZE];

    if (!bin_unpack_bin_fixed(bu, ext_key, EXT_SECRET_KEY_SIZE)) {
        return false;
    }

    memcpy(key->enc, ext_key, CRYPTO_SECRET_KEY_SIZE);
    memcpy(key->sig, &ext_key[CRYPTO_SECRET_KEY_SIZE], CRYPTO_SIGN_SECRET_KEY_SIZE);
    crypto_memzero(ext_key, EXT_SECRET_KEY_SIZE);

    return true;
}
