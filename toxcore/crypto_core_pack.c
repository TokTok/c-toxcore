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

bool pack_extended_public_key(const Extended_Public_Key *key, Bin_Pack *bp)
{
    uint8_t ext_key[EXT_PUBLIC_KEY_SIZE];
    static_assert(sizeof(ext_key) == sizeof(key->enc.data) + sizeof(key->sig.data),
                  "extended secret key size is not the sum of the encryption and sign secret key sizes");
    memcpy(ext_key, key->enc.data, sizeof(key->enc.data));
    memcpy(&ext_key[sizeof(key->enc.data)], key->sig.data, sizeof(key->sig.data));

    return bin_pack_bin(bp, ext_key, sizeof(ext_key));
}

bool pack_extended_secret_key(const Extended_Secret_Key *key, Bin_Pack *bp)
{
    uint8_t ext_key[EXT_SECRET_KEY_SIZE];
    static_assert(sizeof(ext_key) == sizeof(key->enc.data) + sizeof(key->sig.data),
                  "extended secret key size is not the sum of the encryption and sign secret key sizes");
    memcpy(ext_key, key->enc.data, sizeof(key->enc.data));
    memcpy(&ext_key[sizeof(key->enc.data)], key->sig.data, sizeof(key->sig.data));

    const bool result = bin_pack_bin(bp, ext_key, sizeof(ext_key));
    crypto_memzero(ext_key, sizeof(ext_key));
    return result;
}

bool unpack_extended_public_key(Extended_Public_Key *key, Bin_Unpack *bu)
{
    uint8_t ext_key[EXT_PUBLIC_KEY_SIZE];

    if (!bin_unpack_bin_fixed(bu, ext_key, sizeof(ext_key))) {
        return false;
    }

    memcpy(key->enc.data, ext_key, sizeof(key->enc.data));
    memcpy(key->sig.data, &ext_key[sizeof(key->enc.data)], sizeof(key->sig.data));

    return true;
}

bool unpack_extended_secret_key(Extended_Secret_Key *key, Bin_Unpack *bu)
{
    uint8_t ext_key[EXT_SECRET_KEY_SIZE];

    if (!bin_unpack_bin_fixed(bu, ext_key, sizeof(ext_key))) {
        return false;
    }

    memcpy(key->enc.data, ext_key, sizeof(key->enc.data));
    memcpy(key->sig.data, &ext_key[sizeof(key->enc.data)], sizeof(key->sig.data));
    crypto_memzero(ext_key, sizeof(ext_key));

    return true;
}
