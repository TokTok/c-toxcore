/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2023 The TokTok team.
 */
#include "pk_set.h"

#include <assert.h>

#include "ccompat.h"
#include "crypto_core.h"
#include "util.h"

typedef struct Public_Key_Ptr {
    const uint8_t *data;
} Public_Key_Ptr;

struct Pk_Set {
    const Memory *mem;

    Public_Key_Ptr *data;
    uint8_t size;
    uint8_t capacity;
};

Pk_Set *pk_set_new(const Memory *mem, uint16_t initial_capacity)
{
    Pk_Set *pks = (Pk_Set *)mem_alloc(mem, sizeof(Pk_Set));

    if (pks == nullptr) {
        return nullptr;
    }

    const uint8_t capacity = max_u08(1, min_u16(initial_capacity, UINT8_MAX));
    Public_Key_Ptr *data = (Public_Key_Ptr *)mem_valloc(mem, capacity, sizeof(Public_Key_Ptr));

    if (data == nullptr) {
        mem_delete(mem, pks);
        return nullptr;
    }

    pks->mem = mem;

    pks->data = data;
    pks->size = 0;
    pks->capacity = capacity;

    return pks;
}

void pk_set_free(Pk_Set *pks)
{
    if (pks == nullptr) {
        return;
    }

    mem_delete(pks->mem, pks->data);
    mem_delete(pks->mem, pks);
}

bool pk_set_add(Pk_Set *pks, const uint8_t *pk)
{
    if (pk_set_contains(pks, pk)) {
        return false;
    }

    if (pks->size == UINT8_MAX) {
        return false;
    }

    if (pks->size == pks->capacity) {
        // If doubling the capacity would grow the array beyond 8 bits, max out at 8 bits.
        const uint8_t new_capacity = pks->capacity > UINT8_MAX / 2 ? UINT8_MAX : pks->capacity * 2;
        Public_Key_Ptr *new_data = (Public_Key_Ptr *)mem_valloc(pks->mem, new_capacity, sizeof(Public_Key_Ptr));

        if (new_data == nullptr) {
            return false;
        }

        for (uint8_t i = 0; i < pks->size; ++i) {
            new_data[i] = pks->data[i];
        }

        mem_delete(pks->mem, pks->data);
        pks->capacity = new_capacity;
        pks->data = new_data;
    }

    assert(pks->size + 1 <= pks->capacity);
    pks->data[pks->size].data = pk;
    ++pks->size;

    return true;
}

bool pk_set_contains(Pk_Set *pks, const uint8_t *pk)
{
    for (uint8_t i = 0; i < pks->size; ++i) {
        if (memeq(pks->data[i].data, CRYPTO_PUBLIC_KEY_SIZE, pk, CRYPTO_PUBLIC_KEY_SIZE)) {
            return true;
        }
    }

    return false;
}
