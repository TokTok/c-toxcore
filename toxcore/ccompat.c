/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2021 The TokTok team.
 */
#include "ccompat.h"

#include <stdlib.h>
#include <string.h>

void *salloc(uint32_t size, const void *default_value)
{
    void *ptr = malloc(size);

    if (ptr != nullptr) {
        memcpy(ptr, default_value, size);
    }

    return ptr;
}
