/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2018 The TokTok team.
 * Copyright © 2013 Tox project.
 */

#include "internal.h"

#include <stdlib.h>
#include <string.h>

#include "../ccompat.h"

Tox_Events *tox_events_alloc(void *user_data)
{
    Tox_Events **events_ptr = (Tox_Events **)user_data;
    assert(events_ptr != nullptr);

    if (*events_ptr == nullptr) {
        *events_ptr = new (Tox_Events);
    }

    return *events_ptr;
}
