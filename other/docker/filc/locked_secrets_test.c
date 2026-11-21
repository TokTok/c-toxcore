/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2026 The TokTok team.
 */

/* Checks that toxcore locks the memory it keeps secret keys in. */

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../../../toxcore/ccompat.h"
#include "../../../toxcore/tox.h"

/* Returns the amount of memory this process has locked, in kB. */
static long locked_memory(void)
{
    FILE *const status = fopen("/proc/self/status", "r");
    if (status == nullptr) {
        return -1;
    }

    long locked = -1;
    char line[256];
    while (fgets(line, sizeof(line), status) != nullptr) {
        if (sscanf(line, "VmLck: %ld kB", &locked) == 1) {
            break;
        }
    }

    fclose(status);
    return locked;
}

int main(void)
{
    Tox *const tox = tox_new(nullptr, nullptr);
    if (tox == nullptr) {
        fprintf(stderr, "tox_new failed\n");
        return 1;
    }

    const long locked = locked_memory();

    const uint8_t name[] = "name";
    tox_group_new(tox, TOX_GROUP_PRIVACY_STATE_PRIVATE, name, sizeof(name), name, sizeof(name), nullptr);
    const long locked_with_group = locked_memory();

    tox_kill(tox);

    printf("%ld kB of memory locked, %ld kB with a group\n", locked, locked_with_group);
    if (locked <= 0) {
        fprintf(stderr, "No memory is locked: secrets can be swapped to disk\n");
        return 1;
    }
    if (locked_with_group <= locked) {
        fprintf(stderr, "A group locks no memory: its secret keys can be swapped to disk\n");
        return 1;
    }

    return 0;
}
