/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2020 The TokTok team.
 * Copyright © 2015 Tox project.
 */

#ifndef C_TOXCORE_TOXCORE_GROUP_ONION_ANNOUNCE_H
#define C_TOXCORE_TOXCORE_GROUP_ONION_ANNOUNCE_H

#include "group_announce.h"
#include "onion_announce.h"

non_null()
void gca_onion_init(GC_Announces_List *group_announce, Onion_Announce *onion_a);

#endif  // C_TOXCORE_TOXCORE_GROUP_ONION_ANNOUNCE_H
