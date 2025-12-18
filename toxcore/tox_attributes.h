/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2022-2025 The TokTok team.
 */

/**
 * nonnull attributes for GCC/Clang and Cimple.
 *
 * This file is a modified version of c-toxcore/toxcore/attributes.h with a
 * `tox_` prefix added to the macros to avoid conflicts with client code.
 */
#ifndef C_TOXCORE_TOXCORE_TOX_ATTRIBUTES_H
#define C_TOXCORE_TOXCORE_TOX_ATTRIBUTES_H

/* No declarations here. */

//!TOKSTYLE-

#ifndef __clang__
#define _Nonnull
#define _Nullable
#endif

#ifndef _Owned
#define _Owned
#endif

#ifdef SPARSE
#define tox_bitwise __attribute__((bitwise))
#else
#define tox_bitwise
#endif

//!TOKSTYLE+

#endif /* C_TOXCORE_TOXCORE_TOX_ATTRIBUTES_H */
