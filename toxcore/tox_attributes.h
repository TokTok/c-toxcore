/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2022-2023 The TokTok team.
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

#if defined(__GNUC__) && defined(_DEBUG) && !defined(__OPTIMIZE__)
#define tox_non_null(...) __attribute__((__nonnull__(__VA_ARGS__)))
#else
#define tox_non_null(...)
#endif

#define tox_nullable(...)

#ifdef SPARSE
#define tox_bitwise __attribute__((bitwise))
#define tox_force __attribute__((force))
#else
#define tox_bitwise
#define tox_force
#endif

//!TOKSTYLE+

#endif /* C_TOXCORE_TOXCORE_TOX_ATTRIBUTES_H */
