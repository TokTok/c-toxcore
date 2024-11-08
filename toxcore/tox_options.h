/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2018 The TokTok team.
 * Copyright © 2013 Tox project.
 */

#ifndef C_TOXCORE_TOXCORE_TOX_OPTIONS_H
#define C_TOXCORE_TOXCORE_TOX_OPTIONS_H

#include "tox_attributes.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct Tox_Options Tox_Options;

/**
 * @brief Initialises a Tox_Options object with the default options.
 *
 * The result of this function is independent of the original options. All
 * values will be overwritten, no values will be read (so it is permissible
 * to pass an uninitialised object).
 *
 * If options is NULL, this function has no effect.
 *
 * @param options An options object to be filled with default options.
 */
non_null()
void tox_options_default(Tox_Options *options);

typedef enum Tox_Err_Options_New {
    /**
     * The function returned successfully.
     */
    TOX_ERR_OPTIONS_NEW_OK,

    /**
     * The function failed to allocate enough memory for the options struct.
     */
    TOX_ERR_OPTIONS_NEW_MALLOC,
} Tox_Err_Options_New;

const char *tox_err_options_new_to_string(Tox_Err_Options_New value);


/**
 * @brief Allocates a new Tox_Options object and initialises it with the default
 *   options.
 *
 * This function can be used to preserve long term ABI compatibility by
 * giving the responsibility of allocation and deallocation to the Tox library.
 *
 * Objects returned from this function must be freed using the tox_options_free
 * function.
 *
 * @return A new Tox_Options object with default options or NULL on failure.
 */
nullable(1)
Tox_Options *tox_options_new(Tox_Err_Options_New *error);

/**
 * @brief Releases all resources associated with an options objects.
 *
 * Passing a pointer that was not returned by tox_options_new results in
 * undefined behaviour.
 */
nullable(1)
void tox_options_free(Tox_Options *options);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* C_TOXCORE_TOXCORE_TOX_OPTIONS_H */
