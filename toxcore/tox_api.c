/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2021 The TokTok team.
 */
#include "tox.h"

#include "ccompat.h"

#include <stdlib.h>
#include <string.h>

#define SET_ERROR_PARAMETER(param, x) \
    do {                              \
        if (param) {                  \
            *param = x;               \
        }                             \
    } while (0)

//!TOKSTYLE-

#define CONST_FUNCTION(lowercase, uppercase) \
uint32_t tox_##lowercase(void) \
{ \
    return TOX_##uppercase; \
}

CONST_FUNCTION(version_major, VERSION_MAJOR)
CONST_FUNCTION(version_minor, VERSION_MINOR)
CONST_FUNCTION(version_patch, VERSION_PATCH)
CONST_FUNCTION(public_key_size, PUBLIC_KEY_SIZE)
CONST_FUNCTION(secret_key_size, SECRET_KEY_SIZE)
CONST_FUNCTION(conference_uid_size, CONFERENCE_UID_SIZE)
CONST_FUNCTION(conference_id_size, CONFERENCE_ID_SIZE)
CONST_FUNCTION(nospam_size, NOSPAM_SIZE)
CONST_FUNCTION(address_size, ADDRESS_SIZE)
CONST_FUNCTION(max_name_length, MAX_NAME_LENGTH)
CONST_FUNCTION(max_status_message_length, MAX_STATUS_MESSAGE_LENGTH)
CONST_FUNCTION(max_friend_request_length, MAX_FRIEND_REQUEST_LENGTH)
CONST_FUNCTION(max_message_length, MAX_MESSAGE_LENGTH)
CONST_FUNCTION(max_custom_packet_size, MAX_CUSTOM_PACKET_SIZE)
CONST_FUNCTION(hash_length, HASH_LENGTH)
CONST_FUNCTION(file_id_length, FILE_ID_LENGTH)
CONST_FUNCTION(max_filename_length, MAX_FILENAME_LENGTH)
CONST_FUNCTION(max_hostname_length, MAX_HOSTNAME_LENGTH)


#define ACCESSORS(type, ns, name) \
type tox_options_get_##ns##name(const struct Tox_Options *options) \
{ \
    return options->ns##name; \
} \
void tox_options_set_##ns##name(struct Tox_Options *options, type name) \
{ \
    options->ns##name = name; \
}

ACCESSORS(bool,, ipv6_enabled)
ACCESSORS(bool,, udp_enabled)
ACCESSORS(Tox_Proxy_Type, proxy_, type)
ACCESSORS(uint16_t, proxy_, port)
ACCESSORS(uint16_t,, start_port)
ACCESSORS(uint16_t,, end_port)
ACCESSORS(uint16_t,, tcp_port)
ACCESSORS(bool,, hole_punching_enabled)
ACCESSORS(Tox_Savedata_Type, savedata_, type)
ACCESSORS(size_t, savedata_, length)
ACCESSORS(tox_log_cb *, log_, callback)
ACCESSORS(void *, log_, user_data)
ACCESSORS(bool,, local_discovery_enabled)
ACCESSORS(bool,, experimental_thread_safety)

//!TOKSTYLE+

const char *tox_options_get_proxy_host(const struct Tox_Options *options)
{
    return options->proxy_host;
}

bool tox_options_set_proxy_host(struct Tox_Options *options, const char *host, size_t length)
{
    if (length > tox_max_hostname_length()) {
        return false;
    }

    if ((length > 0) && (host[length - 1] != '\0')) {
        // hostname not NUL terminated
        return false;
    }

    free(options->proxy_host);

    if ((host == nullptr) || (length == 0)) {
        // Successfully removed proxy hostname
        return true;
    }

    options->proxy_host = (char *) calloc(length, sizeof(char));

    if (options->proxy_host == nullptr) {
        // malloc error
        return false;
    }

    memcpy(options->proxy_host, host, length);
    return true;
}

const uint8_t *tox_options_get_savedata_data(const struct Tox_Options *options)
{
    return options->savedata_data;
}

bool tox_options_set_savedata_data(struct Tox_Options *options, const uint8_t *data, size_t length)
{
    free(options->savedata_data);

    if ((data == nullptr) || (length == 0)) {
        // Successfully removed savedata
        return true;
    }

    options->savedata_data = (uint8_t *) malloc(length);

    if (options->savedata_data == nullptr) {
        // malloc error
        options->savedata_length = 0;
        return false;
    }

    memcpy(options->savedata_data, data, length);
    options->savedata_length = length;
    return true;
}

struct Tox_Options *tox_options_new(Tox_Err_Options_New *error)
{
    struct Tox_Options *options = (struct Tox_Options *)malloc(sizeof(struct Tox_Options));

    if (options == nullptr) {
        SET_ERROR_PARAMETER(error, TOX_ERR_OPTIONS_NEW_MALLOC);
        return nullptr;
    }

    struct Tox_Options default_options = { 0 };

    *options = default_options;

    tox_options_set_ipv6_enabled(options, true);

    tox_options_set_udp_enabled(options, true);

    tox_options_set_proxy_type(options, TOX_PROXY_TYPE_NONE);

    tox_options_set_hole_punching_enabled(options, true);

    tox_options_set_local_discovery_enabled(options, true);

    tox_options_set_experimental_thread_safety(options, false);

    return options;
}

void tox_options_free(struct Tox_Options *options)
{
    if (options) {
        free(options->savedata_data);
        free(options->proxy_host);
    }

    free(options);
}
