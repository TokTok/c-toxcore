/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2026 The TokTok team.
 * Copyright © 2013 Tox project.
 */

/* Note that Tox_Options has two kinds of string/array members:
 * 1. Legacy string/array members:
 *   Tox_Options initially used to be just a struct without member functions,
 *   with the API user setting Tox_Options's members directly. Due to this,
 *   legacy string/array members are set directly from the user data, i.e.
 *   Tox_Options takes the API user owned data pointer and keeps/uses it as is,
 *   without copying the underlying data. Tox_Options assumes API user's data
 *   pointer remains valid and outlives the Tox_Options instance.
 *
 *   Later it was decided that it's better for ABI compatibility to make
 *   Tox_Options an opaque pointer and use setters/getters instead. (New members
 *   kept getting added to Tox_Options struct, increasing its size, which breaks
 *   ABI compatibility and requires software recompilation). Currently
 *   Tox_Options hasn't been made an opaque pointer yet (expected to be done in
 *   a future API-breaking release), but its direct use has been deprecated in
 *   favor of member functions.
 *
 *   With member functions being introduced and direct struct access being
 *   deprecated, `experimental_owned_data` member was added. If set to true,
 *   Tox_Options's member setter functions for the legacy string/array members
 *   will copy user's data and make it owned by Tox_Options. That way, the
 *   user code that uses the API by setting the members directly will still
 *   continue to work, but newer user code which is aware of the direct access
 *   deprecation and thus only uses the member function - can opt into
 *   Tox_Options owning the member's data. To facilitate this, Tox_Options has
 *   added an `owned_` pointer member for every legacy string/array member,
 *   which stores the pointer owned by Tox_Options.
 *
 *   So legacy string/array members can be user pointers, or Tox_Option's owned
 *   pointers, depending on the `experimental_owned_data` flag.
 *
 * 2. New string/array members:
 *   New string/array members were added *after* the transition from the direct
 *   struct access, to using the member functions, has happened. As such, there
 *   should be no user code that accesses them directly that we must support,
 *   any user code that wants to set/get them must be aware of the direct
 *   struct access deprecation. Given that, it was decided that these new
 *   string/array members will be owned by Tox_Options regardless of the
 *   `experimental_owned_data` flag. The API user must set these new member
 *   using the setter functions only, which in turn will make an Tox_Options
 *   owned copy of the data, storing the owned pointer in the regular struct
 *   member (no extra `owned_` pointer) that the user must never set directly.
 *   These new members' names start with "internal_do_not_set_directly_"
 *   prefix.
 *
 *   If you are adding new string/array members, you should add them like this.
 */

#include "tox_options.h"

#include <stdlib.h> // free, malloc, calloc
#include <string.h> // memcpy, strlen

#include "ccompat.h" // nullptr

#define SET_ERROR_PARAMETER(param, x) \
    do {                              \
        if (param != nullptr) {       \
            *param = x;               \
        }                             \
    } while (0)


bool tox_options_get_ipv6_enabled(const Tox_Options *_Nonnull options)
{
    return options->ipv6_enabled;
}
void tox_options_set_ipv6_enabled(Tox_Options *_Nonnull options, bool ipv6_enabled)
{
    options->ipv6_enabled = ipv6_enabled;
}
bool tox_options_get_udp_enabled(const Tox_Options *_Nonnull options)
{
    return options->udp_enabled;
}
void tox_options_set_udp_enabled(Tox_Options *_Nonnull options, bool udp_enabled)
{
    options->udp_enabled = udp_enabled;
}
Tox_Proxy_Type tox_options_get_proxy_type(const Tox_Options *_Nonnull options)
{
    return options->proxy_type;
}
void tox_options_set_proxy_type(Tox_Options *_Nonnull options, Tox_Proxy_Type proxy_type)
{
    options->proxy_type = proxy_type;
}
static bool options_set_string_experimental_owned_data(bool experimental_owned_data, const char *_Nullable *_Nonnull options_str, char *_Nullable *_Nonnull options_owned_str,
        const char *_Nullable user_str)
{
    if (!experimental_owned_data) {
        *options_str = user_str;
        return true;
    }

    if (*options_owned_str != nullptr) {
        free(*options_owned_str);
        *options_owned_str = nullptr;
    }
    if (user_str == nullptr) {
        *options_str = nullptr;
        return true;
    }

    const size_t user_str_length = strlen(user_str) + 1;
    char *owned_ptr = (char *)malloc(user_str_length);
    if (owned_ptr == nullptr) {
        *options_str = user_str;
        *options_owned_str = nullptr;
        return false;
    }

    memcpy(owned_ptr, user_str, user_str_length);
    *options_str = owned_ptr;
    *options_owned_str = owned_ptr;
    return true;
}
const char *_Nullable tox_options_get_proxy_host(const Tox_Options *_Nonnull options)
{
    return options->proxy_host;
}
bool tox_options_set_proxy_host(Tox_Options *_Nonnull options, const char *_Nullable proxy_host)
{
    return options_set_string_experimental_owned_data(options->experimental_owned_data, &options->proxy_host, &options->owned_proxy_host, proxy_host);
}
Tox_Port tox_options_get_proxy_port(const Tox_Options *_Nonnull options)
{
    return options->proxy_port;
}
void tox_options_set_proxy_port(Tox_Options *_Nonnull options, Tox_Port proxy_port)
{
    options->proxy_port = proxy_port;
}
size_t tox_options_get_proxy_socks5_username_length(const Tox_Options *_Nonnull options)
{
    return options->internal_do_not_set_directly_proxy_socks5_username_length;
}
size_t tox_options_get_proxy_socks5_password_length(const Tox_Options *_Nonnull options)
{
    return options->internal_do_not_set_directly_proxy_socks5_password_length;
}
Tox_Port tox_options_get_start_port(const Tox_Options *_Nonnull options)
{
    return options->start_port;
}
void tox_options_set_start_port(Tox_Options *_Nonnull options, Tox_Port start_port)
{
    options->start_port = start_port;
}
Tox_Port tox_options_get_end_port(const Tox_Options *_Nonnull options)
{
    return options->end_port;
}
void tox_options_set_end_port(Tox_Options *_Nonnull options, Tox_Port end_port)
{
    options->end_port = end_port;
}
Tox_Port tox_options_get_tcp_port(const Tox_Options *_Nonnull options)
{
    return options->tcp_port;
}
void tox_options_set_tcp_port(Tox_Options *_Nonnull options, Tox_Port tcp_port)
{
    options->tcp_port = tcp_port;
}
bool tox_options_get_hole_punching_enabled(const Tox_Options *_Nonnull options)
{
    return options->hole_punching_enabled;
}
void tox_options_set_hole_punching_enabled(Tox_Options *_Nonnull options, bool hole_punching_enabled)
{
    options->hole_punching_enabled = hole_punching_enabled;
}
Tox_Savedata_Type tox_options_get_savedata_type(const Tox_Options *_Nonnull options)
{
    return options->savedata_type;
}
void tox_options_set_savedata_type(Tox_Options *_Nonnull options, Tox_Savedata_Type savedata_type)
{
    options->savedata_type = savedata_type;
}
size_t tox_options_get_savedata_length(const Tox_Options *_Nonnull options)
{
    return options->savedata_length;
}
void tox_options_set_savedata_length(Tox_Options *_Nonnull options, size_t savedata_length)
{
    options->savedata_length = savedata_length;
}
tox_log_cb *_Nullable tox_options_get_log_callback(const Tox_Options *_Nonnull options)
{
    return options->log_callback;
}
void tox_options_set_log_callback(Tox_Options *_Nonnull options, tox_log_cb *_Nullable log_callback)
{
    options->log_callback = log_callback;
}
void *_Nullable tox_options_get_log_user_data(const Tox_Options *_Nonnull options)
{
    return options->log_user_data;
}
void tox_options_set_log_user_data(Tox_Options *_Nonnull options, void *_Nullable log_user_data)
{
    options->log_user_data = log_user_data;
}
bool tox_options_get_local_discovery_enabled(const Tox_Options *_Nonnull options)
{
    return options->local_discovery_enabled;
}
void tox_options_set_local_discovery_enabled(Tox_Options *_Nonnull options, bool local_discovery_enabled)
{
    options->local_discovery_enabled = local_discovery_enabled;
}
bool tox_options_get_dht_announcements_enabled(const Tox_Options *_Nonnull options)
{
    return options->dht_announcements_enabled;
}
void tox_options_set_dht_announcements_enabled(Tox_Options *_Nonnull options, bool dht_announcements_enabled)
{
    options->dht_announcements_enabled = dht_announcements_enabled;
}
bool tox_options_get_experimental_thread_safety(const Tox_Options *_Nonnull options)
{
    return options->experimental_thread_safety;
}
void tox_options_set_experimental_thread_safety(
    Tox_Options *_Nonnull options, bool experimental_thread_safety)
{
    options->experimental_thread_safety = experimental_thread_safety;
}
bool tox_options_get_experimental_groups_persistence(const Tox_Options *_Nonnull options)
{
    return options->experimental_groups_persistence;
}
void tox_options_set_experimental_groups_persistence(
    Tox_Options *_Nonnull options, bool experimental_groups_persistence)
{
    options->experimental_groups_persistence = experimental_groups_persistence;
}
bool tox_options_get_experimental_disable_dns(const Tox_Options *_Nonnull options)
{
    return options->experimental_disable_dns;
}
void tox_options_set_experimental_disable_dns(Tox_Options *_Nonnull options, bool experimental_disable_dns)
{
    options->experimental_disable_dns = experimental_disable_dns;
}
bool tox_options_get_experimental_owned_data(const Tox_Options *_Nonnull options)
{
    return options->experimental_owned_data;
}
void tox_options_set_experimental_owned_data(
    Tox_Options *_Nonnull options, bool experimental_owned_data)
{
    options->experimental_owned_data = experimental_owned_data;
}

static bool options_set_array_experimental_owned_data(bool experimental_owned_data, const uint8_t *_Nullable *_Nonnull options_data, size_t *_Nonnull options_length,
        uint8_t *_Nullable *_Nonnull options_owned_data, const uint8_t *_Nullable user_data, size_t user_length)
{
    if (!experimental_owned_data) {
        *options_data = user_data;
        *options_length = user_length;
        return true;
    }

    if (*options_owned_data != nullptr) {
        free(*options_owned_data);
        *options_owned_data = nullptr;
    }

    if (user_data == nullptr || user_length == 0) {
        *options_data = nullptr;
        *options_length = 0;
        return true;
    }

    uint8_t *owned_ptr = (uint8_t *)malloc(user_length);
    if (owned_ptr == nullptr) {
        *options_data = user_data;
        *options_length = user_length;
        *options_owned_data = nullptr;
        return false;
    }

    memcpy(owned_ptr, user_data, user_length);
    *options_data = owned_ptr;
    *options_length = user_length;
    *options_owned_data = owned_ptr;
    return true;
}

static bool options_set_array(uint8_t *_Nullable *_Nonnull options_data, size_t *_Nonnull options_length, const uint8_t *_Nullable user_data, size_t user_length)
{
    if (*options_data != nullptr) {
        free(*options_data);
    }

    if (user_data == nullptr || user_length == 0) {
        *options_data = nullptr;
        *options_length = 0;
        return true;
    }

    uint8_t *owned_ptr = (uint8_t *)malloc(user_length);
    if (owned_ptr == nullptr) {
        *options_data = nullptr;
        *options_length = 0;
        return false;
    }

    memcpy(owned_ptr, user_data, user_length);
    *options_data = owned_ptr;
    *options_length = user_length;
    return true;
}

uint8_t *_Nullable tox_options_get_proxy_socks5_username(const Tox_Options *_Nonnull options)
{
    return options->internal_do_not_set_directly_proxy_socks5_username;
}

bool tox_options_set_proxy_socks5_username(Tox_Options *_Nonnull options, const uint8_t username[_Nullable], size_t length)
{
    return options_set_array(&options->internal_do_not_set_directly_proxy_socks5_username,
                             &options->internal_do_not_set_directly_proxy_socks5_username_length,
                             username, length);
}

uint8_t *_Nullable tox_options_get_proxy_socks5_password(const Tox_Options *_Nonnull options)
{
    return options->internal_do_not_set_directly_proxy_socks5_password;
}

bool tox_options_set_proxy_socks5_password(Tox_Options *_Nonnull options, const uint8_t password[_Nullable], size_t length)
{
    return options_set_array(&options->internal_do_not_set_directly_proxy_socks5_password,
                             &options->internal_do_not_set_directly_proxy_socks5_password_length,
                             password, length);
}

const uint8_t *_Nullable tox_options_get_savedata_data(const Tox_Options *_Nonnull options)
{
    return options->savedata_data;
}

bool tox_options_set_savedata_data(Tox_Options *_Nonnull options, const uint8_t *_Nullable savedata_data, size_t length)
{
    return options_set_array_experimental_owned_data(options->experimental_owned_data,
            &options->savedata_data, &options->savedata_length,
            &options->owned_savedata_data,
            savedata_data, length);
}

void tox_options_default(Tox_Options *_Nonnull options)
{
    if (options != nullptr) {
        // Free any owned data.
        tox_options_set_proxy_host(options, nullptr);
        tox_options_set_proxy_socks5_username(options, nullptr, 0);
        tox_options_set_proxy_socks5_password(options, nullptr, 0);
        tox_options_set_savedata_data(options, nullptr, 0);

        // Set the rest to default values.
        const Tox_Options default_options = {false};
        *options = default_options;
        tox_options_set_ipv6_enabled(options, true);
        tox_options_set_udp_enabled(options, true);
        tox_options_set_proxy_type(options, TOX_PROXY_TYPE_NONE);
        tox_options_set_hole_punching_enabled(options, true);
        tox_options_set_local_discovery_enabled(options, true);
        tox_options_set_dht_announcements_enabled(options, true);
        tox_options_set_experimental_thread_safety(options, false);
        tox_options_set_experimental_groups_persistence(options, false);
        tox_options_set_experimental_disable_dns(options, false);
        tox_options_set_experimental_owned_data(options, false);
    }
}

void tox_options_copy(Tox_Options *_Nullable dest, const Tox_Options *_Nullable src)
{
    if (dest != nullptr && src != nullptr && dest != src) {
        // Free any owned members in dest
        tox_options_set_proxy_host(dest, nullptr);
        tox_options_set_proxy_socks5_username(dest, nullptr, 0);
        tox_options_set_proxy_socks5_password(dest, nullptr, 0);
        tox_options_set_savedata_data(dest, nullptr, 0);

        // Copy all non-owned members
        *dest = *src;

        // Clear dest's owned members as they now point to src's owned memory
        dest->owned_proxy_host = nullptr;
        dest->internal_do_not_set_directly_proxy_socks5_username = nullptr;
        dest->internal_do_not_set_directly_proxy_socks5_username_length = 0;
        dest->internal_do_not_set_directly_proxy_socks5_password = nullptr;
        dest->internal_do_not_set_directly_proxy_socks5_password_length = 0;
        dest->owned_savedata_data = nullptr;

        // Copy src's owned members to dest
        tox_options_set_proxy_host(dest, src->proxy_host);
        tox_options_set_proxy_socks5_username(dest, src->internal_do_not_set_directly_proxy_socks5_username, src->internal_do_not_set_directly_proxy_socks5_username_length);
        tox_options_set_proxy_socks5_password(dest, src->internal_do_not_set_directly_proxy_socks5_password, src->internal_do_not_set_directly_proxy_socks5_password_length);
        tox_options_set_savedata_data(dest, src->savedata_data, src->savedata_length);
    }
}

Tox_Options *_Nullable tox_options_new(Tox_Err_Options_New *_Nullable error)
{
    Tox_Options *options = (Tox_Options *)calloc(1, sizeof(Tox_Options));

    if (options != nullptr) {
        tox_options_default(options);
        SET_ERROR_PARAMETER(error, TOX_ERR_OPTIONS_NEW_OK);
        return options;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_OPTIONS_NEW_MALLOC);
    return nullptr;
}

void tox_options_free(Tox_Options *_Nullable options)
{
    if (options != nullptr) {
        // Free any owned data.
        tox_options_set_proxy_host(options, nullptr);
        tox_options_set_proxy_socks5_username(options, nullptr, 0);
        tox_options_set_proxy_socks5_password(options, nullptr, 0);
        tox_options_set_savedata_data(options, nullptr, 0);
        free(options);
    }
}
