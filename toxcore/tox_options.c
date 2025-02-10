/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2025 The TokTok team.
 * Copyright © 2013 Tox project.
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


bool tox_options_get_ipv6_enabled(const Tox_Options *options)
{
    return options->ipv6_enabled;
}
void tox_options_set_ipv6_enabled(Tox_Options *options, bool ipv6_enabled)
{
    options->ipv6_enabled = ipv6_enabled;
}
bool tox_options_get_udp_enabled(const Tox_Options *options)
{
    return options->udp_enabled;
}
void tox_options_set_udp_enabled(Tox_Options *options, bool udp_enabled)
{
    options->udp_enabled = udp_enabled;
}
Tox_Proxy_Type tox_options_get_proxy_type(const Tox_Options *options)
{
    return options->proxy_type;
}
void tox_options_set_proxy_type(Tox_Options *options, Tox_Proxy_Type proxy_type)
{
    options->proxy_type = proxy_type;
}
static bool options_set_string_experimental_owned_data(bool experimental_owned_data, const char **options_str, char **options_owned_str, const char *user_str)
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

const char *tox_options_get_proxy_host(const Tox_Options *options)
{
    return options->proxy_host;
}
bool tox_options_set_proxy_host(Tox_Options *options, const char *proxy_host)
{
    return options_set_string_experimental_owned_data(options->experimental_owned_data, &options->proxy_host, &options->owned_proxy_host, proxy_host);
}
uint16_t tox_options_get_proxy_port(const Tox_Options *options)
{
    return options->proxy_port;
}
void tox_options_set_proxy_port(Tox_Options *options, uint16_t proxy_port)
{
    options->proxy_port = proxy_port;
}
size_t tox_options_get_proxy_socks5_username_length(const Tox_Options *options)
{
    return options->internal_do_not_set_directly_proxy_socks5_username_length;
}
size_t tox_options_get_proxy_socks5_password_length(const Tox_Options *options)
{
    return options->internal_do_not_set_directly_proxy_socks5_password_length;
}
uint16_t tox_options_get_start_port(const Tox_Options *options)
{
    return options->start_port;
}
void tox_options_set_start_port(Tox_Options *options, uint16_t start_port)
{
    options->start_port = start_port;
}
uint16_t tox_options_get_end_port(const Tox_Options *options)
{
    return options->end_port;
}
void tox_options_set_end_port(Tox_Options *options, uint16_t end_port)
{
    options->end_port = end_port;
}
uint16_t tox_options_get_tcp_port(const Tox_Options *options)
{
    return options->tcp_port;
}
void tox_options_set_tcp_port(Tox_Options *options, uint16_t tcp_port)
{
    options->tcp_port = tcp_port;
}
bool tox_options_get_hole_punching_enabled(const Tox_Options *options)
{
    return options->hole_punching_enabled;
}
void tox_options_set_hole_punching_enabled(Tox_Options *options, bool hole_punching_enabled)
{
    options->hole_punching_enabled = hole_punching_enabled;
}
Tox_Savedata_Type tox_options_get_savedata_type(const Tox_Options *options)
{
    return options->savedata_type;
}
void tox_options_set_savedata_type(Tox_Options *options, Tox_Savedata_Type savedata_type)
{
    options->savedata_type = savedata_type;
}
size_t tox_options_get_savedata_length(const Tox_Options *options)
{
    return options->savedata_length;
}
void tox_options_set_savedata_length(Tox_Options *options, size_t savedata_length)
{
    options->savedata_length = savedata_length;
}
tox_log_cb *tox_options_get_log_callback(const Tox_Options *options)
{
    return options->log_callback;
}
void tox_options_set_log_callback(Tox_Options *options, tox_log_cb *log_callback)
{
    options->log_callback = log_callback;
}
void *tox_options_get_log_user_data(const Tox_Options *options)
{
    return options->log_user_data;
}
void tox_options_set_log_user_data(Tox_Options *options, void *log_user_data)
{
    options->log_user_data = log_user_data;
}
bool tox_options_get_local_discovery_enabled(const Tox_Options *options)
{
    return options->local_discovery_enabled;
}
void tox_options_set_local_discovery_enabled(Tox_Options *options, bool local_discovery_enabled)
{
    options->local_discovery_enabled = local_discovery_enabled;
}
bool tox_options_get_dht_announcements_enabled(const Tox_Options *options)
{
    return options->dht_announcements_enabled;
}
void tox_options_set_dht_announcements_enabled(Tox_Options *options, bool dht_announcements_enabled)
{
    options->dht_announcements_enabled = dht_announcements_enabled;
}
bool tox_options_get_experimental_thread_safety(const Tox_Options *options)
{
    return options->experimental_thread_safety;
}
void tox_options_set_experimental_thread_safety(
    Tox_Options *options, bool experimental_thread_safety)
{
    options->experimental_thread_safety = experimental_thread_safety;
}
bool tox_options_get_experimental_groups_persistence(const Tox_Options *options)
{
    return options->experimental_groups_persistence;
}
void tox_options_set_experimental_groups_persistence(
    Tox_Options *options, bool experimental_groups_persistence)
{
    options->experimental_groups_persistence = experimental_groups_persistence;
}
bool tox_options_get_experimental_disable_dns(const Tox_Options *options)
{
    return options->experimental_disable_dns;
}
void tox_options_set_experimental_disable_dns(Tox_Options *options, bool experimental_disable_dns)
{
    options->experimental_disable_dns = experimental_disable_dns;
}
bool tox_options_get_experimental_owned_data(const Tox_Options *options)
{
    return options->experimental_owned_data;
}
void tox_options_set_experimental_owned_data(
    Tox_Options *options, bool experimental_owned_data)
{
    options->experimental_owned_data = experimental_owned_data;
}

static bool options_set_array_experimental_owned_data(bool experimental_owned_data, const uint8_t **options_data, size_t *options_length, uint8_t **options_owned_data, const uint8_t *user_data, size_t user_length)
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

    if (user_data == nullptr) {
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

static bool options_set_array(uint8_t **options_data, size_t *options_length, const uint8_t *user_data, size_t user_length)
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

uint8_t *tox_options_get_proxy_socks5_username(const Tox_Options *options)
{
    return options->internal_do_not_set_directly_proxy_socks5_username;
}

bool tox_options_set_proxy_socks5_username(Tox_Options *options, const uint8_t username[], size_t length)
{
    return options_set_array(&options->internal_do_not_set_directly_proxy_socks5_username,
                             &options->internal_do_not_set_directly_proxy_socks5_username_length,
                             username, length);
}

uint8_t *tox_options_get_proxy_socks5_password(const Tox_Options *options)
{
    return options->internal_do_not_set_directly_proxy_socks5_password;
}

bool tox_options_set_proxy_socks5_password(Tox_Options *options, const uint8_t password[], size_t length)
{
    return options_set_array(&options->internal_do_not_set_directly_proxy_socks5_password,
                             &options->internal_do_not_set_directly_proxy_socks5_password_length,
                             password, length);
}

const uint8_t *tox_options_get_savedata_data(const Tox_Options *options)
{
    return options->savedata_data;
}

bool tox_options_set_savedata_data(Tox_Options *options, const uint8_t *savedata_data, size_t length)
{
    return options_set_array_experimental_owned_data(options->experimental_owned_data,
                                                     &options->savedata_data, &options->savedata_length,
                                                     &options->owned_savedata_data,
                                                     savedata_data, length);
}

void tox_options_default(Tox_Options *options)
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

Tox_Options *tox_options_new(Tox_Err_Options_New *error)
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

void tox_options_free(Tox_Options *options)
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
