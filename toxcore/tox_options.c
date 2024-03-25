/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2021 The TokTok team.
 */
#include "tox_options.h"

#include <stdlib.h>

#include "ccompat.h"
#include "tox.h"
#include "tox_system.h"

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
const char *tox_options_get_proxy_host(const Tox_Options *options)
{
    return options->proxy_host;
}
void tox_options_set_proxy_host(Tox_Options *options, const char *proxy_host)
{
    options->proxy_host = proxy_host;
}
uint16_t tox_options_get_proxy_port(const Tox_Options *options)
{
    return options->proxy_port;
}
void tox_options_set_proxy_port(Tox_Options *options, uint16_t proxy_port)
{
    options->proxy_port = proxy_port;
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
void tox_options_set_experimental_thread_safety(Tox_Options *options, bool experimental_thread_safety)
{
    options->experimental_thread_safety = experimental_thread_safety;
}
const Tox_System *tox_options_get_operating_system(const Tox_Options *options)
{
    return options->operating_system;
}
void tox_options_set_operating_system(Tox_Options *options, const Tox_System *operating_system)
{
    options->operating_system = operating_system;
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

const uint8_t *tox_options_get_savedata_data(const Tox_Options *options)
{
    return options->savedata_data;
}
void tox_options_set_savedata_data(Tox_Options *options, const uint8_t *savedata_data, size_t length)
{
    options->savedata_data = savedata_data;
    options->savedata_length = length;
}

void tox_options_default(Tox_Options *options)
{
    if (options != nullptr) {
        const Tox_Options default_options = {0};
        *options = default_options;
        tox_options_set_ipv6_enabled(options, true);
        tox_options_set_udp_enabled(options, true);
        tox_options_set_proxy_type(options, TOX_PROXY_TYPE_NONE);
        tox_options_set_hole_punching_enabled(options, true);
        tox_options_set_local_discovery_enabled(options, true);
        tox_options_set_dht_announcements_enabled(options, true);
        tox_options_set_experimental_thread_safety(options, false);
        tox_options_set_experimental_groups_persistence(options, false);
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
    free(options);
}