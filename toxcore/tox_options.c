/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2021 The TokTok team.
 */
#include "tox.h"

#include <stdlib.h>

#include "ccompat.h"
#include "tox_system.h"

#define SET_ERROR_PARAMETER(param, x) \
    do {                              \
        if (param != nullptr) {       \
            *param = x;               \
        }                             \
    } while (0)

bool tox_options_get_ipv6_enabled(const struct Tox_Options *options)
{
    return options->ipv6_enabled;
}
void tox_options_set_ipv6_enabled(struct Tox_Options *options, bool ipv6_enabled)
{
    options->ipv6_enabled = ipv6_enabled;
}
bool tox_options_get_udp_enabled(const struct Tox_Options *options)
{
    return options->udp_enabled;
}
void tox_options_set_udp_enabled(struct Tox_Options *options, bool udp_enabled)
{
    options->udp_enabled = udp_enabled;
}
Tox_Proxy_Type tox_options_get_proxy_type(const struct Tox_Options *options)
{
    return options->proxy_type;
}
void tox_options_set_proxy_type(struct Tox_Options *options, Tox_Proxy_Type type)
{
    options->proxy_type = type;
}
const char *tox_options_get_proxy_host(const struct Tox_Options *options)
{
    return options->proxy_host;
}
void tox_options_set_proxy_host(struct Tox_Options *options, const char *host)
{
    options->proxy_host = host;
}
uint16_t tox_options_get_proxy_port(const struct Tox_Options *options)
{
    return options->proxy_port;
}
void tox_options_set_proxy_port(struct Tox_Options *options, uint16_t port)
{
    options->proxy_port = port;
}
uint16_t tox_options_get_start_port(const struct Tox_Options *options)
{
    return options->start_port;
}
void tox_options_set_start_port(struct Tox_Options *options, uint16_t start_port)
{
    options->start_port = start_port;
}
uint16_t tox_options_get_end_port(const struct Tox_Options *options)
{
    return options->end_port;
}
void tox_options_set_end_port(struct Tox_Options *options, uint16_t end_port)
{
    options->end_port = end_port;
}
uint16_t tox_options_get_tcp_port(const struct Tox_Options *options)
{
    return options->tcp_port;
}
void tox_options_set_tcp_port(struct Tox_Options *options, uint16_t tcp_port)
{
    options->tcp_port = tcp_port;
}
bool tox_options_get_hole_punching_enabled(const struct Tox_Options *options)
{
    return options->hole_punching_enabled;
}
void tox_options_set_hole_punching_enabled(struct Tox_Options *options, bool hole_punching_enabled)
{
    options->hole_punching_enabled = hole_punching_enabled;
}
Tox_Savedata_Type tox_options_get_savedata_type(const struct Tox_Options *options)
{
    return options->savedata_type;
}
void tox_options_set_savedata_type(struct Tox_Options *options, Tox_Savedata_Type type)
{
    options->savedata_type = type;
}
size_t tox_options_get_savedata_length(const struct Tox_Options *options)
{
    return options->savedata_length;
}
void tox_options_set_savedata_length(struct Tox_Options *options, size_t length)
{
    options->savedata_length = length;
}
tox_log_cb *tox_options_get_log_callback(const struct Tox_Options *options)
{
    return options->log_callback;
}
void tox_options_set_log_callback(struct Tox_Options *options, tox_log_cb *callback)
{
    options->log_callback = callback;
}
void *tox_options_get_log_user_data(const struct Tox_Options *options)
{
    return options->log_user_data;
}
void tox_options_set_log_user_data(struct Tox_Options *options, void *user_data)
{
    options->log_user_data = user_data;
}
bool tox_options_get_local_discovery_enabled(const struct Tox_Options *options)
{
    return options->local_discovery_enabled;
}
void tox_options_set_local_discovery_enabled(struct Tox_Options *options, bool local_discovery_enabled)
{
    options->local_discovery_enabled = local_discovery_enabled;
}
bool tox_options_get_dht_announcements_enabled(const struct Tox_Options *options)
{
    return options->dht_announcements_enabled;
}
void tox_options_set_dht_announcements_enabled(struct Tox_Options *options, bool dht_announcements_enabled)
{
    options->dht_announcements_enabled = dht_announcements_enabled;
}
bool tox_options_get_experimental_thread_safety(const struct Tox_Options *options)
{
    return options->experimental_thread_safety;
}
void tox_options_set_experimental_thread_safety(struct Tox_Options *options, bool experimental_thread_safety)
{
    options->experimental_thread_safety = experimental_thread_safety;
}
const Tox_System *tox_options_get_operating_system(const struct Tox_Options *options)
{
    return options->operating_system;
}
void tox_options_set_operating_system(struct Tox_Options *options, const Tox_System *operating_system)
{
    options->operating_system = operating_system;
}

const uint8_t *tox_options_get_savedata_data(const struct Tox_Options *options)
{
    return options->savedata_data;
}
void tox_options_set_savedata_data(struct Tox_Options *options, const uint8_t *data, size_t length)
{
    options->savedata_data = data;
    options->savedata_length = length;
}

void tox_options_default(struct Tox_Options *options)
{
    if (options != nullptr) {
        const struct Tox_Options default_options = {0};
        *options = default_options;
        tox_options_set_ipv6_enabled(options, true);
        tox_options_set_udp_enabled(options, true);
        tox_options_set_proxy_type(options, TOX_PROXY_TYPE_NONE);
        tox_options_set_hole_punching_enabled(options, true);
        tox_options_set_local_discovery_enabled(options, true);
        tox_options_set_dht_announcements_enabled(options, true);
        tox_options_set_experimental_thread_safety(options, false);
    }
}

struct Tox_Options *tox_options_new(Tox_Err_Options_New *error)
{
    struct Tox_Options *options = (struct Tox_Options *)calloc(1, sizeof(struct Tox_Options));

    if (options != nullptr) {
        tox_options_default(options);
        SET_ERROR_PARAMETER(error, TOX_ERR_OPTIONS_NEW_OK);
        return options;
    }

    SET_ERROR_PARAMETER(error, TOX_ERR_OPTIONS_NEW_MALLOC);
    return nullptr;
}

void tox_options_free(struct Tox_Options *options)
{
    free(options);
}
