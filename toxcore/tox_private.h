/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2020 The TokTok team.
 * Copyright © 2013 Tox project.
 */

#ifndef C_TOXCORE_TOXCORE_TOX_PRIVATE_H
#define C_TOXCORE_TOXCORE_TOX_PRIVATE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Set the callback for the `friend_lossy_packet` event for a specific packet ID.
 * Pass NULL to unset.
 *
 * allowed packet ID range:
 * from `PACKET_ID_RANGE_LOSSY_START` to `PACKET_ID_RANGE_LOSSY_END` (both inclusive)
 */
void tox_callback_friend_lossy_packet_per_pktid(Tox *tox, tox_friend_lossy_packet_cb *callback, uint8_t pktid);

/**
 * Set the callback for the `friend_lossless_packet` event for a specific packet ID.
 * Pass NULL to unset.
 *
 * allowed packet ID range:
 * from `PACKET_ID_RANGE_LOSSLESS_CUSTOM_START` to `PACKET_ID_RANGE_LOSSLESS_CUSTOM_END` (both inclusive)
 * and
 * `PACKET_ID_MSI`
 */
void tox_callback_friend_lossless_packet_per_pktid(Tox *tox, tox_friend_lossless_packet_cb *callback, uint8_t pktid);

void tox_set_av_object(Tox *tox, void *object);
void *tox_get_av_object(const Tox *tox);

struct Tox_Options {
    /**
     * The type of socket to create.
     *
     * If this is set to false, an IPv4 socket is created, which subsequently
     * only allows IPv4 communication.
     * If it is set to true, an IPv6 socket is created, allowing both IPv4 and
     * IPv6 communication.
     */
    bool ipv6_enabled;


    /**
     * Enable the use of UDP communication when available.
     *
     * Setting this to false will force Tox to use TCP only. Communications will
     * need to be relayed through a TCP relay node, potentially slowing them down.
     *
     * If a proxy is enabled, UDP will be disabled if either toxcore or the
     * proxy don't support proxying UDP messages.
     */
    bool udp_enabled;


    /**
     * Enable local network peer discovery.
     *
     * Disabling this will cause Tox to not look for peers on the local network.
     */
    bool local_discovery_enabled;


    /**
     * Pass communications through a proxy.
     */
    Tox_Proxy_Type proxy_type;


    /**
     * The IP address or DNS name of the proxy to be used.
     *
     * If used, this must be non-NULL and be a valid DNS name. The name must not
     * exceed TOX_MAX_HOSTNAME_LENGTH characters, and be in a NUL-terminated C string
     * format (TOX_MAX_HOSTNAME_LENGTH includes the NUL byte).
     *
     * This member is ignored (it can be NULL) if proxy_type is TOX_PROXY_TYPE_NONE.
     */
    const char *proxy_host;


    /**
     * The port to use to connect to the proxy server.
     *
     * Ports must be in the range (1, 65535). The value is ignored if
     * proxy_type is TOX_PROXY_TYPE_NONE.
     */
    uint16_t proxy_port;


    /**
     * The start port of the inclusive port range to attempt to use.
     *
     * If both start_port and end_port are 0, the default port range will be
     * used: `[33445, 33545]`.
     *
     * If either start_port or end_port is 0 while the other is non-zero, the
     * non-zero port will be the only port in the range.
     *
     * Having start_port > end_port will yield the same behavior as if start_port
     * and end_port were swapped.
     */
    uint16_t start_port;


    /**
     * The end port of the inclusive port range to attempt to use.
     */
    uint16_t end_port;


    /**
     * The port to use for the TCP server (relay). If 0, the TCP server is
     * disabled.
     *
     * Enabling it is not required for Tox to function properly.
     *
     * When enabled, your Tox instance can act as a TCP relay for other Tox
     * instance. This leads to increased traffic, thus when writing a client
     * it is recommended to enable TCP server only if the user has an option
     * to disable it.
     */
    uint16_t tcp_port;


    /**
     * Enables or disables UDP hole-punching in toxcore. (Default: enabled).
     */
    bool hole_punching_enabled;


    /**
     * The type of savedata to load from.
     */
    Tox_Savedata_Type savedata_type;


    /**
     * The savedata.
     */
    const uint8_t *savedata_data;


    /**
     * The length of the savedata.
     */
    size_t savedata_length;


    /**
     * Logging callback for the new tox instance.
     */
    tox_log_cb *log_callback;


    /**
     * User data pointer passed to the logging callback.
     */
    void *log_user_data;


    /**
     * These options are experimental, so avoid writing code that depends on
     * them. Options marked "experimental" may change their behaviour or go away
     * entirely in the future, or may be renamed to something non-experimental
     * if they become part of the supported API.
     */
    /**
     * Make public API functions thread-safe using a per-instance lock.
     *
     * Default: false.
     */
    bool experimental_thread_safety;
};

#ifdef __cplusplus
}
#endif

#endif // C_TOXCORE_TOXCORE_TOX_PRIVATE_H
