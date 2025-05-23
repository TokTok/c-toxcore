/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2025 The TokTok team.
 * Copyright © 2013 Tox project.
 */

/** @file
 * @brief Public core API for Tox clients.
 *
 * Every function that can fail takes a function-specific error code pointer
 * that can be used to diagnose problems with the Tox state or the function
 * arguments. The error code pointer can be NULL, which does not influence the
 * function's behaviour, but can be done if the reason for failure is irrelevant
 * to the client.
 *
 * The exception to this rule are simple allocation functions whose only failure
 * mode is allocation failure. They return NULL in that case, and do not set an
 * error code.
 *
 * Every error code type has an OK value to which functions will set their error
 * code value on success. Clients can keep their error code uninitialised before
 * passing it to a function. The library guarantees that after returning, the
 * value pointed to by the error code pointer has been initialised.
 *
 * Functions with pointer parameters often have a NULL error code, meaning they
 * could not perform any operation, because one of the required parameters was
 * NULL. Some functions operate correctly or are defined as effectless on NULL.
 *
 * Some functions additionally return a value outside their return type domain,
 * or a bool containing true on success and false on failure.
 *
 * All functions that take a Tox instance pointer will cause undefined behaviour
 * when passed a NULL Tox pointer.
 *
 * All integer values are expected in host byte order.
 *
 * Functions with parameters with enum types cause unspecified behaviour if the
 * enumeration value is outside the valid range of the type. If possible, the
 * function will try to use a sane default, but there will be no error code,
 * and one possible action for the function to take is to have no effect.
 *
 * Integer constants and the memory layout of publicly exposed structs are not
 * part of the ABI.
 *
 * @section events Events and callbacks
 *
 * Events are handled by callbacks. One callback can be registered per event.
 * All events have a callback function type named `tox_{event}_cb` and a
 * function to register it named `tox_callback_{event}`. Passing a NULL
 * callback will result in no callback being registered for that event. Only
 * one callback per event can be registered, so if a client needs multiple
 * event listeners, it needs to implement the dispatch functionality itself.
 *
 * The last argument to a callback is the user data pointer. It is passed from
 * tox_iterate to each callback in sequence. The user data pointer is never
 * stored or dereferenced by any library code, so can be any pointer, including
 * NULL.
 *
 * @section threading Threading implications
 *
 * It is possible to run multiple concurrent threads with a Tox instance for
 * each thread. It is also possible to run all Tox instances in the same thread.
 * A common way to run Tox (multiple or single instance) is to have one thread
 * running a simple tox_iterate loop, sleeping for tox_iteration_interval
 * milliseconds on each iteration.
 *
 * If you want to access a single Tox instance from multiple threads, access
 * to the instance must be synchronised. While multiple threads can concurrently
 * access multiple different Tox instances, no more than one API function can
 * operate on a single instance at any given time.
 *
 * Functions that write to variable length byte arrays will always have a size
 * function associated with them. The result of this size function is only valid
 * until another mutating function (one that takes a pointer to non-const Tox)
 * is called. Thus, clients must ensure that no other thread calls a mutating
 * function between the call to the size function and the call to the retrieval
 * function.
 *
 * E.g. to get the current nickname, one would write
 *
 * @code
 * size_t length = tox_self_get_name_size(tox);
 * uint8_t *name = malloc(length);
 * if (!name) abort();
 * tox_self_get_name(tox, name);
 * @endcode
 *
 * If any other thread calls tox_self_set_name while this thread is allocating
 * memory, the length may have become invalid, and the call to
 * tox_self_get_name may cause undefined behaviour.
 *
 * @section deprecations
 *
 * Some functions and types are deprecated. We recommend compiling with
 * `-DTOX_HIDE_DEPRECATED` to hide them. They will be removed in the next major
 * version of Tox (and since we're in major version 0, that means the next
 * minor version).
 */
#ifndef C_TOXCORE_TOXCORE_TOX_H
#define C_TOXCORE_TOXCORE_TOX_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "tox_options.h"  // IWYU pragma: export

#ifdef __cplusplus
extern "C" {
#endif

/** @{ @namespace tox */

/**
 * @brief The Tox instance type.
 *
 * All the state associated with a connection is held
 * within the instance. Multiple instances can exist and operate concurrently.
 * The maximum number of Tox instances that can exist on a single network
 * device is limited. Note that this is not just a per-process limit, since the
 * limiting factor is the number of usable ports on a device.
 */
typedef struct Tox Tox;

/** @{
 * @name API version
 */

/**
 * @brief The major version number.
 *
 * Incremented when the API or ABI changes in an incompatible way.
 *
 * The function variants of these constants return the version number of the
 * library. They can be used to display the Tox library version or to check
 * whether the client is compatible with the dynamically linked version of Tox.
 */
#define TOX_VERSION_MAJOR              0

uint32_t tox_version_major(void);

/**
 * @brief The minor version number.
 *
 * Incremented when functionality is added without  breaking the API or ABI.
 * Set to 0 when the major version number is incremented.
 */
#define TOX_VERSION_MINOR              2

uint32_t tox_version_minor(void);

/**
 * @brief The patch or revision number.
 *
 * Incremented when bugfixes are applied without changing any functionality or
 * API or ABI.
 */
#define TOX_VERSION_PATCH              21

uint32_t tox_version_patch(void);

//!TOKSTYLE-
/**
 * @brief A macro to check at preprocessing time whether the client code is
 *   compatible with the installed version of Tox.
 *
 * Leading zeros in the version number are  ignored. E.g. 0.1.5 is to 0.1.4
 * what 1.5 is to 1.4, that is: it can add new features, but can't break the
 * API.
 */
#define TOX_VERSION_IS_API_COMPATIBLE(MAJOR, MINOR, PATCH)              \
  ((TOX_VERSION_MAJOR > 0 && TOX_VERSION_MAJOR == MAJOR) && (           \
    /* 1.x.x, 2.x.x, etc. with matching major version. */               \
    TOX_VERSION_MINOR > MINOR ||                                        \
    (TOX_VERSION_MINOR == MINOR && TOX_VERSION_PATCH >= PATCH)          \
  )) || ((TOX_VERSION_MAJOR == 0 && MAJOR == 0) && (                    \
    /* 0.x.x makes minor behave like major above. */                    \
    ((TOX_VERSION_MINOR > 0 && TOX_VERSION_MINOR == MINOR) && (         \
      TOX_VERSION_PATCH >= PATCH                                        \
    )) || ((TOX_VERSION_MINOR == 0 && MINOR == 0) && (                  \
      /* 0.0.x and 0.0.y are only compatible if x == y. */              \
      TOX_VERSION_PATCH == PATCH                                        \
    ))                                                                  \
  ))
//!TOKSTYLE+

/**
 * @brief Return whether the compiled library version is compatible with the
 *   passed version numbers.
 */
bool tox_version_is_compatible(uint32_t major, uint32_t minor, uint32_t patch);

/**
 * @brief A convenience macro to call tox_version_is_compatible with the
 *   currently compiling API version.
 */
#define TOX_VERSION_IS_ABI_COMPATIBLE()                         \
  tox_version_is_compatible(TOX_VERSION_MAJOR, TOX_VERSION_MINOR, TOX_VERSION_PATCH)

/** @} */

/** @{
 * @name Numeric constants
 *
 * The values of these are not part of the ABI. Prefer to use the function
 * versions of them for code that should remain compatible with future versions
 * of the Tox library.
 */

/**
 * @brief The size of a Tox Public Key in bytes.
 */
#define TOX_PUBLIC_KEY_SIZE            32

uint32_t tox_public_key_size(void);

/**
 * @brief The size of a Tox Secret Key in bytes.
 */
#define TOX_SECRET_KEY_SIZE            32

uint32_t tox_secret_key_size(void);

/**
 * @brief The size of a Tox Conference unique id in bytes.
 *
 * @deprecated Use TOX_CONFERENCE_ID_SIZE instead.
 */
#define TOX_CONFERENCE_UID_SIZE        32

uint32_t tox_conference_uid_size(void);

/**
 * @brief The size of a Tox Conference unique id in bytes.
 */
#define TOX_CONFERENCE_ID_SIZE         32

uint32_t tox_conference_id_size(void);

/**
 * @brief The size of the nospam in bytes when written in a Tox address.
 */
#define TOX_NOSPAM_SIZE                (sizeof(uint32_t))

uint32_t tox_nospam_size(void);

/**
 * @brief The size of a Tox address in bytes.
 *
 * Tox addresses are in the format
 * `[Public Key (TOX_PUBLIC_KEY_SIZE bytes)][nospam (4 bytes)][checksum (2 bytes)]`.
 *
 * The checksum is computed over the Public Key and the nospam value. The first
 * byte is an XOR of all the even bytes (0, 2, 4, ...), the second byte is an
 * XOR of all the odd bytes (1, 3, 5, ...) of the Public Key and nospam.
 */
#define TOX_ADDRESS_SIZE               (TOX_PUBLIC_KEY_SIZE + TOX_NOSPAM_SIZE + sizeof(uint16_t))

uint32_t tox_address_size(void);

/**
 * @brief Maximum length of a nickname in bytes.
 *
 * @deprecated The macro will be removed in 0.3.0. Use the function instead.
 */
#define TOX_MAX_NAME_LENGTH            128

uint32_t tox_max_name_length(void);

/**
 * @brief Maximum length of a status message in bytes.
 *
 * @deprecated The macro will be removed in 0.3.0. Use the function instead.
 */
#define TOX_MAX_STATUS_MESSAGE_LENGTH  1007

uint32_t tox_max_status_message_length(void);

/**
 * @brief Maximum length of a friend request message in bytes.
 *
 * @deprecated The macro will be removed in 0.3.0. Use the function instead.
 */
#define TOX_MAX_FRIEND_REQUEST_LENGTH  921

uint32_t tox_max_friend_request_length(void);

/**
 * @brief Maximum length of a single message after which it should be split.
 *
 * @deprecated The macro will be removed in 0.3.0. Use the function instead.
 */
#define TOX_MAX_MESSAGE_LENGTH         1372

uint32_t tox_max_message_length(void);

/**
 * @brief Maximum size of custom packets. TODO(iphydf): should be LENGTH?
 *
 * @deprecated The macro will be removed in 0.3.0. Use the function instead.
 */
#define TOX_MAX_CUSTOM_PACKET_SIZE     1373

uint32_t tox_max_custom_packet_size(void);

/**
 * @brief The number of bytes in a hash generated by tox_hash.
 */
#define TOX_HASH_LENGTH                32

uint32_t tox_hash_length(void);

/**
 * @brief The number of bytes in a file id.
 */
#define TOX_FILE_ID_LENGTH             32

uint32_t tox_file_id_length(void);

/**
 * @brief Maximum file name length for file transfers.
 *
 * @deprecated The macro will be removed in 0.3.0. Use the function instead.
 */
#define TOX_MAX_FILENAME_LENGTH        255

uint32_t tox_max_filename_length(void);

/**
 * @brief Maximum length of a hostname, e.g. proxy or bootstrap node names.
 *
 * This length does not include the NUL byte. Hostnames are NUL-terminated C
 * strings, so they are 255 characters plus one NUL byte.
 *
 * @deprecated The macro will be removed in 0.3.0. Use the function instead.
 */
#define TOX_MAX_HOSTNAME_LENGTH        255

uint32_t tox_max_hostname_length(void);

/** @} */

/** @{
 * @name Global enumerations
 */

/**
 * @brief Represents the possible statuses a client can have.
 */
typedef enum Tox_User_Status {

    /**
     * User is online and available.
     */
    TOX_USER_STATUS_NONE,

    /**
     * User is away. Clients can set this e.g. after a user defined
     * inactivity time.
     */
    TOX_USER_STATUS_AWAY,

    /**
     * User is busy. Signals to other clients that this client does not
     * currently wish to communicate.
     */
    TOX_USER_STATUS_BUSY,

} Tox_User_Status;

const char *tox_user_status_to_string(Tox_User_Status value);

/**
 * @brief Represents message types for tox_friend_send_message and conference
 *   messages.
 */
typedef enum Tox_Message_Type {

    /**
     * Normal text message. Similar to PRIVMSG on IRC.
     */
    TOX_MESSAGE_TYPE_NORMAL,

    /**
     * A message describing an user action. This is similar to /me (CTCP ACTION)
     * on IRC.
     */
    TOX_MESSAGE_TYPE_ACTION,

} Tox_Message_Type;

const char *tox_message_type_to_string(Tox_Message_Type value);

/** @} */

/** @{
 * @name Creation and destruction
 */

typedef enum Tox_Err_New {

    /**
     * The function returned successfully.
     */
    TOX_ERR_NEW_OK,

    /**
     * One of the arguments to the function was NULL when it was not expected.
     */
    TOX_ERR_NEW_NULL,

    /**
     * The function was unable to allocate enough memory to store the
     * internal structures for the Tox object.
     */
    TOX_ERR_NEW_MALLOC,

    /**
     * The function was unable to bind to a port. This may mean that all ports
     * have already been bound, e.g. by other Tox instances, or it may mean
     * a permission error. You may be able to gather more information from
     * errno.
     */
    TOX_ERR_NEW_PORT_ALLOC,

    /**
     * proxy_type was invalid.
     */
    TOX_ERR_NEW_PROXY_BAD_TYPE,

    /**
     * proxy_type was valid but the proxy_host passed had an invalid format
     * or was NULL.
     */
    TOX_ERR_NEW_PROXY_BAD_HOST,

    /**
     * proxy_type was valid, but the proxy_port was invalid.
     */
    TOX_ERR_NEW_PROXY_BAD_PORT,

    /**
     * The proxy address passed could not be resolved.
     */
    TOX_ERR_NEW_PROXY_NOT_FOUND,

    /**
     * The byte array to be loaded contained an encrypted save.
     */
    TOX_ERR_NEW_LOAD_ENCRYPTED,

    /**
     * The data format was invalid. This can happen when loading data that was
     * saved by an older version of Tox, or when the data has been corrupted.
     * When loading from badly formatted data, some data may have been loaded,
     * and the rest is discarded. Passing an invalid length parameter also
     * causes this error.
     */
    TOX_ERR_NEW_LOAD_BAD_FORMAT,

} Tox_Err_New;

const char *tox_err_new_to_string(Tox_Err_New value);

/**
 * @brief Creates and initialises a new Tox instance with the options passed.
 *
 * This function will bring the instance into a valid state. Running the event
 * loop with a new instance will operate correctly.
 *
 * @param options An options object as described above. If this parameter is
 *   NULL, the default options are used.
 *
 * @see tox_iterate for the event loop.
 *
 * @return A new Tox instance pointer on success or NULL on failure.
 */
Tox *tox_new(const Tox_Options *options, Tox_Err_New *error);

/**
 * @brief Releases all resources associated with the Tox instance and
 *   disconnects from the network.
 *
 * After calling this function, the Tox pointer becomes invalid. No other
 * functions can be called, and the pointer value can no longer be read.
 */
void tox_kill(Tox *tox);

/**
 * @brief Calculates the number of bytes required to store the Tox instance with
 *   tox_get_savedata.
 *
 * This function cannot fail. The result is always greater than 0.
 *
 * @see threading for concurrency implications.
 */
size_t tox_get_savedata_size(const Tox *tox);

/**
 * @brief Store all information associated with the Tox instance to a byte
 *   array.
 *
 * @param savedata A memory region large enough to store the Tox instance
 *   data. Call tox_get_savedata_size to find the number of bytes required. If
 *   this parameter is NULL, this function has no effect.
 */
void tox_get_savedata(const Tox *tox, uint8_t savedata[]);

/** @} */

/** @{
 * @name Connection lifecycle and event loop
 */

typedef enum Tox_Err_Bootstrap {

    /**
     * The function returned successfully.
     */
    TOX_ERR_BOOTSTRAP_OK,

    /**
     * One of the arguments to the function was NULL when it was not expected.
     */
    TOX_ERR_BOOTSTRAP_NULL,

    /**
     * The hostname could not be resolved to an IP address, the IP address
     * passed was invalid, or the function failed to send the initial request
     * packet to the bootstrap node or TCP relay.
     */
    TOX_ERR_BOOTSTRAP_BAD_HOST,

    /**
     * The port passed was invalid. The valid port range is (1, 65535).
     */
    TOX_ERR_BOOTSTRAP_BAD_PORT,

} Tox_Err_Bootstrap;

const char *tox_err_bootstrap_to_string(Tox_Err_Bootstrap value);

/**
 * @brief Sends a "nodes request" to the given bootstrap node with IP, port,
 *   and public key to setup connections.
 *
 * This function will attempt to connect to the node using UDP. You must use
 * this function even if Tox_Options.udp_enabled was set to false.
 *
 * @param host The hostname or IP address (IPv4 or IPv6) of the node. Must be
 *   at most TOX_MAX_HOSTNAME_LENGTH chars, including the NUL byte.
 * @param port The port on the host on which the bootstrap Tox instance is
 *   listening.
 * @param public_key The long term public key of the bootstrap node
 *   (TOX_PUBLIC_KEY_SIZE bytes).
 * @return true on success.
 */
bool tox_bootstrap(Tox *tox, const char *host, uint16_t port, const uint8_t public_key[TOX_PUBLIC_KEY_SIZE], Tox_Err_Bootstrap *error);

/**
 * @brief Adds additional host:port pair as TCP relay.
 *
 * This function can be used to initiate TCP connections to different ports on
 * the same bootstrap node, or to add TCP relays without using them as
 * bootstrap nodes.
 *
 * @param host The hostname or IP address (IPv4 or IPv6) of the TCP relay.
 *   Must be at most TOX_MAX_HOSTNAME_LENGTH chars, including the NUL byte.
 * @param port The port on the host on which the TCP relay is listening.
 * @param public_key The long term public key of the TCP relay
 *   (TOX_PUBLIC_KEY_SIZE bytes).
 * @return true on success.
 */
bool tox_add_tcp_relay(Tox *tox, const char *host, uint16_t port, const uint8_t public_key[TOX_PUBLIC_KEY_SIZE], Tox_Err_Bootstrap *error);

/**
 * @brief Protocols that can be used to connect to the network or friends.
 */
typedef enum Tox_Connection {

    /**
     * @brief There is no connection.
     *
     * This instance, or the friend the state change is about, is now offline.
     */
    TOX_CONNECTION_NONE,

    /**
     * @brief A TCP connection has been established.
     *
     * For the own instance, this means it is connected through a TCP relay,
     * only. For a friend, this means that the connection to that particular
     * friend goes through a TCP relay.
     */
    TOX_CONNECTION_TCP,

    /**
     * @brief A UDP connection has been established.
     *
     * For the own instance, this means it is able to send UDP packets to DHT
     * nodes, but may still be connected to a TCP relay. For a friend, this
     * means that the connection to that particular friend was built using
     * direct UDP packets.
     */
    TOX_CONNECTION_UDP,

} Tox_Connection;

const char *tox_connection_to_string(Tox_Connection value);

/**
 * @brief Return whether we are connected to the DHT.
 *
 * The return value is equal to the last value received through the
 * `self_connection_status` callback.
 *
 * @deprecated This getter is deprecated. Use the event and store the status
 *   in the client state.
 */
Tox_Connection tox_self_get_connection_status(const Tox *tox);

/**
 * @param connection_status Whether we are connected to the DHT.
 */
typedef void tox_self_connection_status_cb(Tox *tox, Tox_Connection connection_status, void *user_data);

/**
 * @brief Set the callback for the `self_connection_status` event.
 *
 * Pass NULL to unset.
 *
 * This event is triggered whenever there is a change in the DHT connection
 * state. When disconnected, a client may choose to call tox_bootstrap again, to
 * reconnect to the DHT. Note that this state may frequently change for short
 * amounts of time. Clients should therefore not immediately bootstrap on
 * receiving a disconnect.
 *
 * TODO(iphydf): how long should a client wait before bootstrapping again?
 */
void tox_callback_self_connection_status(Tox *tox, tox_self_connection_status_cb *callback);

/**
 * @brief Return the time in milliseconds before `tox_iterate()` should be
 *   called again for optimal performance.
 */
uint32_t tox_iteration_interval(const Tox *tox);

/**
 * @brief The main loop that needs to be run in intervals of
 *   `tox_iteration_interval()` milliseconds.
 * @param user_data Any pointer a client wishes the Tox instance to pass into
 *   the event callbacks, including NULL.
 */
void tox_iterate(Tox *tox, void *user_data);

/** @} */

/** @{
 * @name Internal client information (Tox address/id)
 */

/**
 * @brief Writes the Tox friend address of the client to a byte array.
 *
 * The address is not in human-readable format. If a client wants to display
 * the address, formatting is required.
 *
 * @param address A memory region of at least TOX_ADDRESS_SIZE bytes. If this
 *   parameter is NULL, this function has no effect.
 * @see TOX_ADDRESS_SIZE for the address format.
 */
void tox_self_get_address(const Tox *tox, uint8_t address[TOX_ADDRESS_SIZE]);

/**
 * @brief Set the 4-byte nospam part of the address.
 *
 * This value is expected in host byte order. I.e. 0x12345678 will form the
 * bytes `[12, 34, 56, 78]` in the nospam part of the Tox friend address.
 *
 * @param nospam Any 32 bit unsigned integer.
 */
void tox_self_set_nospam(Tox *tox, uint32_t nospam);

/**
 * @brief Get the 4-byte nospam part of the address.
 *
 * This value is returned in host byte order.
 */
uint32_t tox_self_get_nospam(const Tox *tox);

/**
 * @brief Copy the Tox Public Key (long term) from the Tox object.
 *
 * @param public_key A memory region of at least TOX_PUBLIC_KEY_SIZE bytes. If
 *   this parameter is NULL, this function has no effect.
 */
void tox_self_get_public_key(const Tox *tox, uint8_t public_key[TOX_PUBLIC_KEY_SIZE]);

/**
 * @brief Copy the Tox Secret Key from the Tox object.
 *
 * @param secret_key A memory region of at least TOX_SECRET_KEY_SIZE bytes. If
 *   this parameter is NULL, this function has no effect.
 */
void tox_self_get_secret_key(const Tox *tox, uint8_t secret_key[TOX_SECRET_KEY_SIZE]);

/** @} */

/** @{
 * @name User-visible client information (nickname/status)
 */

/**
 * @brief Common error codes for all functions that set a piece of user-visible
 *   client information.
 */
typedef enum Tox_Err_Set_Info {

    /**
     * The function returned successfully.
     */
    TOX_ERR_SET_INFO_OK,

    /**
     * One of the arguments to the function was NULL when it was not expected.
     */
    TOX_ERR_SET_INFO_NULL,

    /**
     * Information length exceeded maximum permissible size.
     */
    TOX_ERR_SET_INFO_TOO_LONG,

} Tox_Err_Set_Info;

const char *tox_err_set_info_to_string(Tox_Err_Set_Info value);

/**
 * @brief Set the nickname for the Tox client.
 *
 * Nickname length cannot exceed TOX_MAX_NAME_LENGTH. If length is 0, the name
 * parameter is ignored (it can be NULL), and the nickname is set back to empty.
 *
 * @param name A byte array containing the new nickname.
 * @param length The size of the name byte array.
 *
 * @return true on success.
 */
bool tox_self_set_name(Tox *tox, const uint8_t name[], size_t length, Tox_Err_Set_Info *error);

/**
 * @brief Return the length of the current nickname as passed to
 *   tox_self_set_name.
 *
 * If no nickname was set before calling this function, the name is empty,
 * and this function returns 0.
 *
 * @see threading for concurrency implications.
 */
size_t tox_self_get_name_size(const Tox *tox);

/**
 * @brief Write the nickname set by tox_self_set_name to a byte array.
 *
 * If no nickname was set before calling this function, the name is empty,
 * and this function has no effect.
 *
 * Call tox_self_get_name_size to find out how much memory to allocate for
 * the result.
 *
 * @param name A valid memory location large enough to hold the nickname.
 *   If this parameter is NULL, the function has no effect.
 */
void tox_self_get_name(const Tox *tox, uint8_t name[]);

/**
 * @brief Set the client's status message.
 *
 * Status message length cannot exceed TOX_MAX_STATUS_MESSAGE_LENGTH. If
 * length is 0, the status parameter is ignored (it can be NULL), and the
 * user status is set back to empty.
 */
bool tox_self_set_status_message(
    Tox *tox, const uint8_t status_message[], size_t length, Tox_Err_Set_Info *error);

/**
 * @brief Return the length of the current status message as passed to
 *   tox_self_set_status_message.
 *
 * If no status message was set before calling this function, the status
 * is empty, and this function returns 0.
 *
 * @see threading for concurrency implications.
 */
size_t tox_self_get_status_message_size(const Tox *tox);

/**
 * @brief Write the status message set by tox_self_set_status_message to a byte
 *   array.
 *
 * If no status message was set before calling this function, the status is
 * empty, and this function has no effect.
 *
 * Call tox_self_get_status_message_size to find out how much memory to allocate
 * for the result.
 *
 * @param status_message A valid memory location large enough to hold the
 *   status message. If this parameter is NULL, the function has no effect.
 */
void tox_self_get_status_message(const Tox *tox, uint8_t status_message[]);

/**
 * @brief Set the client's user status.
 *
 * @param status One of the user statuses listed in the enumeration above.
 */
void tox_self_set_status(Tox *tox, Tox_User_Status status);

/**
 * @brief Returns the client's user status.
 */
Tox_User_Status tox_self_get_status(const Tox *tox);

/** @} */

/** @{
 * @name Friend list management
 */

typedef uint32_t Tox_Friend_Number;

typedef enum Tox_Err_Friend_Add {

    /**
     * The function returned successfully.
     */
    TOX_ERR_FRIEND_ADD_OK,

    /**
     * One of the arguments to the function was NULL when it was not expected.
     */
    TOX_ERR_FRIEND_ADD_NULL,

    /**
     * The length of the friend request message exceeded
     * TOX_MAX_FRIEND_REQUEST_LENGTH.
     */
    TOX_ERR_FRIEND_ADD_TOO_LONG,

    /**
     * The friend request message was empty. This, and the TOO_LONG code will
     * never be returned from tox_friend_add_norequest.
     */
    TOX_ERR_FRIEND_ADD_NO_MESSAGE,

    /**
     * The friend address belongs to the sending client.
     */
    TOX_ERR_FRIEND_ADD_OWN_KEY,

    /**
     * A friend request has already been sent, or the address belongs to a
     * friend that is already on the friend list.
     */
    TOX_ERR_FRIEND_ADD_ALREADY_SENT,

    /**
     * The friend address checksum failed.
     */
    TOX_ERR_FRIEND_ADD_BAD_CHECKSUM,

    /**
     * The friend was already there, but the nospam value was different.
     */
    TOX_ERR_FRIEND_ADD_SET_NEW_NOSPAM,

    /**
     * A memory allocation failed when trying to increase the friend list size.
     */
    TOX_ERR_FRIEND_ADD_MALLOC,

} Tox_Err_Friend_Add;

const char *tox_err_friend_add_to_string(Tox_Err_Friend_Add value);

/**
 * @brief Add a friend to the friend list and send a friend request.
 *
 * A friend request message must be at least 1 byte long and at most
 * TOX_MAX_FRIEND_REQUEST_LENGTH.
 *
 * Friend numbers are unique identifiers used in all functions that operate on
 * friends. Once added, a friend number is stable for the lifetime of the Tox
 * object. After saving the state and reloading it, the friend numbers may not
 * be the same as before. Deleting a friend creates a gap in the friend number
 * set, which is filled by the next adding of a friend. Any pattern in friend
 * numbers should not be relied on.
 *
 * If more than INT32_MAX friends are added, this function causes undefined
 * behaviour.
 *
 * @param address The address of the friend (returned by tox_self_get_address of
 *   the friend you wish to add) it must be TOX_ADDRESS_SIZE bytes.
 * @param message The message that will be sent along with the friend request.
 * @param length The length of the data byte array.
 *
 * @return the friend number on success, an unspecified value on failure.
 */
Tox_Friend_Number tox_friend_add(
    Tox *tox, const uint8_t address[TOX_ADDRESS_SIZE],
    const uint8_t message[], size_t length,
    Tox_Err_Friend_Add *error);

/**
 * @brief Add a friend without sending a friend request.
 *
 * This function is used to add a friend in response to a friend request. If the
 * client receives a friend request, it can be reasonably sure that the other
 * client added this client as a friend, eliminating the need for a friend
 * request.
 *
 * This function is also useful in a situation where both instances are
 * controlled by the same entity, so that this entity can perform the mutual
 * friend adding. In this case, there is no need for a friend request, either.
 *
 * @param public_key A byte array of length TOX_PUBLIC_KEY_SIZE containing the
 *   Public Key (not the Address) of the friend to add.
 *
 * @return the friend number on success, an unspecified value on failure.
 * @see tox_friend_add for a more detailed description of friend numbers.
 */
Tox_Friend_Number tox_friend_add_norequest(
    Tox *tox, const uint8_t public_key[TOX_PUBLIC_KEY_SIZE], Tox_Err_Friend_Add *error);

typedef enum Tox_Err_Friend_Delete {

    /**
     * The function returned successfully.
     */
    TOX_ERR_FRIEND_DELETE_OK,

    /**
     * There was no friend with the given friend number. No friends were
     * deleted.
     */
    TOX_ERR_FRIEND_DELETE_FRIEND_NOT_FOUND,

} Tox_Err_Friend_Delete;

const char *tox_err_friend_delete_to_string(Tox_Err_Friend_Delete value);

/**
 * @brief Remove a friend from the friend list.
 *
 * This does not notify the friend of their deletion. After calling this
 * function, this client will appear offline to the friend and no communication
 * can occur between the two.
 *
 * @param friend_number Friend number for the friend to be deleted.
 *
 * @return true on success.
 */
bool tox_friend_delete(Tox *tox, Tox_Friend_Number friend_number, Tox_Err_Friend_Delete *error);

/** @} */

/** @{
 * @name Friend list queries
 */

typedef enum Tox_Err_Friend_By_Public_Key {

    /**
     * The function returned successfully.
     */
    TOX_ERR_FRIEND_BY_PUBLIC_KEY_OK,

    /**
     * One of the arguments to the function was NULL when it was not expected.
     */
    TOX_ERR_FRIEND_BY_PUBLIC_KEY_NULL,

    /**
     * No friend with the given Public Key exists on the friend list.
     */
    TOX_ERR_FRIEND_BY_PUBLIC_KEY_NOT_FOUND,

} Tox_Err_Friend_By_Public_Key;

const char *tox_err_friend_by_public_key_to_string(Tox_Err_Friend_By_Public_Key value);

/**
 * @brief Return the friend number associated with that Public Key.
 *
 * @param public_key A byte array containing the Public Key.
 *
 * @return the friend number on success, an unspecified value on failure.
 */
Tox_Friend_Number tox_friend_by_public_key(const Tox *tox, const uint8_t public_key[TOX_PUBLIC_KEY_SIZE], Tox_Err_Friend_By_Public_Key *error);

/**
 * @brief Checks if a friend with the given friend number exists and returns
 *   true if it does.
 */
bool tox_friend_exists(const Tox *tox, Tox_Friend_Number friend_number);

/**
 * @brief Return the number of friends on the friend list.
 *
 * This function can be used to determine how much memory to allocate for
 * tox_self_get_friend_list.
 */
size_t tox_self_get_friend_list_size(const Tox *tox);

/**
 * @brief Copy a list of valid friend numbers into an array.
 *
 * Call tox_self_get_friend_list_size to determine the number of elements to
 * allocate.
 *
 * @param friend_list A memory region with enough space to hold the friend
 *   list. If this parameter is NULL, this function has no effect.
 */
void tox_self_get_friend_list(const Tox *tox, Tox_Friend_Number friend_list[]);

typedef enum Tox_Err_Friend_Get_Public_Key {

    /**
     * The function returned successfully.
     */
    TOX_ERR_FRIEND_GET_PUBLIC_KEY_OK,

    /**
     * No friend with the given number exists on the friend list.
     */
    TOX_ERR_FRIEND_GET_PUBLIC_KEY_FRIEND_NOT_FOUND,

} Tox_Err_Friend_Get_Public_Key;

const char *tox_err_friend_get_public_key_to_string(Tox_Err_Friend_Get_Public_Key value);

/**
 * @brief Copies the Public Key associated with a given friend number to a byte
 *   array.
 *
 * @param friend_number The friend number you want the Public Key of.
 * @param public_key A memory region of at least TOX_PUBLIC_KEY_SIZE bytes. If
 *   this parameter is NULL, this function has no effect.
 *
 * @return true on success.
 */
bool tox_friend_get_public_key(
    const Tox *tox, Tox_Friend_Number friend_number, uint8_t public_key[TOX_PUBLIC_KEY_SIZE],
    Tox_Err_Friend_Get_Public_Key *error);

typedef enum Tox_Err_Friend_Get_Last_Online {

    /**
     * The function returned successfully.
     */
    TOX_ERR_FRIEND_GET_LAST_ONLINE_OK,

    /**
     * No friend with the given number exists on the friend list.
     */
    TOX_ERR_FRIEND_GET_LAST_ONLINE_FRIEND_NOT_FOUND,

} Tox_Err_Friend_Get_Last_Online;

const char *tox_err_friend_get_last_online_to_string(Tox_Err_Friend_Get_Last_Online value);

/**
 * @brief Return a unix-time timestamp of the last time the friend associated
 *   with a given friend number was seen online.
 *
 * This function will return UINT64_MAX on error.
 *
 * @param friend_number The friend number you want to query.
 */
uint64_t tox_friend_get_last_online(
    const Tox *tox, Tox_Friend_Number friend_number, Tox_Err_Friend_Get_Last_Online *error);

/** @} */

/** @{
 * @name Friend-specific state queries (can also be received through callbacks)
 */

/**
 * @brief Common error codes for friend state query functions.
 */
typedef enum Tox_Err_Friend_Query {

    /**
     * The function returned successfully.
     */
    TOX_ERR_FRIEND_QUERY_OK,

    /**
     * The pointer parameter for storing the query result (name, message) was
     * NULL. Unlike the `_self_` variants of these functions, which have no
     * effect when a parameter is NULL, these functions return an error in that
     * case.
     */
    TOX_ERR_FRIEND_QUERY_NULL,

    /**
     * The friend_number did not designate a valid friend.
     */
    TOX_ERR_FRIEND_QUERY_FRIEND_NOT_FOUND,

} Tox_Err_Friend_Query;

const char *tox_err_friend_query_to_string(Tox_Err_Friend_Query value);

/**
 * @brief Return the length of the friend's name.
 *
 * If the friend number is invalid, the return value is unspecified.
 *
 * The return value is equal to the `length` argument received by the last
 * `friend_name` callback.
 */
size_t tox_friend_get_name_size(
    const Tox *tox, Tox_Friend_Number friend_number, Tox_Err_Friend_Query *error);

/**
 * @brief Write the name of the friend designated by the given friend number to
 *   a byte array.
 *
 * Call tox_friend_get_name_size to determine the allocation size for the `name`
 * parameter.
 *
 * The data written to `name` is equal to the data received by the last
 * `friend_name` callback.
 *
 * @param name A valid memory region large enough to store the friend's name.
 *
 * @return true on success.
 */
bool tox_friend_get_name(
    const Tox *tox, Tox_Friend_Number friend_number, uint8_t name[], Tox_Err_Friend_Query *error);

/**
 * @param friend_number The friend number of the friend whose name changed.
 * @param name A byte array containing the same data as
 *   tox_friend_get_name would write to its `name` parameter.
 * @param length A value equal to the return value of
 *   tox_friend_get_name_size.
 */
typedef void tox_friend_name_cb(
    Tox *tox, Tox_Friend_Number friend_number,
    const uint8_t name[], size_t length, void *user_data);

/**
 * @brief Set the callback for the `friend_name` event.
 *
 * Pass NULL to unset.
 *
 * This event is triggered when a friend changes their name.
 */
void tox_callback_friend_name(Tox *tox, tox_friend_name_cb *callback);

/**
 * @brief Return the length of the friend's status message.
 *
 * If the friend number is invalid, the return value is SIZE_MAX.
 */
size_t tox_friend_get_status_message_size(
    const Tox *tox, Tox_Friend_Number friend_number, Tox_Err_Friend_Query *error);

/**
 * @brief Write the status message of the friend designated by the given friend
 *   number to a byte array.
 *
 * Call tox_friend_get_status_message_size to determine the allocation size for
 * the `status_message` parameter.
 *
 * The data written to `status_message` is equal to the data received by the
 * last `friend_status_message` callback.
 *
 * @param status_message A valid memory region large enough to store the
 *   friend's status message.
 */
bool tox_friend_get_status_message(
    const Tox *tox, Tox_Friend_Number friend_number, uint8_t status_message[],
    Tox_Err_Friend_Query *error);

/**
 * @param friend_number The friend number of the friend whose status message
 *   changed.
 * @param message A byte array containing the same data as
 *   tox_friend_get_status_message would write to its `status_message`
 *   parameter.
 * @param length A value equal to the return value of
 *   tox_friend_get_status_message_size.
 */
typedef void tox_friend_status_message_cb(
    Tox *tox, Tox_Friend_Number friend_number,
    const uint8_t message[], size_t length, void *user_data);

/**
 * @brief Set the callback for the `friend_status_message` event.
 *
 * Pass NULL to unset.
 *
 * This event is triggered when a friend changes their status message.
 */
void tox_callback_friend_status_message(Tox *tox, tox_friend_status_message_cb *callback);

/**
 * @brief Return the friend's user status (away/busy/...).
 *
 * If the friend number is invalid, the return value is unspecified.
 *
 * The status returned is equal to the last status received through the
 * `friend_status` callback.
 *
 * @deprecated This getter is deprecated. Use the event and store the status
 *   in the client state.
 */
Tox_User_Status tox_friend_get_status(
    const Tox *tox, Tox_Friend_Number friend_number, Tox_Err_Friend_Query *error);

/**
 * @param friend_number The friend number of the friend whose user status
 *   changed.
 * @param status The new user status.
 */
typedef void tox_friend_status_cb(
    Tox *tox, Tox_Friend_Number friend_number, Tox_User_Status status, void *user_data);

/**
 * @brief Set the callback for the `friend_status` event.
 *
 * Pass NULL to unset.
 *
 * This event is triggered when a friend changes their user status.
 */
void tox_callback_friend_status(Tox *tox, tox_friend_status_cb *callback);

/**
 * @brief Check whether a friend is currently connected to this client.
 *
 * The result of this function is equal to the last value received by the
 * `friend_connection_status` callback.
 *
 * @param friend_number The friend number for which to query the connection
 *   status.
 *
 * @return the friend's connection status as it was received through the
 *   `friend_connection_status` event.
 *
 * @deprecated This getter is deprecated. Use the event and store the status
 *   in the client state.
 */
Tox_Connection tox_friend_get_connection_status(
    const Tox *tox, Tox_Friend_Number friend_number, Tox_Err_Friend_Query *error);

/**
 * @param friend_number The friend number of the friend whose connection status
 *   changed.
 * @param connection_status The result of calling
 *   tox_friend_get_connection_status on the passed friend_number.
 */
typedef void tox_friend_connection_status_cb(
    Tox *tox, Tox_Friend_Number friend_number, Tox_Connection connection_status, void *user_data);

/**
 * @brief Set the callback for the `friend_connection_status` event.
 *
 * Pass NULL to unset.
 *
 * This event is triggered when a friend goes offline after having been online,
 * or when a friend goes online.
 *
 * This callback is not called when adding friends. It is assumed that when
 * adding friends, their connection status is initially offline.
 */
void tox_callback_friend_connection_status(Tox *tox, tox_friend_connection_status_cb *callback);

/**
 * @brief Check whether a friend is currently typing a message.
 *
 * @param friend_number The friend number for which to query the typing status.
 *
 * @return true if the friend is typing.
 * @return false if the friend is not typing, or the friend number was
 *   invalid. Inspect the error code to determine which case it is.
 *
 * @deprecated This getter is deprecated. Use the event and store the status
 *   in the client state.
 */
bool tox_friend_get_typing(
    const Tox *tox, Tox_Friend_Number friend_number, Tox_Err_Friend_Query *error);

/**
 * @param friend_number The friend number of the friend who started or stopped
 *   typing.
 * @param typing The result of calling tox_friend_get_typing on the passed
 *   friend_number.
 */
typedef void tox_friend_typing_cb(
    Tox *tox, Tox_Friend_Number friend_number, bool typing, void *user_data);

/**
 * @brief Set the callback for the `friend_typing` event.
 *
 * Pass NULL to unset.
 *
 * This event is triggered when a friend starts or stops typing.
 */
void tox_callback_friend_typing(Tox *tox, tox_friend_typing_cb *callback);

/** @} */

/** @{
 * @name Sending private messages
 */

typedef enum Tox_Err_Set_Typing {

    /**
     * The function returned successfully.
     */
    TOX_ERR_SET_TYPING_OK,

    /**
     * The friend number did not designate a valid friend.
     */
    TOX_ERR_SET_TYPING_FRIEND_NOT_FOUND,

} Tox_Err_Set_Typing;

const char *tox_err_set_typing_to_string(Tox_Err_Set_Typing value);

/**
 * @brief Set the client's typing status for a friend.
 *
 * The client is responsible for turning it on or off.
 *
 * @param friend_number The friend to which the client is typing a message.
 * @param typing The typing status. True means the client is typing.
 *
 * @return true on success.
 */
bool tox_self_set_typing(
    Tox *tox, Tox_Friend_Number friend_number, bool typing, Tox_Err_Set_Typing *error);

typedef enum Tox_Err_Friend_Send_Message {

    /**
     * The function returned successfully.
     */
    TOX_ERR_FRIEND_SEND_MESSAGE_OK,

    /**
     * One of the arguments to the function was NULL when it was not expected.
     */
    TOX_ERR_FRIEND_SEND_MESSAGE_NULL,

    /**
     * The friend number did not designate a valid friend.
     */
    TOX_ERR_FRIEND_SEND_MESSAGE_FRIEND_NOT_FOUND,

    /**
     * This client is currently not connected to the friend.
     */
    TOX_ERR_FRIEND_SEND_MESSAGE_FRIEND_NOT_CONNECTED,

    /**
     * An allocation error occurred while increasing the send queue size.
     */
    TOX_ERR_FRIEND_SEND_MESSAGE_SENDQ,

    /**
     * Message length exceeded TOX_MAX_MESSAGE_LENGTH.
     */
    TOX_ERR_FRIEND_SEND_MESSAGE_TOO_LONG,

    /**
     * Attempted to send a zero-length message.
     */
    TOX_ERR_FRIEND_SEND_MESSAGE_EMPTY,

} Tox_Err_Friend_Send_Message;

const char *tox_err_friend_send_message_to_string(Tox_Err_Friend_Send_Message value);

typedef uint32_t Tox_Friend_Message_Id;

/**
 * @brief Send a text chat message to an online friend.
 *
 * This function creates a chat message packet and pushes it into the send
 * queue.
 *
 * The message length may not exceed TOX_MAX_MESSAGE_LENGTH. Larger messages
 * must be split by the client and sent as separate messages. Other clients can
 * then reassemble the fragments. Messages may not be empty.
 *
 * The return value of this function is the message ID. If a read receipt is
 * received, the triggered `friend_read_receipt` event will be passed this
 * message ID.
 *
 * Message IDs are unique per friend. The first message ID is 0. Message IDs are
 * incremented by 1 each time a message is sent. If UINT32_MAX messages were
 * sent, the next message ID is 0.
 *
 * @param type Message type (normal, action, ...).
 * @param friend_number The friend number of the friend to send the message to.
 * @param message A non-NULL pointer to the first element of a byte array
 *   containing the message text.
 * @param length Length of the message to be sent.
 */
Tox_Friend_Message_Id tox_friend_send_message(
    Tox *tox, Tox_Friend_Number friend_number, Tox_Message_Type type,
    const uint8_t message[], size_t length, Tox_Err_Friend_Send_Message *error);

/**
 * @param friend_number The friend number of the friend who received the
 *   message.
 * @param message_id The message ID as returned from tox_friend_send_message
 *   corresponding to the message sent.
 */
typedef void tox_friend_read_receipt_cb(
    Tox *tox, Tox_Friend_Number friend_number, Tox_Friend_Message_Id message_id, void *user_data);

/**
 * @brief Set the callback for the `friend_read_receipt` event.
 *
 * Pass NULL to unset.
 *
 * This event is triggered when the friend receives the message sent with
 * tox_friend_send_message with the corresponding message ID.
 */
void tox_callback_friend_read_receipt(Tox *tox, tox_friend_read_receipt_cb *callback);

/** @} */

/** @{
 * @name Receiving private messages and friend requests
 */

/**
 * @param public_key The Public Key of the user who sent the friend request.
 * @param message The message they sent along with the request.
 * @param length The size of the message byte array.
 */
typedef void tox_friend_request_cb(
    Tox *tox, const uint8_t public_key[TOX_PUBLIC_KEY_SIZE],
    const uint8_t message[], size_t length,
    void *user_data);

/**
 * @brief Set the callback for the `friend_request` event.
 *
 * Pass NULL to unset.
 *
 * This event is triggered when a friend request is received.
 */
void tox_callback_friend_request(Tox *tox, tox_friend_request_cb *callback);

/**
 * @param friend_number The friend number of the friend who sent the message.
 * @param type The type of the message (normal, action, ...).
 * @param message The message data they sent.
 * @param length The size of the message byte array.
 */
typedef void tox_friend_message_cb(
    Tox *tox, Tox_Friend_Number friend_number, Tox_Message_Type type,
    const uint8_t message[], size_t length, void *user_data);

/**
 * @brief Set the callback for the `friend_message` event.
 *
 * Pass NULL to unset.
 *
 * This event is triggered when a message from a friend is received.
 */
void tox_callback_friend_message(Tox *tox, tox_friend_message_cb *callback);

/** @} */

/** @{
 * @name File transmission: common between sending and receiving
 */

typedef uint32_t Tox_File_Number;

/**
 * @brief Generates a cryptographic hash of the given data.
 *
 * This function may be used by clients for any purpose, but is provided
 * primarily for validating cached avatars. This use is highly recommended to
 * avoid unnecessary avatar updates.
 *
 * If hash is NULL or data is NULL while length is not 0 the function returns
 * false, otherwise it returns true.
 *
 * This function is a wrapper to internal message-digest functions.
 *
 * @param hash A valid memory location the hash data. It must be at least
 *   TOX_HASH_LENGTH bytes in size.
 * @param data Data to be hashed or NULL.
 * @param length Size of the data array or 0.
 *
 * @return true if hash was not NULL.
 */
bool tox_hash(uint8_t hash[TOX_HASH_LENGTH], const uint8_t data[], size_t length);

/**
 * @brief A list of pre-defined file kinds.
 *
 * The Tox library itself does not behave differently for different file kinds.
 * These are a hint to the client telling it what use the sender intended for
 * the file. The `kind` parameter in the send function and recv callback are
 * `uint32_t`, not Tox_File_Kind, because clients can invent their own file
 * kind. Unknown file kinds should be treated as TOX_FILE_KIND_DATA.
 */
enum Tox_File_Kind {

    /**
     * Arbitrary file data. Clients can choose to handle it based on the file
     * name or magic or any other way they choose.
     */
    TOX_FILE_KIND_DATA,

    /**
     * Avatar file_id. This consists of tox_hash(image).
     * Avatar data. This consists of the image data.
     *
     * Avatars can be sent at any time the client wishes. Generally, a client
     * will send the avatar to a friend when that friend comes online, and to
     * all friends when the avatar changed. A client can save some traffic by
     * remembering which friend received the updated avatar already and only
     * send it if the friend has an out of date avatar.
     *
     * Clients who receive avatar send requests can reject it (by sending
     * TOX_FILE_CONTROL_CANCEL before any other controls), or accept it (by
     * sending TOX_FILE_CONTROL_RESUME). The file_id of length TOX_HASH_LENGTH
     * bytes (same length as TOX_FILE_ID_LENGTH) will contain the hash. A client
     * can compare this hash with a saved hash and send TOX_FILE_CONTROL_CANCEL
     * to terminate the avatar transfer if it matches.
     *
     * When file_size is set to 0 in the transfer request it means that the
     * client has no avatar.
     */
    TOX_FILE_KIND_AVATAR,

};

typedef enum Tox_File_Control {

    /**
     * Sent by the receiving side to accept a file send request. Also sent after
     * a TOX_FILE_CONTROL_PAUSE command to continue sending or receiving.
     */
    TOX_FILE_CONTROL_RESUME,

    /**
     * Sent by clients to pause the file transfer. The initial state of a file
     * transfer is always paused on the receiving side and running on the
     * sending side. If both the sending and receiving side pause the transfer,
     * then both need to send TOX_FILE_CONTROL_RESUME for the transfer to
     * resume.
     */
    TOX_FILE_CONTROL_PAUSE,

    /**
     * Sent by the receiving side to reject a file send request before any other
     * commands are sent. Also sent by either side to terminate a file transfer.
     */
    TOX_FILE_CONTROL_CANCEL,

} Tox_File_Control;

const char *tox_file_control_to_string(Tox_File_Control value);

typedef enum Tox_Err_File_Control {

    /**
     * The function returned successfully.
     */
    TOX_ERR_FILE_CONTROL_OK,

    /**
     * The friend_number passed did not designate a valid friend.
     */
    TOX_ERR_FILE_CONTROL_FRIEND_NOT_FOUND,

    /**
     * This client is currently not connected to the friend.
     */
    TOX_ERR_FILE_CONTROL_FRIEND_NOT_CONNECTED,

    /**
     * No file transfer with the given file number was found for the given
     * friend.
     */
    TOX_ERR_FILE_CONTROL_NOT_FOUND,

    /**
     * A RESUME control was sent, but the file transfer is running normally.
     */
    TOX_ERR_FILE_CONTROL_NOT_PAUSED,

    /**
     * A RESUME control was sent, but the file transfer was paused by the other
     * party. Only the party that paused the transfer can resume it.
     */
    TOX_ERR_FILE_CONTROL_DENIED,

    /**
     * A PAUSE control was sent, but the file transfer was already paused.
     */
    TOX_ERR_FILE_CONTROL_ALREADY_PAUSED,

    /**
     * Packet queue is full.
     */
    TOX_ERR_FILE_CONTROL_SENDQ,

} Tox_Err_File_Control;

const char *tox_err_file_control_to_string(Tox_Err_File_Control value);

/**
 * @brief Sends a file control command to a friend for a given file transfer.
 *
 * @param friend_number The friend number of the friend the file is being
 *   transferred to or received from.
 * @param file_number The friend-specific identifier for the file transfer.
 * @param control The control command to send.
 *
 * @return true on success.
 */
bool tox_file_control(
    Tox *tox, Tox_Friend_Number friend_number, Tox_File_Number file_number, Tox_File_Control control,
    Tox_Err_File_Control *error);

/**
 * @brief When receiving TOX_FILE_CONTROL_CANCEL, the client should release the
 * resources associated with the file number and consider the transfer failed.
 *
 * @param friend_number The friend number of the friend who is sending the file.
 * @param file_number The friend-specific file number the data received is
 *   associated with.
 * @param control The file control command received.
 */
typedef void tox_file_recv_control_cb(
    Tox *tox, Tox_Friend_Number friend_number, Tox_File_Number file_number, Tox_File_Control control,
    void *user_data);

/**
 * @brief Set the callback for the `file_recv_control` event.
 *
 * Pass NULL to unset.
 *
 * This event is triggered when a file control command is received from a
 * friend.
 */
void tox_callback_file_recv_control(Tox *tox, tox_file_recv_control_cb *callback);

typedef enum Tox_Err_File_Seek {

    /**
     * The function returned successfully.
     */
    TOX_ERR_FILE_SEEK_OK,

    /**
     * The friend_number passed did not designate a valid friend.
     */
    TOX_ERR_FILE_SEEK_FRIEND_NOT_FOUND,

    /**
     * This client is currently not connected to the friend.
     */
    TOX_ERR_FILE_SEEK_FRIEND_NOT_CONNECTED,

    /**
     * No file transfer with the given file number was found for the given
     * friend.
     */
    TOX_ERR_FILE_SEEK_NOT_FOUND,

    /**
     * File was not in a state where it could be seeked.
     */
    TOX_ERR_FILE_SEEK_DENIED,

    /**
     * Seek position was invalid
     */
    TOX_ERR_FILE_SEEK_INVALID_POSITION,

    /**
     * Packet queue is full.
     */
    TOX_ERR_FILE_SEEK_SENDQ,

} Tox_Err_File_Seek;

const char *tox_err_file_seek_to_string(Tox_Err_File_Seek value);

/**
 * @brief Sends a file seek control command to a friend for a given file
 *   transfer.
 *
 * This function can only be called to resume a file transfer right before
 * TOX_FILE_CONTROL_RESUME is sent.
 *
 * @param friend_number The friend number of the friend the file is being
 *   received from.
 * @param file_number The friend-specific identifier for the file transfer.
 * @param position The position that the file should be seeked to.
 */
bool tox_file_seek(
    Tox *tox, Tox_Friend_Number friend_number, Tox_File_Number file_number, uint64_t position, Tox_Err_File_Seek *error);

typedef enum Tox_Err_File_Get {

    /**
     * The function returned successfully.
     */
    TOX_ERR_FILE_GET_OK,

    /**
     * One of the arguments to the function was NULL when it was not expected.
     */
    TOX_ERR_FILE_GET_NULL,

    /**
     * The friend_number passed did not designate a valid friend.
     */
    TOX_ERR_FILE_GET_FRIEND_NOT_FOUND,

    /**
     * No file transfer with the given file number was found for the given
     * friend.
     */
    TOX_ERR_FILE_GET_NOT_FOUND,

} Tox_Err_File_Get;

const char *tox_err_file_get_to_string(Tox_Err_File_Get value);

/**
 * @brief Copy the file id associated to the file transfer to a byte array.
 *
 * @param friend_number The friend number of the friend the file is being
 *   transferred to or received from.
 * @param file_number The friend-specific identifier for the file transfer.
 * @param file_id A memory region of at least TOX_FILE_ID_LENGTH bytes. If this
 *   parameter is NULL, this function has no effect.
 *
 * @return true on success.
 */
bool tox_file_get_file_id(
    const Tox *tox, Tox_Friend_Number friend_number, Tox_File_Number file_number,
    uint8_t file_id[TOX_FILE_ID_LENGTH],
    Tox_Err_File_Get *error);

/** @} */

/** @{
 * @name File transmission: sending
 */

typedef enum Tox_Err_File_Send {

    /**
     * The function returned successfully.
     */
    TOX_ERR_FILE_SEND_OK,

    /**
     * One of the arguments to the function was NULL when it was not expected.
     */
    TOX_ERR_FILE_SEND_NULL,

    /**
     * The friend_number passed did not designate a valid friend.
     */
    TOX_ERR_FILE_SEND_FRIEND_NOT_FOUND,

    /**
     * This client is currently not connected to the friend.
     */
    TOX_ERR_FILE_SEND_FRIEND_NOT_CONNECTED,

    /**
     * Filename length exceeded TOX_MAX_FILENAME_LENGTH bytes.
     */
    TOX_ERR_FILE_SEND_NAME_TOO_LONG,

    /**
     * Too many ongoing transfers. The maximum number of concurrent file
     * transfers is 256 per friend per direction (sending and receiving).
     */
    TOX_ERR_FILE_SEND_TOO_MANY,

} Tox_Err_File_Send;

const char *tox_err_file_send_to_string(Tox_Err_File_Send value);

/**
 * @brief Send a file transmission request.
 *
 * Maximum filename length is TOX_MAX_FILENAME_LENGTH bytes. The filename should
 * generally just be a file name, not a path with directory names.
 *
 * If a non-UINT64_MAX file size is provided, it can be used by both sides to
 * determine the sending progress. File size can be set to UINT64_MAX for
 * streaming data of unknown size.
 *
 * File transmission occurs in chunks, which are requested through the
 * `file_chunk_request` event.
 *
 * When a friend goes offline, all file transfers associated with the friend get
 * purged.
 *
 * If the file contents change during a transfer, the behaviour is unspecified
 * in general. What will actually happen depends on the mode in which the file
 * was modified and how the client determines the file size.
 *
 * - If the file size was increased
 *   - and sending mode was streaming (file_size = UINT64_MAX), the behaviour
 *     will be as expected.
 *   - and sending mode was file (file_size != UINT64_MAX), the
 *     file_chunk_request callback will receive length = 0 when Tox thinks the
 *     file transfer has finished. If the client remembers the file size as it
 *     was when sending the request, it will terminate the transfer normally. If
 *     the client re-reads the size, it will think the friend cancelled the
 *     transfer.
 * - If the file size was decreased
 *   - and sending mode was streaming, the behaviour is as expected.
 *   - and sending mode was file, the callback will return 0 at the new
 *     (earlier) end-of-file, signaling to the friend that the transfer was
 *     cancelled.
 * - If the file contents were modified
 *   - at a position before the current read, the two files (local and remote)
 *     will differ after the transfer terminates.
 *   - at a position after the current read, the file transfer will succeed as
 *     expected.
 *   - In either case, both sides will regard the transfer as complete and
 *     successful.
 *
 * @param friend_number The friend number of the friend the file send request
 *   should be sent to.
 * @param kind The meaning of the file to be sent.
 * @param file_size Size in bytes of the file the client wants to send,
 *   UINT64_MAX if unknown or streaming.
 * @param file_id A file identifier of length TOX_FILE_ID_LENGTH that can be
 *   used to uniquely identify file transfers across Tox restarts. If NULL, a
 *   random one will be generated by the library. It can then be obtained by
 *   using `tox_file_get_file_id()`.
 * @param filename Name of the file. Does not need to be the actual name. This
 *   name will be sent along with the file send request.
 * @param filename_length Size in bytes of the filename.
 *
 * @return A file number used as an identifier in subsequent callbacks. This
 *   number is per friend. File numbers are reused after a transfer terminates.
 *   On failure, this function returns an unspecified value. Any pattern in file
 *   numbers should not be relied on.
 */
Tox_File_Number tox_file_send(
    Tox *tox, Tox_Friend_Number friend_number, uint32_t kind, uint64_t file_size,
    const uint8_t file_id[TOX_FILE_ID_LENGTH], const uint8_t filename[], size_t filename_length,
    Tox_Err_File_Send *error);

typedef enum Tox_Err_File_Send_Chunk {

    /**
     * The function returned successfully.
     */
    TOX_ERR_FILE_SEND_CHUNK_OK,

    /**
     * The length parameter was non-zero, but data was NULL.
     */
    TOX_ERR_FILE_SEND_CHUNK_NULL,

    /**
     * The friend_number passed did not designate a valid friend.
     */
    TOX_ERR_FILE_SEND_CHUNK_FRIEND_NOT_FOUND,

    /**
     * This client is currently not connected to the friend.
     */
    TOX_ERR_FILE_SEND_CHUNK_FRIEND_NOT_CONNECTED,

    /**
     * No file transfer with the given file number was found for the given
     * friend.
     */
    TOX_ERR_FILE_SEND_CHUNK_NOT_FOUND,

    /**
     * File transfer was found but isn't in a transferring state: (paused, done,
     * broken, etc...) (happens only when not called from the request chunk
     * callback).
     */
    TOX_ERR_FILE_SEND_CHUNK_NOT_TRANSFERRING,

    /**
     * Attempted to send more or less data than requested. The requested data
     * size is adjusted according to maximum transmission unit and the expected
     * end of the file. Trying to send less or more than requested will return
     * this error.
     */
    TOX_ERR_FILE_SEND_CHUNK_INVALID_LENGTH,

    /**
     * Packet queue is full.
     */
    TOX_ERR_FILE_SEND_CHUNK_SENDQ,

    /**
     * Position parameter was wrong.
     */
    TOX_ERR_FILE_SEND_CHUNK_WRONG_POSITION,

} Tox_Err_File_Send_Chunk;

const char *tox_err_file_send_chunk_to_string(Tox_Err_File_Send_Chunk value);

/**
 * @brief Send a chunk of file data to a friend.
 *
 * This function is called in response to the `file_chunk_request` callback. The
 * length parameter should be equal to the one received though the callback.
 * If it is zero, the transfer is assumed complete. For files with known size,
 * Tox will know that the transfer is complete after the last byte has been
 * received, so it is not necessary (though not harmful) to send a zero-length
 * chunk to terminate. For streams, Tox will know that the transfer is finished
 * if a chunk with length less than the length requested in the callback is
 * sent.
 *
 * @param friend_number The friend number of the receiving friend for this file.
 * @param file_number The file transfer identifier returned by tox_file_send.
 * @param position The file or stream position from which to continue reading.
 * @return true on success.
 */
bool tox_file_send_chunk(
    Tox *tox, Tox_Friend_Number friend_number, Tox_File_Number file_number, uint64_t position,
    const uint8_t data[], size_t length, Tox_Err_File_Send_Chunk *error);

/**
 * If the length parameter is 0, the file transfer is finished, and the client's
 * resources associated with the file number should be released. After a call
 * with zero length, the file number can be reused for future file transfers.
 *
 * If the requested position is not equal to the client's idea of the current
 * file or stream position, it will need to seek. In case of read-once streams,
 * the client should keep the last read chunk so that a seek back can be
 * supported. A seek-back only ever needs to read from the last requested chunk.
 * This happens when a chunk was requested, but the send failed. A seek-back
 * request can occur an arbitrary number of times for any given chunk.
 *
 * In response to receiving this callback, the client should call the function
 * `tox_file_send_chunk` with the requested chunk. If the number of bytes sent
 * through that function is zero, the file transfer is assumed complete. A
 * client must send the full length of data requested with this callback.
 *
 * @param friend_number The friend number of the receiving friend for this file.
 * @param file_number The file transfer identifier returned by tox_file_send.
 * @param position The file or stream position from which to continue reading.
 * @param length The number of bytes requested for the current chunk.
 */
typedef void tox_file_chunk_request_cb(
    Tox *tox, Tox_Friend_Number friend_number, Tox_File_Number file_number, uint64_t position,
    size_t length, void *user_data);

/**
 * @brief Set the callback for the `file_chunk_request` event.
 *
 * Pass NULL to unset.
 *
 * This event is triggered when Tox is ready to send more file data.
 */
void tox_callback_file_chunk_request(Tox *tox, tox_file_chunk_request_cb *callback);

/** @} */

/** @{
 * @name File transmission: receiving
 */

/**
 * The client should acquire resources to be associated with the file transfer.
 * Incoming file transfers start in the PAUSED state. After this callback
 * returns, a transfer can be rejected by sending a TOX_FILE_CONTROL_CANCEL
 * control command before any other control commands. It can be accepted by
 * sending TOX_FILE_CONTROL_RESUME.
 *
 * @param friend_number The friend number of the friend who is sending the file
 *   transfer request.
 * @param file_number The friend-specific file number the data received is
 *   associated with.
 * @param kind The meaning of the file that was sent.
 * @param file_size Size in bytes of the file the client wants to send,
 *   UINT64_MAX if unknown or streaming.
 * @param filename Name of the file. Does not need to be the actual name. This
 *   name will be sent along with the file send request.
 * @param filename_length Size in bytes of the filename.
 */
typedef void tox_file_recv_cb(
    Tox *tox, Tox_Friend_Number friend_number, Tox_File_Number file_number, uint32_t kind, uint64_t file_size,
    const uint8_t filename[], size_t filename_length, void *user_data);

/**
 * @brief Set the callback for the `file_recv` event.
 *
 * Pass NULL to unset.
 *
 * This event is triggered when a file transfer request is received.
 */
void tox_callback_file_recv(Tox *tox, tox_file_recv_cb *callback);

/**
 * When length is 0, the transfer is finished and the client should release the
 * resources it acquired for the transfer. After a call with length = 0, the
 * file number can be reused for new file transfers.
 *
 * If position is equal to file_size (received in the file_receive callback)
 * when the transfer finishes, the file was received completely. Otherwise, if
 * file_size was UINT64_MAX, streaming ended successfully when length is 0.
 *
 * @param friend_number The friend number of the friend who is sending the file.
 * @param file_number The friend-specific file number the data received is
 *   associated with.
 * @param position The file position of the first byte in data.
 * @param data A byte array containing the received chunk.
 * @param length The length of the received chunk.
 */
typedef void tox_file_recv_chunk_cb(
    Tox *tox, Tox_Friend_Number friend_number, Tox_File_Number file_number, uint64_t position,
    const uint8_t data[], size_t length, void *user_data);

/**
 * @brief Set the callback for the `file_recv_chunk` event.
 *
 * Pass NULL to unset.
 *
 * This event is first triggered when a file transfer request is received, and
 * subsequently when a chunk of file data for an accepted request was received.
 */
void tox_callback_file_recv_chunk(Tox *tox, tox_file_recv_chunk_cb *callback);

/** @} */

/** @{
 * @name Conference management
 */

typedef uint32_t Tox_Conference_Number;
typedef uint32_t Tox_Conference_Peer_Number;
typedef uint32_t Tox_Conference_Offline_Peer_Number;

/**
 * @brief Conference types for the conference_invite event.
 */
typedef enum Tox_Conference_Type {

    /**
     * Text-only conferences that must be accepted with the tox_conference_join
     * function.
     */
    TOX_CONFERENCE_TYPE_TEXT,

    /**
     * Video conference. The function to accept these is in toxav.
     */
    TOX_CONFERENCE_TYPE_AV,

} Tox_Conference_Type;

const char *tox_conference_type_to_string(Tox_Conference_Type value);

/**
 * The invitation will remain valid until the inviting friend goes offline
 * or exits the conference.
 *
 * @param friend_number The friend who invited us.
 * @param type The conference type (text only or audio/video).
 * @param cookie A piece of data of variable length required to join the
 *   conference.
 * @param length The length of the cookie.
 */
typedef void tox_conference_invite_cb(
    Tox *tox, Tox_Friend_Number friend_number, Tox_Conference_Type type,
    const uint8_t cookie[], size_t length, void *user_data);

/**
 * @brief Set the callback for the `conference_invite` event.
 *
 * Pass NULL to unset.
 *
 * This event is triggered when the client is invited to join a conference.
 */
void tox_callback_conference_invite(Tox *tox, tox_conference_invite_cb *callback);

/**
 * @param conference_number The conference number of the conference to which we
 *   have connected.
 */
typedef void tox_conference_connected_cb(Tox *tox, Tox_Conference_Number conference_number, void *user_data);

/**
 * @brief Set the callback for the `conference_connected` event.
 *
 * Pass NULL to unset.
 *
 * This event is triggered when the client successfully connects to a
 * conference after joining it with the tox_conference_join function.
 */
void tox_callback_conference_connected(Tox *tox, tox_conference_connected_cb *callback);

/**
 * @param conference_number The conference number of the conference the message
 *   is intended for.
 * @param peer_number The ID of the peer who sent the message.
 * @param type The type of message (normal, action, ...).
 * @param message The message data.
 * @param length The length of the message.
 */
typedef void tox_conference_message_cb(
    Tox *tox, Tox_Conference_Number conference_number, Tox_Conference_Peer_Number peer_number,
    Tox_Message_Type type, const uint8_t message[], size_t length, void *user_data);

/**
 * @brief Set the callback for the `conference_message` event.
 *
 * Pass NULL to unset.
 *
 * This event is triggered when the client receives a conference message.
 */
void tox_callback_conference_message(Tox *tox, tox_conference_message_cb *callback);

/**
 * @param conference_number The conference number of the conference the title
 *   change is intended for.
 * @param peer_number The ID of the peer who changed the title.
 * @param title The title data.
 * @param length The title length.
 */
typedef void tox_conference_title_cb(
    Tox *tox, Tox_Conference_Number conference_number, Tox_Conference_Peer_Number peer_number,
    const uint8_t title[], size_t length, void *user_data);

/**
 * @brief Set the callback for the `conference_title` event.
 *
 * Pass NULL to unset.
 *
 * This event is triggered when a peer changes the conference title.
 *
 * If peer_number == UINT32_MAX, then author is unknown (e.g. initial joining
 * the conference).
 */
void tox_callback_conference_title(Tox *tox, tox_conference_title_cb *callback);

/**
 * @param conference_number The conference number of the conference the
 *   peer is in.
 * @param peer_number The ID of the peer who changed their nickname.
 * @param name A byte array containing the new nickname.
 * @param length The size of the name byte array.
 */
typedef void tox_conference_peer_name_cb(
    Tox *tox, Tox_Conference_Number conference_number, Tox_Conference_Peer_Number peer_number,
    const uint8_t name[], size_t length, void *user_data);

/**
 * @brief Set the callback for the `conference_peer_name` event.
 *
 * Pass NULL to unset.
 *
 * This event is triggered when a peer changes their name.
 */
void tox_callback_conference_peer_name(Tox *tox, tox_conference_peer_name_cb *callback);

/**
 * @param conference_number The conference number of the conference the
 *   peer is in.
 */
typedef void tox_conference_peer_list_changed_cb(Tox *tox, Tox_Conference_Number conference_number, void *user_data);

/**
 * @brief Set the callback for the `conference_peer_list_changed` event.
 *
 * Pass NULL to unset.
 *
 * This event is triggered when a peer joins or leaves the conference.
 */
void tox_callback_conference_peer_list_changed(Tox *tox, tox_conference_peer_list_changed_cb *callback);

typedef enum Tox_Err_Conference_New {

    /**
     * The function returned successfully.
     */
    TOX_ERR_CONFERENCE_NEW_OK,

    /**
     * The conference instance failed to initialize.
     */
    TOX_ERR_CONFERENCE_NEW_INIT,

} Tox_Err_Conference_New;

const char *tox_err_conference_new_to_string(Tox_Err_Conference_New value);

/**
 * @brief Creates a new conference.
 *
 * This function creates and connects to a new text conference.
 *
 * @return
 *   - conference number on success
 *   - an unspecified value on failure
 */
Tox_Conference_Number tox_conference_new(Tox *tox, Tox_Err_Conference_New *error);

typedef enum Tox_Err_Conference_Delete {

    /**
     * The function returned successfully.
     */
    TOX_ERR_CONFERENCE_DELETE_OK,

    /**
     * The conference number passed did not designate a valid conference.
     */
    TOX_ERR_CONFERENCE_DELETE_CONFERENCE_NOT_FOUND,

} Tox_Err_Conference_Delete;

const char *tox_err_conference_delete_to_string(Tox_Err_Conference_Delete value);

/**
 * @brief This function deletes a conference.
 *
 * @param conference_number The conference number of the conference to be
 *   deleted.
 *
 * @return true on success.
 */
bool tox_conference_delete(Tox *tox, Tox_Conference_Number conference_number, Tox_Err_Conference_Delete *error);

/**
 * @brief Error codes for peer info queries.
 */
typedef enum Tox_Err_Conference_Peer_Query {

    /**
     * The function returned successfully.
     */
    TOX_ERR_CONFERENCE_PEER_QUERY_OK,

    /**
     * The conference number passed did not designate a valid conference.
     */
    TOX_ERR_CONFERENCE_PEER_QUERY_CONFERENCE_NOT_FOUND,

    /**
     * The peer number passed did not designate a valid peer.
     */
    TOX_ERR_CONFERENCE_PEER_QUERY_PEER_NOT_FOUND,

    /**
     * The client is not connected to the conference.
     */
    TOX_ERR_CONFERENCE_PEER_QUERY_NO_CONNECTION,

} Tox_Err_Conference_Peer_Query;

const char *tox_err_conference_peer_query_to_string(Tox_Err_Conference_Peer_Query value);

/**
 * @brief Return the number of online peers in the conference.
 *
 * The unsigned integers less than this number are the valid values of
 * peer_number for the functions querying these peers. Return value is
 * unspecified on failure.
 */
uint32_t tox_conference_peer_count(
    const Tox *tox, Tox_Conference_Number conference_number, Tox_Err_Conference_Peer_Query *error);

/**
 * @brief Return the length of the peer's name.
 *
 * Return value is unspecified on failure.
 */
size_t tox_conference_peer_get_name_size(
    const Tox *tox, Tox_Conference_Number conference_number, Tox_Conference_Peer_Number peer_number,
    Tox_Err_Conference_Peer_Query *error);

/**
 * @brief Copy the name of peer_number who is in conference_number to name.
 *
 * Call tox_conference_peer_get_name_size to determine the allocation size for
 * the `name` parameter.
 *
 * @param name A valid memory region large enough to store the peer's name.
 *
 * @return true on success.
 */
bool tox_conference_peer_get_name(
    const Tox *tox, Tox_Conference_Number conference_number, Tox_Conference_Peer_Number peer_number,
    uint8_t name[], Tox_Err_Conference_Peer_Query *error);

/**
 * @brief Copy the public key of peer_number who is in conference_number to
 *   public_key.
 *
 * public_key must be TOX_PUBLIC_KEY_SIZE long.
 *
 * @return true on success.
 */
bool tox_conference_peer_get_public_key(
    const Tox *tox, Tox_Conference_Number conference_number, Tox_Conference_Peer_Number peer_number,
    uint8_t public_key[TOX_PUBLIC_KEY_SIZE], Tox_Err_Conference_Peer_Query *error);

/**
 * @brief Return true if passed peer_number corresponds to our own.
 */
bool tox_conference_peer_number_is_ours(
    const Tox *tox, Tox_Conference_Number conference_number, Tox_Conference_Peer_Number peer_number,
    Tox_Err_Conference_Peer_Query *error);

/**
 * @brief Return the number of offline peers in the conference.
 *
 * The unsigned integers less than this number are the valid values of
 * offline_peer_number for the functions querying these peers.
 *
 * Return value is unspecified on failure.
 */
uint32_t tox_conference_offline_peer_count(
    const Tox *tox, Tox_Conference_Number conference_number,
    Tox_Err_Conference_Peer_Query *error);

/**
 * @brief Return the length of the offline peer's name.
 *
 * Return value is unspecified on failure.
 */
size_t tox_conference_offline_peer_get_name_size(
    const Tox *tox, Tox_Conference_Number conference_number,
    Tox_Conference_Offline_Peer_Number offline_peer_number, Tox_Err_Conference_Peer_Query *error);

/**
 * @brief Copy the name of offline_peer_number who is in conference_number to
 *   name.
 *
 * Call tox_conference_offline_peer_get_name_size to determine the allocation
 * size for the `name` parameter.
 *
 * @param name A valid memory region large enough to store the peer's name.
 *
 * @return true on success.
 */
bool tox_conference_offline_peer_get_name(
    const Tox *tox, Tox_Conference_Number conference_number, Tox_Conference_Offline_Peer_Number offline_peer_number,
    uint8_t name[], Tox_Err_Conference_Peer_Query *error);

/**
 * @brief Copy the public key of offline_peer_number who is in conference_number
 *   to public_key.
 *
 * public_key must be TOX_PUBLIC_KEY_SIZE long.
 *
 * @return true on success.
 */
bool tox_conference_offline_peer_get_public_key(
    const Tox *tox, Tox_Conference_Number conference_number,
    Tox_Conference_Offline_Peer_Number offline_peer_number, uint8_t public_key[TOX_PUBLIC_KEY_SIZE], Tox_Err_Conference_Peer_Query *error);

/**
 * @brief Return a unix-time timestamp of the last time offline_peer_number was
 *   seen to be active.
 */
uint64_t tox_conference_offline_peer_get_last_active(
    const Tox *tox, Tox_Conference_Number conference_number,
    Tox_Conference_Offline_Peer_Number offline_peer_number, Tox_Err_Conference_Peer_Query *error);

typedef enum Tox_Err_Conference_Set_Max_Offline {

    /**
     * The function returned successfully.
     */
    TOX_ERR_CONFERENCE_SET_MAX_OFFLINE_OK,

    /**
     * The conference number passed did not designate a valid conference.
     */
    TOX_ERR_CONFERENCE_SET_MAX_OFFLINE_CONFERENCE_NOT_FOUND,

} Tox_Err_Conference_Set_Max_Offline;

const char *tox_err_conference_set_max_offline_to_string(Tox_Err_Conference_Set_Max_Offline value);

/**
 * @brief Set maximum number of offline peers to store, overriding the default.
 */
bool tox_conference_set_max_offline(
    Tox *tox, Tox_Conference_Number conference_number, uint32_t max_offline,
    Tox_Err_Conference_Set_Max_Offline *error);

typedef enum Tox_Err_Conference_Invite {

    /**
     * The function returned successfully.
     */
    TOX_ERR_CONFERENCE_INVITE_OK,

    /**
     * The conference number passed did not designate a valid conference.
     */
    TOX_ERR_CONFERENCE_INVITE_CONFERENCE_NOT_FOUND,

    /**
     * The invite packet failed to send.
     */
    TOX_ERR_CONFERENCE_INVITE_FAIL_SEND,

    /**
     * The client is not connected to the conference.
     */
    TOX_ERR_CONFERENCE_INVITE_NO_CONNECTION,

} Tox_Err_Conference_Invite;

const char *tox_err_conference_invite_to_string(Tox_Err_Conference_Invite value);

/**
 * @brief Invites a friend to a conference.
 *
 * @param friend_number The friend number of the friend we want to invite.
 * @param conference_number The conference number of the conference we want to
 *   invite the friend to.
 *
 * @return true on success.
 */
bool tox_conference_invite(
    Tox *tox, Tox_Friend_Number friend_number, Tox_Conference_Number conference_number,
    Tox_Err_Conference_Invite *error);

typedef enum Tox_Err_Conference_Join {

    /**
     * The function returned successfully.
     */
    TOX_ERR_CONFERENCE_JOIN_OK,

    /**
     * The cookie passed has an invalid length.
     */
    TOX_ERR_CONFERENCE_JOIN_INVALID_LENGTH,

    /**
     * The conference is not the expected type. This indicates an invalid
     * cookie.
     */
    TOX_ERR_CONFERENCE_JOIN_WRONG_TYPE,

    /**
     * The friend number passed does not designate a valid friend.
     */
    TOX_ERR_CONFERENCE_JOIN_FRIEND_NOT_FOUND,

    /**
     * Client is already in this conference.
     */
    TOX_ERR_CONFERENCE_JOIN_DUPLICATE,

    /**
     * Conference instance failed to initialize.
     */
    TOX_ERR_CONFERENCE_JOIN_INIT_FAIL,

    /**
     * The join packet failed to send.
     */
    TOX_ERR_CONFERENCE_JOIN_FAIL_SEND,

    /**
     * The cookie passed was NULL.
     */
    TOX_ERR_CONFERENCE_JOIN_NULL,

} Tox_Err_Conference_Join;

const char *tox_err_conference_join_to_string(Tox_Err_Conference_Join value);

/**
 * @brief Joins a conference that the client has been invited to.
 *
 * After successfully joining the conference, the client will not be "connected"
 * to it until a handshaking procedure has been completed. A
 * `conference_connected` event will then occur for the conference. The client
 * will then remain connected to the conference until the conference is deleted,
 * even across Tox restarts. Many operations on a conference will fail with a
 * corresponding error if attempted on a conference to which the client is not
 * yet connected.
 *
 * @param friend_number The friend number of the friend who sent the invite.
 * @param cookie Received via the `conference_invite` event.
 * @param length The size of cookie.
 *
 * @return conference number on success, an unspecified value on failure.
 */
Tox_Conference_Number tox_conference_join(
    Tox *tox, Tox_Friend_Number friend_number,
    const uint8_t cookie[], size_t length,
    Tox_Err_Conference_Join *error);

typedef enum Tox_Err_Conference_Send_Message {

    /**
     * The function returned successfully.
     */
    TOX_ERR_CONFERENCE_SEND_MESSAGE_OK,

    /**
     * The conference number passed did not designate a valid conference.
     */
    TOX_ERR_CONFERENCE_SEND_MESSAGE_CONFERENCE_NOT_FOUND,

    /**
     * The message is too long.
     */
    TOX_ERR_CONFERENCE_SEND_MESSAGE_TOO_LONG,

    /**
     * The client is not connected to the conference.
     */
    TOX_ERR_CONFERENCE_SEND_MESSAGE_NO_CONNECTION,

    /**
     * The message packet failed to send.
     */
    TOX_ERR_CONFERENCE_SEND_MESSAGE_FAIL_SEND,

} Tox_Err_Conference_Send_Message;

const char *tox_err_conference_send_message_to_string(Tox_Err_Conference_Send_Message value);

/**
 * @brief Send a text chat message to the conference.
 *
 * This function creates a conference message packet and pushes it into the send
 * queue.
 *
 * The message length may not exceed TOX_MAX_MESSAGE_LENGTH. Larger messages
 * must be split by the client and sent as separate messages. Other clients can
 * then reassemble the fragments.
 *
 * @param conference_number The conference number of the conference the message
 *   is intended for.
 * @param type Message type (normal, action, ...).
 * @param message A non-NULL pointer to the first element of a byte array
 *   containing the message text.
 * @param length Length of the message to be sent.
 *
 * @return true on success.
 */
bool tox_conference_send_message(
    Tox *tox, Tox_Conference_Number conference_number, Tox_Message_Type type,
    const uint8_t message[], size_t length,
    Tox_Err_Conference_Send_Message *error);

typedef enum Tox_Err_Conference_Title {

    /**
     * The function returned successfully.
     */
    TOX_ERR_CONFERENCE_TITLE_OK,

    /**
     * The conference number passed did not designate a valid conference.
     */
    TOX_ERR_CONFERENCE_TITLE_CONFERENCE_NOT_FOUND,

    /**
     * The title is too long or empty.
     */
    TOX_ERR_CONFERENCE_TITLE_INVALID_LENGTH,

    /**
     * The title packet failed to send.
     */
    TOX_ERR_CONFERENCE_TITLE_FAIL_SEND,

} Tox_Err_Conference_Title;

const char *tox_err_conference_title_to_string(Tox_Err_Conference_Title value);

/**
 * @brief Return the length of the conference title.
 *
 * Return value is unspecified on failure.
 *
 * The return value is equal to the `length` argument received by the last
 * `conference_title` callback.
 */
size_t tox_conference_get_title_size(
    const Tox *tox, Tox_Conference_Number conference_number, Tox_Err_Conference_Title *error);

/**
 * @brief Write the title designated by the given conference number to a byte
 *   array.
 *
 * Call tox_conference_get_title_size to determine the allocation size for the
 * `title` parameter.
 *
 * The data written to `title` is equal to the data received by the last
 * `conference_title` callback.
 *
 * @param title A valid memory region large enough to store the title.
 *   If this parameter is NULL, this function has no effect.
 *
 * @return true on success.
 */
bool tox_conference_get_title(
    const Tox *tox, Tox_Conference_Number conference_number,
    uint8_t title[],
    Tox_Err_Conference_Title *error);

/**
 * @brief Set the conference title and broadcast it to the rest of the
 *   conference.
 *
 * Title length cannot be longer than TOX_MAX_NAME_LENGTH.
 *
 * @return true on success.
 */
bool tox_conference_set_title(
    Tox *tox, Tox_Conference_Number conference_number,
    const uint8_t title[], size_t length,
    Tox_Err_Conference_Title *error);

/**
 * @brief Return the number of conferences in the Tox instance.
 *
 * This should be used to determine how much memory to allocate for
 * `tox_conference_get_chatlist`.
 */
size_t tox_conference_get_chatlist_size(const Tox *tox);

/**
 * @brief Copy a list of valid conference numbers into the array chatlist.
 *
 * Determine how much space to allocate for the array with the
 * `tox_conference_get_chatlist_size` function.
 *
 * Note that `tox_get_savedata` saves all connected conferences; when a Tox
 * instance is created from savedata in which conferences were saved, those
 * conferences will be connected at startup, and will be listed by
 * `tox_conference_get_chatlist`.
 *
 * The conference number of a loaded conference may differ from the conference
 * number it had when it was saved.
 */
void tox_conference_get_chatlist(const Tox *tox, Tox_Conference_Number chatlist[]);

/**
 * @brief Returns the type of conference (Tox_Conference_Type) that
 *   conference_number is.
 *
 * Return value is unspecified on failure.
 */
typedef enum Tox_Err_Conference_Get_Type {

    /**
     * The function returned successfully.
     */
    TOX_ERR_CONFERENCE_GET_TYPE_OK,

    /**
     * The conference number passed did not designate a valid conference.
     */
    TOX_ERR_CONFERENCE_GET_TYPE_CONFERENCE_NOT_FOUND,

} Tox_Err_Conference_Get_Type;

const char *tox_err_conference_get_type_to_string(Tox_Err_Conference_Get_Type value);

/**
 * @brief Get the type (text or A/V) for the conference.
 */
Tox_Conference_Type tox_conference_get_type(
    const Tox *tox, Tox_Conference_Number conference_number,
    Tox_Err_Conference_Get_Type *error);

/**
 * @brief Get the conference unique ID.
 *
 * If id is NULL, this function has no effect.
 *
 * @param id A memory region large enough to store TOX_CONFERENCE_ID_SIZE bytes.
 *
 * @return true on success.
 */
bool tox_conference_get_id(
    const Tox *tox, Tox_Conference_Number conference_number, uint8_t id[TOX_CONFERENCE_ID_SIZE]);

typedef enum Tox_Err_Conference_By_Id {

    /**
     * The function returned successfully.
     */
    TOX_ERR_CONFERENCE_BY_ID_OK,

    /**
     * One of the arguments to the function was NULL when it was not expected.
     */
    TOX_ERR_CONFERENCE_BY_ID_NULL,

    /**
     * No conference with the given id exists on the conference list.
     */
    TOX_ERR_CONFERENCE_BY_ID_NOT_FOUND,

} Tox_Err_Conference_By_Id;

const char *tox_err_conference_by_id_to_string(Tox_Err_Conference_By_Id value);

/**
 * @brief Return the conference number associated with the specified id.
 *
 * @param id A byte array containing the conference id (TOX_CONFERENCE_ID_SIZE).
 *
 * @return the conference number on success, an unspecified value on failure.
 */
Tox_Conference_Number tox_conference_by_id(
    const Tox *tox, const uint8_t id[TOX_CONFERENCE_ID_SIZE], Tox_Err_Conference_By_Id *error);

#ifndef TOX_HIDE_DEPRECATED
/**
 * @brief Get the conference unique ID.
 *
 * If uid is NULL, this function has no effect.
 *
 * @param uid A memory region large enough to store TOX_CONFERENCE_UID_SIZE
 *   bytes.
 *
 * @return true on success.
 * @deprecated use tox_conference_get_id instead (exactly the same function,
 *   just renamed).
 */
bool tox_conference_get_uid(
    const Tox *tox, Tox_Conference_Number conference_number, uint8_t uid[TOX_CONFERENCE_UID_SIZE]);
#endif /* TOX_HIDE_DEPRECATED */

typedef enum Tox_Err_Conference_By_Uid {

    /**
     * The function returned successfully.
     */
    TOX_ERR_CONFERENCE_BY_UID_OK,

    /**
     * One of the arguments to the function was NULL when it was not expected.
     */
    TOX_ERR_CONFERENCE_BY_UID_NULL,

    /**
     * No conference with the given uid exists on the conference list.
     */
    TOX_ERR_CONFERENCE_BY_UID_NOT_FOUND,

} Tox_Err_Conference_By_Uid;

const char *tox_err_conference_by_uid_to_string(Tox_Err_Conference_By_Uid value);

#ifndef TOX_HIDE_DEPRECATED
/**
 * @brief Return the conference number associated with the specified uid.
 *
 * @param uid A byte array containing the conference id
 *   (TOX_CONFERENCE_UID_SIZE).
 *
 * @return the conference number on success, an unspecified value on failure.
 * @deprecated use tox_conference_by_id instead (exactly the same function,
 *   just renamed).
 */
Tox_Conference_Number tox_conference_by_uid(
    const Tox *tox, const uint8_t uid[TOX_CONFERENCE_UID_SIZE], Tox_Err_Conference_By_Uid *error);
#endif /* TOX_HIDE_DEPRECATED */

/** @} */

/** @{
 * @name Low-level custom packet sending and receiving
 */

typedef enum Tox_Err_Friend_Custom_Packet {

    /**
     * The function returned successfully.
     */
    TOX_ERR_FRIEND_CUSTOM_PACKET_OK,

    /**
     * One of the arguments to the function was NULL when it was not expected.
     */
    TOX_ERR_FRIEND_CUSTOM_PACKET_NULL,

    /**
     * The friend number did not designate a valid friend.
     */
    TOX_ERR_FRIEND_CUSTOM_PACKET_FRIEND_NOT_FOUND,

    /**
     * This client is currently not connected to the friend.
     */
    TOX_ERR_FRIEND_CUSTOM_PACKET_FRIEND_NOT_CONNECTED,

    /**
     * The first byte of data was not one of the permitted values;
     * for lossy packets the first byte must be in the range 192-254,
     * and for lossless packets it must be either 69 or in the range 160-191.
     */
    TOX_ERR_FRIEND_CUSTOM_PACKET_INVALID,

    /**
     * Attempted to send an empty packet.
     */
    TOX_ERR_FRIEND_CUSTOM_PACKET_EMPTY,

    /**
     * Packet data length exceeded TOX_MAX_CUSTOM_PACKET_SIZE.
     */
    TOX_ERR_FRIEND_CUSTOM_PACKET_TOO_LONG,

    /**
     * Packet queue is full.
     */
    TOX_ERR_FRIEND_CUSTOM_PACKET_SENDQ,

} Tox_Err_Friend_Custom_Packet;

const char *tox_err_friend_custom_packet_to_string(Tox_Err_Friend_Custom_Packet value);

/**
 * @brief Send a custom lossy packet to a friend.
 *
 * The first byte of data must be in the range 192-254. Maximum length of a
 * custom packet is TOX_MAX_CUSTOM_PACKET_SIZE.
 *
 * Lossy packets behave like UDP packets, meaning they might never reach the
 * other side or might arrive more than once (if someone is messing with the
 * connection) or might arrive in the wrong order.
 *
 * Unless latency is an issue, it is recommended that you use lossless custom
 * packets instead.
 *
 * @param friend_number The friend number of the friend this lossy packet
 *   should be sent to.
 * @param data A byte array containing the packet data.
 * @param length The length of the packet data byte array.
 *
 * @return true on success.
 */
bool tox_friend_send_lossy_packet(
    Tox *tox, Tox_Friend_Number friend_number,
    const uint8_t data[], size_t length,
    Tox_Err_Friend_Custom_Packet *error);

/**
 * @brief Send a custom lossless packet to a friend.
 *
 * The first byte of data must be either 69 or in the range 160-191. Maximum length of a
 * custom packet is TOX_MAX_CUSTOM_PACKET_SIZE.
 *
 * Lossless packet behaviour is comparable to TCP (reliability, arrive in order)
 * but with packets instead of a stream.
 *
 * @param friend_number The friend number of the friend this lossless packet
 *   should be sent to.
 * @param data A byte array containing the packet data.
 * @param length The length of the packet data byte array.
 *
 * @return true on success.
 */
bool tox_friend_send_lossless_packet(
    Tox *tox, Tox_Friend_Number friend_number,
    const uint8_t data[], size_t length,
    Tox_Err_Friend_Custom_Packet *error);

/**
 * tox_callback_friend_lossy_packet is the compatibility function to
 * set the callback for all packet IDs except those reserved for ToxAV.
 *
 * @param friend_number The friend number of the friend who sent a lossy packet.
 * @param data A byte array containing the received packet data.
 * @param length The length of the packet data byte array.
 */
typedef void tox_friend_lossy_packet_cb(
    Tox *tox, Tox_Friend_Number friend_number,
    const uint8_t data[], size_t length,
    void *user_data);

/**
 * @brief Set the callback for the `friend_lossy_packet` event.
 *
 * Pass NULL to unset.
 */
void tox_callback_friend_lossy_packet(Tox *tox, tox_friend_lossy_packet_cb *callback);

/**
 * @param friend_number The friend number of the friend who sent the packet.
 * @param data A byte array containing the received packet data.
 * @param length The length of the packet data byte array.
 */
typedef void tox_friend_lossless_packet_cb(
    Tox *tox, Tox_Friend_Number friend_number,
    const uint8_t data[], size_t length,
    void *user_data);

/**
 * @brief Set the callback for the `friend_lossless_packet` event.
 *
 * Pass NULL to unset.
 */
void tox_callback_friend_lossless_packet(Tox *tox, tox_friend_lossless_packet_cb *callback);

/** @} */

/** @{
 * @name Low-level network information
 */

typedef enum Tox_Err_Get_Port {

    /**
     * The function returned successfully.
     */
    TOX_ERR_GET_PORT_OK,

    /**
     * The instance was not bound to any port.
     */
    TOX_ERR_GET_PORT_NOT_BOUND,

} Tox_Err_Get_Port;

const char *tox_err_get_port_to_string(Tox_Err_Get_Port value);

/**
 * @brief Writes the temporary DHT public key of this instance to a byte array.
 *
 * This can be used in combination with an externally accessible IP address and
 * the bound port (from tox_self_get_udp_port) to run a temporary bootstrap
 * node.
 *
 * Be aware that every time a new instance is created, the DHT public key
 * changes, meaning this cannot be used to run a permanent bootstrap node.
 *
 * @param dht_id A memory region of at least TOX_PUBLIC_KEY_SIZE bytes. If this
 *   parameter is NULL, this function has no effect.
 */
void tox_self_get_dht_id(const Tox *tox, uint8_t dht_id[TOX_PUBLIC_KEY_SIZE]);

/**
 * @brief Return the UDP port this Tox instance is bound to.
 */
uint16_t tox_self_get_udp_port(const Tox *tox, Tox_Err_Get_Port *error);

/**
 * @brief Return the TCP port this Tox instance is bound to.
 *
 * This is only relevant if the instance is acting as a TCP relay.
 */
uint16_t tox_self_get_tcp_port(const Tox *tox, Tox_Err_Get_Port *error);

/** @} */

/** @{
 * @name Group chats
 */

typedef uint32_t Tox_Group_Number;
typedef uint32_t Tox_Group_Peer_Number;
typedef uint32_t Tox_Group_Message_Id;

/*******************************************************************************
 *
 * :: Group chat numeric constants
 *
 ******************************************************************************/

/**
 * Maximum length of a group topic.
 */
#define TOX_GROUP_MAX_TOPIC_LENGTH     512

uint32_t tox_group_max_topic_length(void);

/**
 * Maximum length of a peer part message.
 */
#define TOX_GROUP_MAX_PART_LENGTH      128

uint32_t tox_group_max_part_length(void);

/**
 * Maximum length of a group text message.
 */
#define TOX_GROUP_MAX_MESSAGE_LENGTH    1372

uint32_t tox_group_max_message_length(void);

/**
 * Maximum length of a group custom lossy packet.
 */
#define TOX_GROUP_MAX_CUSTOM_LOSSY_PACKET_LENGTH 1373

uint32_t tox_group_max_custom_lossy_packet_length(void);

/**
 * Maximum length of a group custom lossless packet.
 */
#define TOX_GROUP_MAX_CUSTOM_LOSSLESS_PACKET_LENGTH 1373

uint32_t tox_group_max_custom_lossless_packet_length(void);

/**
 * Maximum length of a group name.
 */
#define TOX_GROUP_MAX_GROUP_NAME_LENGTH 48

uint32_t tox_group_max_group_name_length(void);

/**
 * Maximum length of a group password.
 */
#define TOX_GROUP_MAX_PASSWORD_SIZE    32

uint32_t tox_group_max_password_size(void);

/**
 * Number of bytes in a group Chat ID.
 */
#define TOX_GROUP_CHAT_ID_SIZE         32

uint32_t tox_group_chat_id_size(void);

/**
 * Size of a peer public key.
 */
#define TOX_GROUP_PEER_PUBLIC_KEY_SIZE 32

uint32_t tox_group_peer_public_key_size(void);

/*******************************************************************************
 *
 * :: Group chat state enumerators
 *
 ******************************************************************************/

/**
 * Represents the group privacy state.
 */
typedef enum Tox_Group_Privacy_State {

    /**
     * The group is considered to be public. Anyone may join the group using
     * the Chat ID.
     *
     * If the group is in this state, even if the Chat ID is never explicitly
     * shared with someone outside of the group, information including the Chat
     * ID, IP addresses, and peer ID's (but not Tox ID's) is visible to anyone
     * with access to a node storing a DHT entry for the given group.
     */
    TOX_GROUP_PRIVACY_STATE_PUBLIC,

    /**
     * The group is considered to be private. The only way to join the group is
     * by having someone in your contact list send you an invite.
     *
     * If the group is in this state, no group information (mentioned above) is
     * present in the DHT; the DHT is not used for any purpose at all. If a
     * public group is set to private, all DHT information related to the group
     * will expire shortly.
     */
    TOX_GROUP_PRIVACY_STATE_PRIVATE,

} Tox_Group_Privacy_State;

const char *tox_group_privacy_state_to_string(Tox_Group_Privacy_State value);

/**
 * Represents the state of the group topic lock.
 *
 * The default is enabled.
 */
typedef enum Tox_Group_Topic_Lock {

    /**
     * The topic lock is enabled. Only peers with the founder and moderator
     * roles may set the topic.
     */
    TOX_GROUP_TOPIC_LOCK_ENABLED,

    /**
     * The topic lock is disabled. All peers except those with the observer role
     * may set the topic.
     */
    TOX_GROUP_TOPIC_LOCK_DISABLED,

} Tox_Group_Topic_Lock;

const char *tox_group_topic_lock_to_string(Tox_Group_Topic_Lock value);

/**
 * Represents the group voice state, which determines which Group Roles have
 * permission to speak in the group chat. The voice state does not have any
 * effect private messages or topic setting.
 */
typedef enum Tox_Group_Voice_State {
    /**
     * All group roles above Observer have permission to speak.
     */
    TOX_GROUP_VOICE_STATE_ALL,

    /**
     * Moderators and Founders have permission to speak.
     */
    TOX_GROUP_VOICE_STATE_MODERATOR,

    /**
     * Only the founder may speak.
     */
    TOX_GROUP_VOICE_STATE_FOUNDER,
} Tox_Group_Voice_State;

const char *tox_group_voice_state_to_string(Tox_Group_Voice_State value);

/**
 * Represents group roles.
 *
 * Roles are hierarchical in that each role has a set of privileges plus all the
 * privileges of the roles below it.
 */
typedef enum Tox_Group_Role {

    /**
     * May kick all other peers as well as set their role to anything (except
     * founder). Founders may also set the group password, toggle the privacy
     * state, and set the peer limit.
     */
    TOX_GROUP_ROLE_FOUNDER,

    /**
     * May kick and set the user and observer roles for peers below this role.
     * May also set the group topic.
     */
    TOX_GROUP_ROLE_MODERATOR,

    /**
     * May communicate with other peers normally.
     */
    TOX_GROUP_ROLE_USER,

    /**
     * May observe the group and ignore peers; may not communicate with other
     * peers or with the group.
     */
    TOX_GROUP_ROLE_OBSERVER,

} Tox_Group_Role;

const char *tox_group_role_to_string(Tox_Group_Role value);

/*******************************************************************************
 *
 * :: Group chat instance management
 *
 ******************************************************************************/

typedef enum Tox_Err_Group_New {

    /**
     * The function returned successfully.
     */
    TOX_ERR_GROUP_NEW_OK,

    /**
     * name exceeds TOX_MAX_NAME_LENGTH or group_name exceeded
     * TOX_GROUP_MAX_GROUP_NAME_LENGTH.
     */
    TOX_ERR_GROUP_NEW_TOO_LONG,

    /**
     * name or group_name is NULL or length is zero.
     */
    TOX_ERR_GROUP_NEW_EMPTY,

    /**
     * The group instance failed to initialize.
     */
    TOX_ERR_GROUP_NEW_INIT,

    /**
     * The group state failed to initialize. This usually indicates that
     * something went wrong related to cryptographic signing.
     */
    TOX_ERR_GROUP_NEW_STATE,

    /**
     * The group failed to announce to the DHT. This indicates a network related
     * error.
     */
    TOX_ERR_GROUP_NEW_ANNOUNCE,

} Tox_Err_Group_New;

const char *tox_err_group_new_to_string(Tox_Err_Group_New value);

/**
 * Creates a new group chat.
 *
 * This function creates a new group chat object and adds it to the chats array.
 *
 * The caller of this function has Founder role privileges.
 *
 * The client should initiate its peer list with self info after calling this
 * function, as the peer_join callback will not be triggered.
 *
 * @param privacy_state The privacy state of the group. If this is set to
 *   TOX_GROUP_PRIVACY_STATE_PUBLIC, the group will attempt to announce itself
 *   to the DHT and anyone with the Chat ID may join. Otherwise a friend invite
 *   will be required to join the group.
 * @param group_name The name of the group. The name must be non-NULL.
 * @param group_name_length The length of the group name. This must be greater
 *   than zero and no larger than TOX_GROUP_MAX_GROUP_NAME_LENGTH.
 * @param name The name of the peer creating the group.
 * @param name_length The length of the peer's name. This must be greater than
 *   zero and no larger than TOX_MAX_NAME_LENGTH.
 *
 * @return group_number on success, UINT32_MAX on failure.
 */
Tox_Group_Number tox_group_new(
    Tox *tox, Tox_Group_Privacy_State privacy_state,
    const uint8_t group_name[], size_t group_name_length,
    const uint8_t name[], size_t name_length, Tox_Err_Group_New *error);

typedef enum Tox_Err_Group_Join {

    /**
     * The function returned successfully.
     */
    TOX_ERR_GROUP_JOIN_OK,

    /**
     * The group instance failed to initialize.
     */
    TOX_ERR_GROUP_JOIN_INIT,

    /**
     * The chat_id pointer is set to NULL.
     */
    TOX_ERR_GROUP_JOIN_BAD_CHAT_ID,

    /**
     * name is NULL or name_length is zero.
     */
    TOX_ERR_GROUP_JOIN_EMPTY,

    /**
     * name exceeds TOX_MAX_NAME_LENGTH.
     */
    TOX_ERR_GROUP_JOIN_TOO_LONG,

    /**
     * Failed to set password. This usually occurs if the password exceeds
     * TOX_GROUP_MAX_PASSWORD_SIZE.
     */
    TOX_ERR_GROUP_JOIN_PASSWORD,

    /**
     * There was a core error when initiating the group.
     */
    TOX_ERR_GROUP_JOIN_CORE,

} Tox_Err_Group_Join;

const char *tox_err_group_join_to_string(Tox_Err_Group_Join value);

/**
 * Joins a group chat with specified Chat ID or reconnects to an existing group.
 *
 * This function creates a new group chat object, adds it to the chats array,
 * and sends a DHT announcement to find peers in the group associated with
 * chat_id. Once a peer has been found a join attempt will be initiated.
 *
 * If a group with the specified Chat ID already exists, this function will attempt
 * to reconnect to the group.
 *
 * @param chat_id The Chat ID of the group you wish to join. This must be
 *   TOX_GROUP_CHAT_ID_SIZE bytes.
 * @param password The password required to join the group. Set to NULL if no
 *   password is required.
 * @param password_length The length of the password. If length is equal to
 *   zero, the password parameter is ignored. length must be no larger than
 *   TOX_GROUP_MAX_PASSWORD_SIZE.
 * @param name The name of the peer joining the group.
 * @param name_length The length of the peer's name. This must be greater than
 *   zero and no larger than TOX_MAX_NAME_LENGTH.
 *
 * @return group_number on success, UINT32_MAX on failure.
 */
Tox_Group_Number tox_group_join(
    Tox *tox, const uint8_t chat_id[TOX_GROUP_CHAT_ID_SIZE],
    const uint8_t name[], size_t name_length,
    const uint8_t password[], size_t password_length,
    Tox_Err_Group_Join *error);

typedef enum Tox_Err_Group_Is_Connected {

    /**
     * The function returned successfully.
     */
    TOX_ERR_GROUP_IS_CONNECTED_OK,

    /**
     * The group number passed did not designate a valid group.
     */
    TOX_ERR_GROUP_IS_CONNECTED_GROUP_NOT_FOUND,

} Tox_Err_Group_Is_Connected;

const char *tox_err_group_is_connected_to_string(Tox_Err_Group_Is_Connected value);

/**
 * Returns true if the group chat is currently connected or attempting to
 * connect to other peers in the group.
 *
 * @param group_number The group number of the designated group.
 */
bool tox_group_is_connected(const Tox *tox, Tox_Group_Number group_number, Tox_Err_Group_Is_Connected *error);

typedef enum Tox_Err_Group_Disconnect {

    /**
     * The function returned successfully.
     */
    TOX_ERR_GROUP_DISCONNECT_OK,

    /**
     * The group number passed did not designate a valid group.
     */
    TOX_ERR_GROUP_DISCONNECT_GROUP_NOT_FOUND,

    /**
     * The group is already disconnected.
     */
    TOX_ERR_GROUP_DISCONNECT_ALREADY_DISCONNECTED,
} Tox_Err_Group_Disconnect;

const char *tox_err_group_disconnect_to_string(Tox_Err_Group_Disconnect value);

/**
 * Disconnects from a group chat while retaining the group state and
 * credentials.
 *
 * Returns true if we successfully disconnect from the group.
 *
 * @param group_number The group number of the designated group.
 */
bool tox_group_disconnect(const Tox *tox, Tox_Group_Number group_number, Tox_Err_Group_Disconnect *error);

typedef enum Tox_Err_Group_Reconnect {

    /**
     * The function returned successfully.
     */
    TOX_ERR_GROUP_RECONNECT_OK,

    /**
     * The group number passed did not designate a valid group.
     */
    TOX_ERR_GROUP_RECONNECT_GROUP_NOT_FOUND,

    /**
     * There was a core error when initiating the group.
     */
    TOX_ERR_GROUP_RECONNECT_CORE,

} Tox_Err_Group_Reconnect;

const char *tox_err_group_reconnect_to_string(Tox_Err_Group_Reconnect value);

#ifndef TOX_HIDE_DEPRECATED
/**
 * Reconnects to a group.
 *
 * This function disconnects from all peers in the group, then attempts to
 * reconnect with the group. The caller's state is not changed (i.e. name,
 * status, role, chat public key etc.).
 *
 * @param group_number The group number of the group we wish to reconnect to.
 *
 * @return true on success.
 *
 * @deprecated Use `tox_group_join` instead.
 */
bool tox_group_reconnect(Tox *tox, Tox_Group_Number group_number, Tox_Err_Group_Reconnect *error);
#endif /* TOX_HIDE_DEPRECATED */

typedef enum Tox_Err_Group_Leave {

    /**
     * The function returned successfully.
     */
    TOX_ERR_GROUP_LEAVE_OK,

    /**
     * The group number passed did not designate a valid group.
     */
    TOX_ERR_GROUP_LEAVE_GROUP_NOT_FOUND,

    /**
     * Message length exceeded TOX_GROUP_MAX_PART_LENGTH.
     */
    TOX_ERR_GROUP_LEAVE_TOO_LONG,

    /**
     * The parting packet failed to send.
     */
    TOX_ERR_GROUP_LEAVE_FAIL_SEND,
} Tox_Err_Group_Leave;

const char *tox_err_group_leave_to_string(Tox_Err_Group_Leave value);

/**
 * Leaves a group.
 *
 * This function sends a parting packet containing a custom (non-obligatory)
 * message to all peers in a group, and deletes the group from the chat array.
 * All group state information is permanently lost, including keys and role
 * credentials.
 *
 * @param group_number The group number of the group we wish to leave.
 * @param part_message The parting message to be sent to all the peers. Set to
 *   NULL if we do not wish to send a parting message.
 * @param length The length of the parting message. Set to 0 if we do not wish
 *   to send a parting message.
 *
 * @return true if the group chat instance is successfully deleted.
 */
bool tox_group_leave(
    Tox *tox, Tox_Group_Number group_number,
    const uint8_t part_message[], size_t length,
    Tox_Err_Group_Leave *error);

/*******************************************************************************
 *
 * :: Group user-visible client information (nickname/status/role/public key)
 *
 ******************************************************************************/

/**
 * General error codes for self state get and size functions.
 */
typedef enum Tox_Err_Group_Self_Query {

    /**
     * The function returned successfully.
     */
    TOX_ERR_GROUP_SELF_QUERY_OK,

    /**
     * The group number passed did not designate a valid group.
     */
    TOX_ERR_GROUP_SELF_QUERY_GROUP_NOT_FOUND,

} Tox_Err_Group_Self_Query;

const char *tox_err_group_self_query_to_string(Tox_Err_Group_Self_Query value);

/**
 * Error codes for self name setting.
 */
typedef enum Tox_Err_Group_Self_Name_Set {

    /**
     * The function returned successfully.
     */
    TOX_ERR_GROUP_SELF_NAME_SET_OK,

    /**
     * The group number passed did not designate a valid group.
     */
    TOX_ERR_GROUP_SELF_NAME_SET_GROUP_NOT_FOUND,

    /**
     * Name length exceeded TOX_MAX_NAME_LENGTH.
     */
    TOX_ERR_GROUP_SELF_NAME_SET_TOO_LONG,

    /**
     * The length given to the set function is zero or name is a NULL pointer.
     */
    TOX_ERR_GROUP_SELF_NAME_SET_INVALID,

    /**
     * The packet failed to send.
     */
    TOX_ERR_GROUP_SELF_NAME_SET_FAIL_SEND,

} Tox_Err_Group_Self_Name_Set;

const char *tox_err_group_self_name_set_to_string(Tox_Err_Group_Self_Name_Set value);

/**
 * Set the client's nickname for the group instance designated by the given
 * group number.
 *
 * Nickname length cannot exceed TOX_MAX_NAME_LENGTH. If length is equal to
 * zero or name is a NULL pointer, the function call will fail.
 *
 * @param name A byte array containing the new nickname.
 * @param length The size of the name byte array.
 *
 * @return true on success.
 */
bool tox_group_self_set_name(
    Tox *tox, Tox_Group_Number group_number,
    const uint8_t name[], size_t length,
    Tox_Err_Group_Self_Name_Set *error);

/**
 * Return the length of the client's current nickname for the group instance
 * designated by group_number as passed to tox_group_self_set_name.
 *
 * If no nickname was set before calling this function, the name is empty,
 * and this function returns 0.
 *
 * @see threading for concurrency implications.
 */
size_t tox_group_self_get_name_size(const Tox *tox, Tox_Group_Number group_number, Tox_Err_Group_Self_Query *error);

/**
 * Write the nickname set by tox_group_self_set_name to a byte array.
 *
 * If no nickname was set before calling this function, the name is empty,
 * and this function has no effect.
 *
 * Call tox_group_self_get_name_size to find out how much memory to allocate for
 * the result.
 *
 * @param name A valid memory location large enough to hold the nickname.
 *   If this parameter is NULL, the function has no effect.
 *
 * @return true on success.
 */
bool tox_group_self_get_name(
    const Tox *tox, Tox_Group_Number group_number,
    uint8_t name[], Tox_Err_Group_Self_Query *error);

/**
 * Error codes for self status setting.
 */
typedef enum Tox_Err_Group_Self_Status_Set {

    /**
     * The function returned successfully.
     */
    TOX_ERR_GROUP_SELF_STATUS_SET_OK,

    /**
     * The group number passed did not designate a valid group.
     */
    TOX_ERR_GROUP_SELF_STATUS_SET_GROUP_NOT_FOUND,

    /**
     * The packet failed to send.
     */
    TOX_ERR_GROUP_SELF_STATUS_SET_FAIL_SEND,

} Tox_Err_Group_Self_Status_Set;

const char *tox_err_group_self_status_set_to_string(Tox_Err_Group_Self_Status_Set value);

/**
 * Set the client's status for the group instance. Status must be a
 * Tox_User_Status.
 *
 * @return true on success.
 */
bool tox_group_self_set_status(Tox *tox, Tox_Group_Number group_number, Tox_User_Status status,
                               Tox_Err_Group_Self_Status_Set *error);

/**
 * returns the client's status for the group instance on success.
 * return value is unspecified on failure.
 */
Tox_User_Status tox_group_self_get_status(const Tox *tox, Tox_Group_Number group_number, Tox_Err_Group_Self_Query *error);

/**
 * returns the client's role for the group instance on success.
 * return value is unspecified on failure.
 */
Tox_Group_Role tox_group_self_get_role(const Tox *tox, Tox_Group_Number group_number, Tox_Err_Group_Self_Query *error);

/**
 * returns the client's peer id for the group instance on success.
 * return value is unspecified on failure.
 */
Tox_Group_Peer_Number tox_group_self_get_peer_id(const Tox *tox, Tox_Group_Number group_number, Tox_Err_Group_Self_Query *error);

/**
 * Write the client's group public key designated by the given group number to
 * a byte array.
 *
 * This key will be permanently tied to the client's identity for this
 * particular group until the client explicitly leaves the group. This key is
 * the only way for other peers to reliably identify the client across client
 * restarts.
 *
 * `public_key` should have room for at least TOX_GROUP_PEER_PUBLIC_KEY_SIZE
 * bytes.
 *
 * @param public_key A valid memory region large enough to store the public key.
 *   If this parameter is NULL, this function call has no effect.
 *
 * @return true on success.
 */
bool tox_group_self_get_public_key(const Tox *tox, Tox_Group_Number group_number, uint8_t public_key[TOX_PUBLIC_KEY_SIZE],
                                   Tox_Err_Group_Self_Query *error);

/*******************************************************************************
 *
 * :: Peer-specific group state queries.
 *
 ******************************************************************************/

/**
 * Error codes for peer info queries.
 */
typedef enum Tox_Err_Group_Peer_Query {

    /**
     * The function returned successfully.
     */
    TOX_ERR_GROUP_PEER_QUERY_OK,

    /**
     * The group number passed did not designate a valid group.
     */
    TOX_ERR_GROUP_PEER_QUERY_GROUP_NOT_FOUND,

    /**
     * The ID passed did not designate a valid peer.
     */
    TOX_ERR_GROUP_PEER_QUERY_PEER_NOT_FOUND,

} Tox_Err_Group_Peer_Query;

const char *tox_err_group_peer_query_to_string(Tox_Err_Group_Peer_Query value);

/**
 * Return the length of the peer's name. If the group number or ID is invalid,
 * the return value is unspecified.
 *
 * @param group_number The group number of the group we wish to query.
 * @param peer_id The ID of the peer whose name length we want to retrieve.
 *
 * The return value is equal to the `length` argument received by the last
 * `group_peer_name` callback.
 */
size_t tox_group_peer_get_name_size(const Tox *tox, Tox_Group_Number group_number, Tox_Group_Peer_Number peer_id,
                                    Tox_Err_Group_Peer_Query *error);

/**
 * Write the name of the peer designated by the given ID to a byte
 * array.
 *
 * Call tox_group_peer_get_name_size to determine the allocation size for the
 * `name` parameter.
 *
 * The data written to `name` is equal to the data received by the last
 * `group_peer_name` callback.
 *
 * @param group_number The group number of the group we wish to query.
 * @param peer_id The ID of the peer whose name we wish to retrieve.
 * @param name A valid memory region large enough to store the friend's name.
 *
 * @return true on success.
 */
bool tox_group_peer_get_name(
    const Tox *tox, Tox_Group_Number group_number, Tox_Group_Peer_Number peer_id,
    uint8_t name[], Tox_Err_Group_Peer_Query *error);

/**
 * Return the peer's user status (away/busy/...). If the ID or group number is
 * invalid, the return value is unspecified.
 *
 * @param group_number The group number of the group we wish to query.
 * @param peer_id The ID of the peer whose status we wish to query.
 *
 * The status returned is equal to the last status received through the
 * `group_peer_status` callback.
 */
Tox_User_Status tox_group_peer_get_status(const Tox *tox, Tox_Group_Number group_number, Tox_Group_Peer_Number peer_id,
        Tox_Err_Group_Peer_Query *error);

/**
 * Return the peer's role (user/moderator/founder...). If the ID or group number
 * is invalid, the return value is unspecified.
 *
 * @param group_number The group number of the group we wish to query.
 * @param peer_id The ID of the peer whose role we wish to query.
 *
 * The role returned is equal to the last role received through the
 * `group_moderation` callback.
 */
Tox_Group_Role tox_group_peer_get_role(const Tox *tox, Tox_Group_Number group_number, Tox_Group_Peer_Number peer_id,
                                       Tox_Err_Group_Peer_Query *error);

/**
 * Return the type of connection we have established with a peer.
 *
 * If `peer_id` designates ourself, the return value indicates whether we're
 * capable of making UDP connections with other peers, or are limited to TCP
 * connections.
 *
 * @param group_number The group number of the group we wish to query.
 * @param peer_id The ID of the peer whose connection status we wish to query.
 */
Tox_Connection tox_group_peer_get_connection_status(const Tox *tox, Tox_Group_Number group_number, Tox_Group_Peer_Number peer_id,
        Tox_Err_Group_Peer_Query *error);

/**
 * Write the group public key with the designated peer_id for the designated
 * group number to public_key.
 *
 * This key will be permanently tied to a particular peer until they explicitly
 * leave the group and is the only way to reliably identify the same peer across
 * client restarts.
 *
 * `public_key` should have room for at least TOX_GROUP_PEER_PUBLIC_KEY_SIZE
 * bytes. If `public_key` is NULL this function has no effect.
 *
 * @param group_number The group number of the group we wish to query.
 * @param peer_id The ID of the peer whose public key we wish to retrieve.
 * @param public_key A valid memory region large enough to store the public key.
 *   If this parameter is NULL, this function call has no effect.
 *
 * @return true on success.
 */
bool tox_group_peer_get_public_key(
    const Tox *tox, Tox_Group_Number group_number, Tox_Group_Peer_Number peer_id,
    uint8_t public_key[TOX_PUBLIC_KEY_SIZE], Tox_Err_Group_Peer_Query *error);

/**
 * @param group_number The group number of the group the name change is intended
 *   for.
 * @param peer_id The ID of the peer who has changed their name.
 * @param name The name data.
 * @param name_length The length of the name.
 */
typedef void tox_group_peer_name_cb(
    Tox *tox, Tox_Group_Number group_number, Tox_Group_Peer_Number peer_id,
    const uint8_t name[], size_t name_length, void *user_data);

/**
 * Set the callback for the `group_peer_name` event. Pass NULL to unset.
 *
 * This event is triggered when a peer changes their nickname.
 */
void tox_callback_group_peer_name(Tox *tox, tox_group_peer_name_cb *callback);

/**
 * @param group_number The group number of the group the status change is
 *   intended for.
 * @param peer_id The ID of the peer who has changed their status.
 * @param status The new status of the peer.
 */
typedef void tox_group_peer_status_cb(Tox *tox, Tox_Group_Number group_number, Tox_Group_Peer_Number peer_id, Tox_User_Status status,
                                      void *user_data);

/**
 * Set the callback for the `group_peer_status` event. Pass NULL to unset.
 *
 * This event is triggered when a peer changes their status.
 */
void tox_callback_group_peer_status(Tox *tox, tox_group_peer_status_cb *callback);

/*******************************************************************************
 *
 * :: Group chat state queries and events.
 *
 ******************************************************************************/

/**
 * General error codes for group state get and size functions.
 */
typedef enum Tox_Err_Group_State_Query {

    /**
     * The function returned successfully.
     */
    TOX_ERR_GROUP_STATE_QUERY_OK,

    /**
     * The group number passed did not designate a valid group.
     */
    TOX_ERR_GROUP_STATE_QUERY_GROUP_NOT_FOUND,

} Tox_Err_Group_State_Query;

const char *tox_err_group_state_query_to_string(Tox_Err_Group_State_Query value);

/**
 * Error codes for group topic setting.
 */
typedef enum Tox_Err_Group_Topic_Set {

    /**
     * The function returned successfully.
     */
    TOX_ERR_GROUP_TOPIC_SET_OK,

    /**
     * The group number passed did not designate a valid group.
     */
    TOX_ERR_GROUP_TOPIC_SET_GROUP_NOT_FOUND,

    /**
     * Topic length exceeded TOX_GROUP_MAX_TOPIC_LENGTH.
     */
    TOX_ERR_GROUP_TOPIC_SET_TOO_LONG,

    /**
     * The caller does not have the required permissions to set the topic.
     */
    TOX_ERR_GROUP_TOPIC_SET_PERMISSIONS,

    /**
     * The packet could not be created. This error is usually related to
     * cryptographic signing.
     */
    TOX_ERR_GROUP_TOPIC_SET_FAIL_CREATE,

    /**
     * The packet failed to send.
     */
    TOX_ERR_GROUP_TOPIC_SET_FAIL_SEND,

    /**
     * The group is disconnected.
     */
    TOX_ERR_GROUP_TOPIC_SET_DISCONNECTED,

} Tox_Err_Group_Topic_Set;

const char *tox_err_group_topic_set_to_string(Tox_Err_Group_Topic_Set value);

/**
 * Set the group topic and broadcast it to the rest of the group.
 *
 * Topic length cannot be longer than TOX_GROUP_MAX_TOPIC_LENGTH. If the length
 * is equal to zero or topic is set to NULL, the topic will be unset.
 *
 * @return true on success.
 */
bool tox_group_set_topic(
    Tox *tox, Tox_Group_Number group_number,
    const uint8_t topic[], size_t length,
    Tox_Err_Group_Topic_Set *error);

/**
 * Return the length of the group topic. If the group number is invalid, the
 * return value is unspecified.
 *
 * The return value is equal to the `length` argument received by the last
 * `group_topic` callback.
 */
size_t tox_group_get_topic_size(const Tox *tox, Tox_Group_Number group_number, Tox_Err_Group_State_Query *error);

/**
 * Write the topic designated by the given group number to a byte array.
 *
 * Call tox_group_get_topic_size to determine the allocation size for the
 * `topic` parameter.
 *
 * The data written to `topic` is equal to the data received by the last
 * `group_topic` callback.
 *
 * @param topic A valid memory region large enough to store the topic.
 *   If this parameter is NULL, this function has no effect.
 *
 * @return true on success.
 */
bool tox_group_get_topic(
    const Tox *tox, Tox_Group_Number group_number,
    uint8_t topic[], Tox_Err_Group_State_Query *error);

/**
 * @param group_number The group number of the group the topic change is
 *   intended for.
 * @param peer_id The ID of the peer who changed the topic. If the peer who set
 *   the topic is not present in our peer list this value will be set to 0.
 * @param topic The topic data.
 * @param topic_length The topic length.
 */
typedef void tox_group_topic_cb(
    Tox *tox, Tox_Group_Number group_number, Tox_Group_Peer_Number peer_id,
    const uint8_t topic[], size_t topic_length,
    void *user_data);

/**
 * Set the callback for the `group_topic` event. Pass NULL to unset.
 *
 * This event is triggered when a peer changes the group topic.
 */
void tox_callback_group_topic(Tox *tox, tox_group_topic_cb *callback);

/**
 * Return the length of the group name. If the group number is invalid, the
 * return value is unspecified.
 */
size_t tox_group_get_name_size(const Tox *tox, Tox_Group_Number group_number, Tox_Err_Group_State_Query *error);

/**
 * Write the name of the group designated by the given group number to a byte
 * array.
 *
 * Call tox_group_get_name_size to determine the allocation size for the `name`
 * parameter.
 *
 * @param name A valid memory region large enough to store the group name.
 *   If this parameter is NULL, this function call has no effect.
 *
 * @return true on success.
 */
bool tox_group_get_name(
    const Tox *tox, Tox_Group_Number group_number,
    uint8_t name[], Tox_Err_Group_State_Query *error);

/**
 * Write the Chat ID designated by the given group number to a byte array.
 *
 * `chat_id` should have room for at least TOX_GROUP_CHAT_ID_SIZE bytes.
 *
 * @param chat_id A valid memory region large enough to store the Chat ID.
 *   If this parameter is NULL, this function call has no effect.
 *
 * @return true on success.
 */
bool tox_group_get_chat_id(
    const Tox *tox, Tox_Group_Number group_number, uint8_t chat_id[TOX_GROUP_CHAT_ID_SIZE],
    Tox_Err_Group_State_Query *error);

/**
 * Return the number of groups in the Tox chats array.
 */
uint32_t tox_group_get_number_groups(const Tox *tox);

/**
 * Return the privacy state of the group designated by the given group number.
 * If group number is invalid, the return value is unspecified.
 *
 * The value returned is equal to the data received by the last
 * `group_privacy_state` callback.
 *
 * @see the `Group chat Founder controls` section for the respective set
 *   function.
 */
Tox_Group_Privacy_State tox_group_get_privacy_state(const Tox *tox, Tox_Group_Number group_number,
        Tox_Err_Group_State_Query *error);

/**
 * @param group_number The group number of the group the privacy state is
 *   intended for.
 * @param privacy_state The new privacy state.
 */
typedef void tox_group_privacy_state_cb(Tox *tox, Tox_Group_Number group_number, Tox_Group_Privacy_State privacy_state,
                                        void *user_data);

/**
 * Set the callback for the `group_privacy_state` event. Pass NULL to unset.
 *
 * This event is triggered when the group founder changes the privacy state.
 */
void tox_callback_group_privacy_state(Tox *tox, tox_group_privacy_state_cb *callback);

/**
 * Return the voice state of the group designated by the given group number. If
 * group number is invalid, the return value is unspecified.
 *
 * The value returned is equal to the data received by the last
 * `group_voice_state` callback.
 *
 * @see the `Group chat Founder controls` section for the respective set
 *   function.
 */
Tox_Group_Voice_State tox_group_get_voice_state(const Tox *tox, Tox_Group_Number group_number,
        Tox_Err_Group_State_Query *error);

/**
 * @param group_number The group number of the group the voice state change is
 *   intended for.
 * @param voice_state The new voice state.
 */
typedef void tox_group_voice_state_cb(Tox *tox, Tox_Group_Number group_number, Tox_Group_Voice_State voice_state,
                                      void *user_data);

/**
 * Set the callback for the `group_privacy_state` event. Pass NULL to unset.
 *
 * This event is triggered when the group founder changes the voice state.
 */
void tox_callback_group_voice_state(Tox *tox, tox_group_voice_state_cb *callback);

/**
 * Return the topic lock status of the group designated by the given group
 * number. If group number
 * is invalid, the return value is unspecified.
 *
 * The value returned is equal to the data received by the last
 * `group_topic_lock` callback.
 *
 * @see the `Group chat Founder controls` section for the respective set
 *   function.
 */
Tox_Group_Topic_Lock tox_group_get_topic_lock(const Tox *tox, Tox_Group_Number group_number,
        Tox_Err_Group_State_Query *error);

/**
 * @param group_number The group number of the group for which the topic lock
 *   has changed.
 * @param topic_lock The new topic lock state.
 */
typedef void tox_group_topic_lock_cb(Tox *tox, Tox_Group_Number group_number, Tox_Group_Topic_Lock topic_lock, void *user_data);

/**
 * Set the callback for the `group_topic_lock` event. Pass NULL to unset.
 *
 * This event is triggered when the group founder changes the topic lock status.
 */
void tox_callback_group_topic_lock(Tox *tox, tox_group_topic_lock_cb *callback);

/**
 * Return the maximum number of peers allowed for the group designated by the
 * given group number. If the group number is invalid, the return value is
 * unspecified.
 *
 * The value returned is equal to the data received by the last
 * `group_peer_limit` callback.
 *
 * @see the `Group chat Founder controls` section for the respective set
 *   function.
 */
uint16_t tox_group_get_peer_limit(const Tox *tox, Tox_Group_Number group_number, Tox_Err_Group_State_Query *error);

/**
 * @param group_number The group number of the group for which the peer limit
 *   has changed.
 * @param peer_limit The new peer limit for the group.
 */
typedef void tox_group_peer_limit_cb(Tox *tox, Tox_Group_Number group_number, uint32_t peer_limit, void *user_data);

/**
 * Set the callback for the `group_peer_limit` event. Pass NULL to unset.
 *
 * This event is triggered when the group founder changes the maximum peer
 * limit.
 */
void tox_callback_group_peer_limit(Tox *tox, tox_group_peer_limit_cb *callback);

/**
 * Return the length of the group password. If the group number is invalid, the
 * return value is unspecified.
 */
size_t tox_group_get_password_size(const Tox *tox, Tox_Group_Number group_number, Tox_Err_Group_State_Query *error);

/**
 * Write the password for the group designated by the given group number to a
 * byte array.
 *
 * Call tox_group_get_password_size to determine the allocation size for the
 * `password` parameter.
 *
 * The data received is equal to the data received by the last `group_password`
 * callback.
 *
 * @see the `Group chat Founder controls` section for the respective set
 *   function.
 *
 * @param password A valid memory region large enough to store the group
 *   password. If this parameter is NULL, this function call has no effect.
 *
 * @return true on success.
 */
bool tox_group_get_password(
    const Tox *tox, Tox_Group_Number group_number, uint8_t password[],
    Tox_Err_Group_State_Query *error);

/**
 * @param group_number The group number of the group for which the password has
 *   changed.
 * @param password The new group password.
 * @param password_length The length of the password.
 */
typedef void tox_group_password_cb(
    Tox *tox, Tox_Group_Number group_number,
    const uint8_t password[], size_t password_length,
    void *user_data);

/**
 * Set the callback for the `group_password` event. Pass NULL to unset.
 *
 * This event is triggered when the group founder changes the group password.
 */
void tox_callback_group_password(Tox *tox, tox_group_password_cb *callback);

/*******************************************************************************
 *
 * :: Group chat message sending
 *
 ******************************************************************************/

typedef enum Tox_Err_Group_Send_Message {

    /**
     * The function returned successfully.
     */
    TOX_ERR_GROUP_SEND_MESSAGE_OK,

    /**
     * The group number passed did not designate a valid group.
     */
    TOX_ERR_GROUP_SEND_MESSAGE_GROUP_NOT_FOUND,

    /**
     * Message length exceeded TOX_GROUP_MAX_MESSAGE_LENGTH.
     */
    TOX_ERR_GROUP_SEND_MESSAGE_TOO_LONG,

    /**
     * The message pointer is NULL or length is zero.
     */
    TOX_ERR_GROUP_SEND_MESSAGE_EMPTY,

    /**
     * The message type is invalid.
     */
    TOX_ERR_GROUP_SEND_MESSAGE_BAD_TYPE,

    /**
     * The caller does not have the required permissions to send group messages.
     */
    TOX_ERR_GROUP_SEND_MESSAGE_PERMISSIONS,

    /**
     * Packet failed to send.
     */
    TOX_ERR_GROUP_SEND_MESSAGE_FAIL_SEND,

    /**
     * The group is disconnected.
     */
    TOX_ERR_GROUP_SEND_MESSAGE_DISCONNECTED,

} Tox_Err_Group_Send_Message;

const char *tox_err_group_send_message_to_string(Tox_Err_Group_Send_Message value);

/**
 * Send a text chat message to the group.
 *
 * This function creates a group message packet and pushes it into the send
 * queue.
 *
 * The message length may not exceed TOX_GROUP_MAX_MESSAGE_LENGTH. Larger
 * messages must be split by the client and sent as separate messages. Other
 * clients can then reassemble the fragments. Messages may not be empty.
 *
 * @param group_number The group number of the group the message is intended
 *   for.
 * @param message_type Message type (normal, action, ...).
 * @param message A non-NULL pointer to the first element of a byte array
 *   containing the message text.
 * @param length Length of the message to be sent.
 *
 * @return The message_id of this message. If this function has an error, the
 *   returned message ID value will be undefined.
 */
Tox_Group_Message_Id tox_group_send_message(
    const Tox *tox, Tox_Group_Number group_number, Tox_Message_Type message_type,
    const uint8_t message[], size_t length,
    Tox_Err_Group_Send_Message *error);

typedef enum Tox_Err_Group_Send_Private_Message {

    /**
     * The function returned successfully.
     */
    TOX_ERR_GROUP_SEND_PRIVATE_MESSAGE_OK,

    /**
     * The group number passed did not designate a valid group.
     */
    TOX_ERR_GROUP_SEND_PRIVATE_MESSAGE_GROUP_NOT_FOUND,

    /**
     * The peer ID passed did not designate a valid peer.
     */
    TOX_ERR_GROUP_SEND_PRIVATE_MESSAGE_PEER_NOT_FOUND,

    /**
     * Message length exceeded TOX_GROUP_MAX_MESSAGE_LENGTH.
     */
    TOX_ERR_GROUP_SEND_PRIVATE_MESSAGE_TOO_LONG,

    /**
     * The message pointer is NULL or length is zero.
     */
    TOX_ERR_GROUP_SEND_PRIVATE_MESSAGE_EMPTY,

    /**
     * The message type is invalid.
     */
    TOX_ERR_GROUP_SEND_PRIVATE_MESSAGE_BAD_TYPE,

    /**
     * The caller does not have the required permissions to send group messages.
     */
    TOX_ERR_GROUP_SEND_PRIVATE_MESSAGE_PERMISSIONS,

    /**
     * Packet failed to send.
     */
    TOX_ERR_GROUP_SEND_PRIVATE_MESSAGE_FAIL_SEND,

    /**
     * The group is disconnected.
     */
    TOX_ERR_GROUP_SEND_PRIVATE_MESSAGE_DISCONNECTED,

} Tox_Err_Group_Send_Private_Message;

const char *tox_err_group_send_private_message_to_string(Tox_Err_Group_Send_Private_Message value);

/**
 * Send a text chat message to the specified peer in the specified group.
 *
 * This function creates a group private message packet and pushes it into the
 * send queue.
 *
 * The message length may not exceed TOX_GROUP_MAX_MESSAGE_LENGTH. Larger
 * messages must be split by the client and sent as separate messages. Other
 * clients can then reassemble the fragments. Messages may not be empty.
 *
 * @param group_number The group number of the group the message is intended
 *   for.
 * @param peer_id The ID of the peer the message is intended for.
 * @param message_type The type of message (normal, action, ...).
 * @param message A non-NULL pointer to the first element of a byte array
 *   containing the message text.
 * @param length Length of the message to be sent.
 *
 * @return true on success.
 */
Tox_Group_Message_Id tox_group_send_private_message(
    const Tox *tox, Tox_Group_Number group_number, Tox_Group_Peer_Number peer_id, Tox_Message_Type message_type,
    const uint8_t message[], size_t length,
    Tox_Err_Group_Send_Private_Message *error);

typedef enum Tox_Err_Group_Send_Custom_Packet {

    /**
     * The function returned successfully.
     */
    TOX_ERR_GROUP_SEND_CUSTOM_PACKET_OK,

    /**
     * The group number passed did not designate a valid group.
     */
    TOX_ERR_GROUP_SEND_CUSTOM_PACKET_GROUP_NOT_FOUND,

    /**
     * Message length exceeded TOX_GROUP_MAX_CUSTOM_LOSSY_PACKET_LENGTH if the
     * packet was lossy, or TOX_GROUP_MAX_CUSTOM_LOSSLESS_PACKET_LENGTH if the
     * packet was lossless.
     */
    TOX_ERR_GROUP_SEND_CUSTOM_PACKET_TOO_LONG,

    /**
     * The message pointer is NULL or length is zero.
     */
    TOX_ERR_GROUP_SEND_CUSTOM_PACKET_EMPTY,

    /**
     * The group is disconnected.
     */
    TOX_ERR_GROUP_SEND_CUSTOM_PACKET_DISCONNECTED,

    /**
     * The packet did not successfully send to any peer. This often indicates
     * a connection issue on the sender's side.
     */
    TOX_ERR_GROUP_SEND_CUSTOM_PACKET_FAIL_SEND,

} Tox_Err_Group_Send_Custom_Packet;

const char *tox_err_group_send_custom_packet_to_string(Tox_Err_Group_Send_Custom_Packet value);

/**
 * Send a custom packet to the group.
 *
 * If lossless is true the packet will be lossless. Lossless packet behaviour is
 * comparable to TCP (reliability, arrive in order) but with packets instead of
 * a stream.
 *
 * If lossless is false, the packet will be lossy. Lossy packets behave like UDP
 * packets, meaning they might never reach the other side or might arrive more
 * than once (if someone is messing with the connection) or might arrive in the
 * wrong order.
 *
 * Unless latency is an issue or message reliability is not important, it is
 * recommended that you use lossless packets.
 *
 * The message length may not exceed TOX_MAX_CUSTOM_PACKET_SIZE. Larger packets
 * must be split by the client and sent as separate packets. Other clients can
 * then reassemble the fragments. Packets may not be empty.
 *
 * @param group_number The group number of the group the packet is intended for.
 * @param lossless True if the packet should be lossless.
 * @param data A byte array containing the packet data.
 * @param length The length of the packet data byte array.
 *
 * @return true on success.
 */
bool tox_group_send_custom_packet(
    const Tox *tox, Tox_Group_Number group_number, bool lossless,
    const uint8_t data[], size_t length,
    Tox_Err_Group_Send_Custom_Packet *error);

typedef enum Tox_Err_Group_Send_Custom_Private_Packet {

    /**
     * The function returned successfully.
     */
    TOX_ERR_GROUP_SEND_CUSTOM_PRIVATE_PACKET_OK,

    /**
     * The group number passed did not designate a valid group.
     */
    TOX_ERR_GROUP_SEND_CUSTOM_PRIVATE_PACKET_GROUP_NOT_FOUND,

    /**
     * Message length exceeded TOX_GROUP_MAX_CUSTOM_LOSSY_PACKET_LENGTH if the
     * packet was lossy, or TOX_GROUP_MAX_CUSTOM_LOSSLESS_PACKET_LENGTH if the
     * packet was lossless.
     */
    TOX_ERR_GROUP_SEND_CUSTOM_PRIVATE_PACKET_TOO_LONG,

    /**
     * The message pointer is NULL or length is zero.
     */
    TOX_ERR_GROUP_SEND_CUSTOM_PRIVATE_PACKET_EMPTY,

    /**
     * The peer ID passed did no designate a valid peer.
     */
    TOX_ERR_GROUP_SEND_CUSTOM_PRIVATE_PACKET_PEER_NOT_FOUND,

    /**
     * The packet failed to send.
     */
    TOX_ERR_GROUP_SEND_CUSTOM_PRIVATE_PACKET_FAIL_SEND,

    /**
     * The group is disconnected.
     */
    TOX_ERR_GROUP_SEND_CUSTOM_PRIVATE_PACKET_DISCONNECTED,

} Tox_Err_Group_Send_Custom_Private_Packet;

const char *tox_err_group_send_custom_private_packet_to_string(Tox_Err_Group_Send_Custom_Private_Packet value);

/**
 * Send a custom private packet to a designated peer in the group.
 *
 * If lossless is true the packet will be lossless. Lossless packet behaviour is
 * comparable to TCP (reliability, arrive in order) but with packets instead of
 * a stream.
 *
 * If lossless is false, the packet will be lossy. Lossy packets behave like UDP
 * packets, meaning they might never reach the other side or might arrive more
 * than once (if someone is messing with the connection) or might arrive in the
 * wrong order.
 *
 * Unless latency is an issue or message reliability is not important, it is
 * recommended that you use lossless packets.
 *
 * The packet length may not exceed TOX_MAX_CUSTOM_PACKET_SIZE. Larger packets
 * must be split by the client and sent as separate packets. Other clients can
 * then reassemble the fragments. Packets may not be empty.
 *
 * @param group_number The group number of the group the packet is intended for.
 * @param peer_id The ID of the peer the packet is intended for.
 * @param lossless True if the packet should be lossless.
 * @param data A byte array containing the packet data.
 * @param length The length of the packet data byte array.
 *
 * @return true on success.
 */
bool tox_group_send_custom_private_packet(const Tox *tox, Tox_Group_Number group_number, Tox_Group_Peer_Number peer_id, bool lossless,
        const uint8_t data[], size_t length,
        Tox_Err_Group_Send_Custom_Private_Packet *error);

/*******************************************************************************
 *
 * :: Group chat message receiving
 *
 ******************************************************************************/

/**
 * @param group_number The group number of the group the message is intended
 *   for.
 * @param peer_id The ID of the peer who sent the message.
 * @param message_type The type of message (normal, action, ...).
 * @param message The message data.
 * @param message_length The length of the message.
 * @param message_id A pseudo message id that clients can use to uniquely
 *   identify this group message.
 */
typedef void tox_group_message_cb(
    Tox *tox, Tox_Group_Number group_number, Tox_Group_Peer_Number peer_id, Tox_Message_Type message_type,
    const uint8_t message[], size_t message_length, Tox_Group_Message_Id message_id, void *user_data);

/**
 * Set the callback for the `group_message` event. Pass NULL to unset.
 *
 * This event is triggered when the client receives a group message.
 */
void tox_callback_group_message(Tox *tox, tox_group_message_cb *callback);

/**
 * @param group_number The group number of the group the private message is
 *   intended for.
 * @param peer_id The ID of the peer who sent the private message.
 * @param message_type The type of message (normal, action, ...).
 * @param message The message data.
 * @param message_length The length of the message.
 * @param message_id A pseudo message id that clients can use to uniquely
 *   identify this group message.
 */
typedef void tox_group_private_message_cb(
    Tox *tox, Tox_Group_Number group_number, Tox_Group_Peer_Number peer_id, Tox_Message_Type message_type,
    const uint8_t message[], size_t message_length, Tox_Group_Message_Id message_id, void *user_data);

/**
 * Set the callback for the `group_private_message` event. Pass NULL to unset.
 *
 * This event is triggered when the client receives a private message.
 */
void tox_callback_group_private_message(Tox *tox, tox_group_private_message_cb *callback);

/**
 * @param group_number The group number of the group the packet is intended for.
 * @param peer_id The ID of the peer who sent the packet.
 * @param data The packet data.
 * @param data_length The length of the data.
 */
typedef void tox_group_custom_packet_cb(
    Tox *tox, Tox_Group_Number group_number, Tox_Group_Peer_Number peer_id,
    const uint8_t data[], size_t data_length, void *user_data);

/**
 * Set the callback for the `group_custom_packet` event. Pass NULL to unset.
 *
 * This event is triggered when the client receives a custom packet.
 */
void tox_callback_group_custom_packet(Tox *tox, tox_group_custom_packet_cb *callback);

/**
 * @param group_number The group number of the group the packet is intended for.
 * @param peer_id The ID of the peer who sent the packet.
 * @param data The packet data.
 * @param data_length The length of the data.
 */
typedef void tox_group_custom_private_packet_cb(
    Tox *tox, Tox_Group_Number group_number, Tox_Group_Peer_Number peer_id,
    const uint8_t data[], size_t data_length, void *user_data);

/**
 * Set the callback for the `group_custom_private_packet` event. Pass NULL to
 * unset.
 *
 * This event is triggered when the client receives a custom private packet.
 */
void tox_callback_group_custom_private_packet(Tox *tox, tox_group_custom_private_packet_cb *callback);

/*******************************************************************************
 *
 * :: Group chat inviting and join/part events
 *
 ******************************************************************************/

typedef enum Tox_Err_Group_Invite_Friend {

    /**
     * The function returned successfully.
     */
    TOX_ERR_GROUP_INVITE_FRIEND_OK,

    /**
     * The group number passed did not designate a valid group.
     */
    TOX_ERR_GROUP_INVITE_FRIEND_GROUP_NOT_FOUND,

    /**
     * The friend number passed did not designate a valid friend.
     */
    TOX_ERR_GROUP_INVITE_FRIEND_FRIEND_NOT_FOUND,

    /**
     * Creation of the invite packet failed. This indicates a network related
     * error.
     */
    TOX_ERR_GROUP_INVITE_FRIEND_INVITE_FAIL,

    /**
     * Packet failed to send.
     */
    TOX_ERR_GROUP_INVITE_FRIEND_FAIL_SEND,

    /**
     * The group is disconnected.
     */
    TOX_ERR_GROUP_INVITE_FRIEND_DISCONNECTED,

} Tox_Err_Group_Invite_Friend;

const char *tox_err_group_invite_friend_to_string(Tox_Err_Group_Invite_Friend value);

/**
 * Invite a friend to a group.
 *
 * This function creates an invite request packet and pushes it to the send
 * queue.
 *
 * @param group_number The group number of the group the message is intended
 *   for.
 * @param friend_number The friend number of the friend the invite is intended
 *   for.
 *
 * @return true on success.
 */
bool tox_group_invite_friend(
    const Tox *tox, Tox_Group_Number group_number, Tox_Friend_Number friend_number,
    Tox_Err_Group_Invite_Friend *error);

typedef enum Tox_Err_Group_Invite_Accept {

    /**
     * The function returned successfully.
     */
    TOX_ERR_GROUP_INVITE_ACCEPT_OK,

    /**
     * The invite data is not in the expected format.
     */
    TOX_ERR_GROUP_INVITE_ACCEPT_BAD_INVITE,

    /**
     * The group instance failed to initialize.
     */
    TOX_ERR_GROUP_INVITE_ACCEPT_INIT_FAILED,

    /**
     * name exceeds TOX_MAX_NAME_LENGTH
     */
    TOX_ERR_GROUP_INVITE_ACCEPT_TOO_LONG,

    /**
     * name is NULL or name_length is zero.
     */
    TOX_ERR_GROUP_INVITE_ACCEPT_EMPTY,

    /**
     * Failed to set password. This usually occurs if the password exceeds
     * TOX_GROUP_MAX_PASSWORD_SIZE.
     */
    TOX_ERR_GROUP_INVITE_ACCEPT_PASSWORD,

    /**
     * The friend number passed did not designate a valid friend.
     */
    TOX_ERR_GROUP_INVITE_ACCEPT_FRIEND_NOT_FOUND,

    /**
     * Packet failed to send.
     */
    TOX_ERR_GROUP_INVITE_ACCEPT_FAIL_SEND,

    /**
     * Invite data or name is NULL.
     */
    TOX_ERR_GROUP_INVITE_ACCEPT_NULL,

} Tox_Err_Group_Invite_Accept;

const char *tox_err_group_invite_accept_to_string(Tox_Err_Group_Invite_Accept value);

/**
 * Accept an invite to a group chat that the client previously received from a
 * friend. The invite is only valid while the inviter is present in the group.
 *
 * @param invite_data The invite data received from the `group_invite` event.
 * @param length The length of the invite data.
 * @param name The name of the peer joining the group.
 * @param name_length The length of the peer's name. This must be greater than
 *   zero and no larger than TOX_MAX_NAME_LENGTH.
 * @param password The password required to join the group. Set to NULL if no
 *   password is required.
 * @param password_length The length of the password. If password_length is
 *   equal to zero, the password parameter will be ignored. password_length
 *   must be no larger than TOX_GROUP_MAX_PASSWORD_SIZE.
 *
 * @return the group_number on success, UINT32_MAX on failure.
 */
Tox_Group_Number tox_group_invite_accept(
    Tox *tox, Tox_Friend_Number friend_number,
    const uint8_t invite_data[], size_t length,
    const uint8_t name[], size_t name_length,
    const uint8_t password[], size_t password_length,
    Tox_Err_Group_Invite_Accept *error);

/**
 * @param friend_number The friend number of the contact who sent the invite.
 * @param invite_data The invite data.
 * @param invite_data_length The length of invite_data.
 * @param group_name The name of the group. In conferences, this is "title".
 * @param group_name_length The length of the group name.
 */
typedef void tox_group_invite_cb(
    Tox *tox, Tox_Friend_Number friend_number,
    const uint8_t invite_data[], size_t invite_data_length,
    const uint8_t group_name[], size_t group_name_length,
    void *user_data);

/**
 * Set the callback for the `group_invite` event. Pass NULL to unset.
 *
 * This event is triggered when the client receives a group invite from a
 * friend. The client must store invite_data which is used to join the group
 * via tox_group_invite_accept.
 */
void tox_callback_group_invite(Tox *tox, tox_group_invite_cb *callback);

/**
 * @param group_number The group number of the group in which a new peer has
 *   joined.
 * @param peer_id The permanent ID of the new peer. This id should not be relied
 *   on for client behaviour and should be treated as a random value.
 */
typedef void tox_group_peer_join_cb(Tox *tox, Tox_Group_Number group_number, Tox_Group_Peer_Number peer_id, void *user_data);

/**
 * Set the callback for the `group_peer_join` event. Pass NULL to unset.
 *
 * This event is triggered when a peer other than self joins the group.
 */
void tox_callback_group_peer_join(Tox *tox, tox_group_peer_join_cb *callback);

/**
 * Represents peer exit events. These should be used with the `group_peer_exit`
 * event.
 */
typedef enum Tox_Group_Exit_Type {

    /**
     * The peer has quit the group.
     */
    TOX_GROUP_EXIT_TYPE_QUIT,

    /**
     * Your connection with this peer has timed out.
     */
    TOX_GROUP_EXIT_TYPE_TIMEOUT,

    /**
     * Your connection with this peer has been severed.
     */
    TOX_GROUP_EXIT_TYPE_DISCONNECTED,

    /**
     * Your connection with all peers has been severed. This will occur when you
     * are kicked from a group, rejoin a group, or manually disconnect from a
     * group.
     */
    TOX_GROUP_EXIT_TYPE_SELF_DISCONNECTED,

    /**
     * The peer has been kicked.
     */
    TOX_GROUP_EXIT_TYPE_KICK,

    /**
     * The peer provided invalid group sync information.
     */
    TOX_GROUP_EXIT_TYPE_SYNC_ERROR,

} Tox_Group_Exit_Type;

const char *tox_group_exit_type_to_string(Tox_Group_Exit_Type value);

/**
 * @param group_number The group number of the group in which a peer has left.
 * @param peer_id The ID of the peer who left the group. This ID no longer
 *   designates a valid peer and cannot be used for API calls.
 * @param exit_type The type of exit event. One of Tox_Group_Exit_Type.
 * @param name The nickname of the peer who left the group.
 * @param name_length The length of the peer name.
 * @param part_message The parting message data.
 * @param part_message_length The length of the parting message.
 */
typedef void tox_group_peer_exit_cb(
    Tox *tox, Tox_Group_Number group_number, Tox_Group_Peer_Number peer_id, Tox_Group_Exit_Type exit_type,
    const uint8_t name[], size_t name_length,
    const uint8_t part_message[], size_t part_message_length, void *user_data);

/**
 * Set the callback for the `group_peer_exit` event. Pass NULL to unset.
 *
 * This event is triggered when a peer other than self exits the group.
 */
void tox_callback_group_peer_exit(Tox *tox, tox_group_peer_exit_cb *callback);

/**
 * @param group_number The group number of the group that the client has joined.
 */
typedef void tox_group_self_join_cb(Tox *tox, Tox_Group_Number group_number, void *user_data);

/**
 * Set the callback for the `group_self_join` event. Pass NULL to unset.
 *
 * This event is triggered when the client has successfully joined a group. Use
 * this to initialize any group information the client may need.
 */
void tox_callback_group_self_join(Tox *tox, tox_group_self_join_cb *callback);

/**
 * Represents types of failed group join attempts. These are used in the
 * tox_callback_group_rejected callback when a peer fails to join a group.
 */
typedef enum Tox_Group_Join_Fail {

    /**
     * The group peer limit has been reached.
     */
    TOX_GROUP_JOIN_FAIL_PEER_LIMIT,

    /**
     * You have supplied an invalid password.
     */
    TOX_GROUP_JOIN_FAIL_INVALID_PASSWORD,

    /**
     * The join attempt failed due to an unspecified error. This often occurs
     * when the group is not found in the DHT.
     */
    TOX_GROUP_JOIN_FAIL_UNKNOWN,

} Tox_Group_Join_Fail;

const char *tox_group_join_fail_to_string(Tox_Group_Join_Fail value);

/**
 * @param group_number The group number of the group for which the join has
 *   failed.
 * @param fail_type The type of group rejection.
 */
typedef void tox_group_join_fail_cb(Tox *tox, Tox_Group_Number group_number, Tox_Group_Join_Fail fail_type, void *user_data);

/**
 * Set the callback for the `group_join_fail` event. Pass NULL to unset.
 *
 * This event is triggered when the client fails to join a group.
 */
void tox_callback_group_join_fail(Tox *tox, tox_group_join_fail_cb *callback);

/*******************************************************************************
 *
 * :: Group chat Founder controls
 *
 ******************************************************************************/

typedef enum Tox_Err_Group_Set_Password {

    /**
     * The function returned successfully.
     */
    TOX_ERR_GROUP_SET_PASSWORD_OK,

    /**
     * The group number passed did not designate a valid group.
     */
    TOX_ERR_GROUP_SET_PASSWORD_GROUP_NOT_FOUND,

    /**
     * The caller does not have the required permissions to set the password.
     */
    TOX_ERR_GROUP_SET_PASSWORD_PERMISSIONS,

    /**
     * Password length exceeded TOX_GROUP_MAX_PASSWORD_SIZE.
     */
    TOX_ERR_GROUP_SET_PASSWORD_TOO_LONG,

    /**
     * The packet failed to send.
     */
    TOX_ERR_GROUP_SET_PASSWORD_FAIL_SEND,

    /**
     * The function failed to allocate enough memory for the operation.
     */
    TOX_ERR_GROUP_SET_PASSWORD_MALLOC,

    /**
     * The group is disconnected.
     */
    TOX_ERR_GROUP_SET_PASSWORD_DISCONNECTED,

} Tox_Err_Group_Set_Password;

const char *tox_err_group_set_password_to_string(Tox_Err_Group_Set_Password value);

/**
 * Set or unset the group password.
 *
 * This function allows Founders to set or unset a group password. It will
 * create a new group shared state including the change and distribute it to the
 * rest of the group.
 *
 * @param group_number The group number of the group for which we wish to set
 *   the password.
 * @param password The password we want to set. Set password to NULL to unset
 *   the password.
 * @param length The length of the password. length must be no longer than
 *   TOX_GROUP_MAX_PASSWORD_SIZE.
 *
 * @return true on success.
 */
bool tox_group_set_password(
    Tox *tox, Tox_Group_Number group_number,
    const uint8_t password[], size_t length,
    Tox_Err_Group_Set_Password *error);

typedef enum Tox_Err_Group_Set_Topic_Lock {

    /**
     * The function returned successfully.
     */
    TOX_ERR_GROUP_SET_TOPIC_LOCK_OK,

    /**
     * The group number passed did not designate a valid group.
     */
    TOX_ERR_GROUP_SET_TOPIC_LOCK_GROUP_NOT_FOUND,

    /**
     * Tox_Group_Topic_Lock is an invalid type.
     */
    TOX_ERR_GROUP_SET_TOPIC_LOCK_INVALID,

    /**
     * The caller does not have the required permissions to set the topic lock.
     */
    TOX_ERR_GROUP_SET_TOPIC_LOCK_PERMISSIONS,

    /**
     * The topic lock could not be set. This may occur due to an error related
     * to cryptographic signing of the new shared state.
     */
    TOX_ERR_GROUP_SET_TOPIC_LOCK_FAIL_SET,

    /**
     * The packet failed to send.
     */
    TOX_ERR_GROUP_SET_TOPIC_LOCK_FAIL_SEND,

    /**
     * The group is disconnected.
     */
    TOX_ERR_GROUP_SET_TOPIC_LOCK_DISCONNECTED,

} Tox_Err_Group_Set_Topic_Lock;

const char *tox_err_group_set_topic_lock_to_string(Tox_Err_Group_Set_Topic_Lock value);

/**
 * Set the group topic lock state.
 *
 * This function allows Founders to enable or disable the group's topic lock. It
 * will create a new shared state including the change and distribute it to the
 * rest of the group.
 *
 * When the topic lock is enabled, only the group founder and moderators may set
 * the topic.  When disabled, all peers except those with the observer role may
 * set the topic.
 *
 * @param group_number The group number of the group for which we wish to change
 *   the topic lock state.
 * @param topic_lock The state we wish to set the topic lock to.
 *
 * @return true on success.
 */
bool tox_group_set_topic_lock(Tox *tox, Tox_Group_Number group_number, Tox_Group_Topic_Lock topic_lock,
                              Tox_Err_Group_Set_Topic_Lock *error);

typedef enum Tox_Err_Group_Set_Voice_State {

    /**
     * The function returned successfully.
     */
    TOX_ERR_GROUP_SET_VOICE_STATE_OK,

    /**
     * The group number passed did not designate a valid group.
     */
    TOX_ERR_GROUP_SET_VOICE_STATE_GROUP_NOT_FOUND,

    /**
     * The caller does not have the required permissions to set the privacy
     * state.
     */
    TOX_ERR_GROUP_SET_VOICE_STATE_PERMISSIONS,

    /**
     * The voice state could not be set. This may occur due to an error related
     * to cryptographic signing of the new shared state.
     */
    TOX_ERR_GROUP_SET_VOICE_STATE_FAIL_SET,

    /**
     * The packet failed to send.
     */
    TOX_ERR_GROUP_SET_VOICE_STATE_FAIL_SEND,

    /**
     * The group is disconnected.
     */
    TOX_ERR_GROUP_SET_VOICE_STATE_DISCONNECTED,

} Tox_Err_Group_Set_Voice_State;

const char *tox_err_group_set_voice_state_to_string(Tox_Err_Group_Set_Voice_State value);

/**
 * Set the group voice state.
 *
 * This function allows Founders to set the group's voice state. It will create
 * a new group shared state including the change and distribute it to the rest
 * of the group.
 *
 * If an attempt is made to set the voice state to the same state that the group
 * is already in, the function call will be successful and no action will be
 * taken.
 *
 * @param group_number The group number of the group for which we wish to change
 *   the voice state.
 * @param voice_state The voice state we wish to set the group to.
 *
 * @return true on success.
 */
bool tox_group_set_voice_state(Tox *tox, Tox_Group_Number group_number, Tox_Group_Voice_State voice_state,
                               Tox_Err_Group_Set_Voice_State *error);

typedef enum Tox_Err_Group_Set_Privacy_State {

    /**
     * The function returned successfully.
     */
    TOX_ERR_GROUP_SET_PRIVACY_STATE_OK,

    /**
     * The group number passed did not designate a valid group.
     */
    TOX_ERR_GROUP_SET_PRIVACY_STATE_GROUP_NOT_FOUND,

    /**
     * The caller does not have the required permissions to set the privacy
     * state.
     */
    TOX_ERR_GROUP_SET_PRIVACY_STATE_PERMISSIONS,

    /**
     * The privacy state could not be set. This may occur due to an error
     * related to cryptographic signing of the new shared state.
     */
    TOX_ERR_GROUP_SET_PRIVACY_STATE_FAIL_SET,

    /**
     * The packet failed to send.
     */
    TOX_ERR_GROUP_SET_PRIVACY_STATE_FAIL_SEND,

    /**
     * The group is disconnected.
     */
    TOX_ERR_GROUP_SET_PRIVACY_STATE_DISCONNECTED,

} Tox_Err_Group_Set_Privacy_State;

const char *tox_err_group_set_privacy_state_to_string(Tox_Err_Group_Set_Privacy_State value);

/**
 * Set the group privacy state.
 *
 * This function allows Founders to set the group's privacy state. It will
 * create a new group shared state including the change and distribute it to the
 * rest of the group.
 *
 * If an attempt is made to set the privacy state to the same state that the
 * group is already in, the function call will be successful and no action will
 * be taken.
 *
 * @param group_number The group number of the group for which we wish to change
 *   the privacy state.
 * @param privacy_state The privacy state we wish to set the group to.
 *
 * @return true on success.
 */
bool tox_group_set_privacy_state(Tox *tox, Tox_Group_Number group_number, Tox_Group_Privacy_State privacy_state,
                                 Tox_Err_Group_Set_Privacy_State *error);

typedef enum Tox_Err_Group_Set_Peer_Limit {

    /**
     * The function returned successfully.
     */
    TOX_ERR_GROUP_SET_PEER_LIMIT_OK,

    /**
     * The group number passed did not designate a valid group.
     */
    TOX_ERR_GROUP_SET_PEER_LIMIT_GROUP_NOT_FOUND,

    /**
     * The caller does not have the required permissions to set the peer limit.
     */
    TOX_ERR_GROUP_SET_PEER_LIMIT_PERMISSIONS,

    /**
     * The peer limit could not be set. This may occur due to an error related
     * to cryptographic signing of the new shared state.
     */
    TOX_ERR_GROUP_SET_PEER_LIMIT_FAIL_SET,

    /**
     * The packet failed to send.
     */
    TOX_ERR_GROUP_SET_PEER_LIMIT_FAIL_SEND,

    /**
     * The group is disconnected.
     */
    TOX_ERR_GROUP_SET_PEER_LIMIT_DISCONNECTED,

} Tox_Err_Group_Set_Peer_Limit;

const char *tox_err_group_set_peer_limit_to_string(Tox_Err_Group_Set_Peer_Limit value);

/**
 * Set the group peer limit.
 *
 * This function allows Founders to set a limit for the number of peers who may
 * be in the group. It will create a new group shared state including the change
 * and distribute it to the rest of the group.
 *
 * @param group_number The group number of the group for which we wish to set
 *   the peer limit.
 * @param peer_limit The maximum number of peers to allow in the group.
 *
 * @return true on success.
 */
bool tox_group_set_peer_limit(Tox *tox, Tox_Group_Number group_number, uint16_t peer_limit,
                              Tox_Err_Group_Set_Peer_Limit *error);

/*******************************************************************************
 *
 * :: Group chat moderation controls
 *
 ******************************************************************************/

typedef enum Tox_Err_Group_Set_Ignore {

    /**
     * The function returned successfully.
     */
    TOX_ERR_GROUP_SET_IGNORE_OK,

    /**
     * The group number passed did not designate a valid group.
     */
    TOX_ERR_GROUP_SET_IGNORE_GROUP_NOT_FOUND,

    /**
     * The ID passed did not designate a valid peer.
     */
    TOX_ERR_GROUP_SET_IGNORE_PEER_NOT_FOUND,

    /**
     * The caller attempted to ignore himself.
     */
    TOX_ERR_GROUP_SET_IGNORE_SELF,

} Tox_Err_Group_Set_Ignore;

const char *tox_err_group_set_ignore_to_string(Tox_Err_Group_Set_Ignore value);

/**
 * Ignore or unignore a peer.
 *
 * @param group_number The group number of the group in which you wish to ignore
 *   a peer.
 * @param peer_id The ID of the peer who shall be ignored or unignored.
 * @param ignore True to ignore the peer, false to unignore the peer.
 *
 * @return true on success.
 */
bool tox_group_set_ignore(Tox *tox, Tox_Group_Number group_number, Tox_Group_Peer_Number peer_id, bool ignore,
                          Tox_Err_Group_Set_Ignore *error);

typedef enum Tox_Err_Group_Set_Role {

    /**
     * The function returned successfully.
     */
    TOX_ERR_GROUP_SET_ROLE_OK,

    /**
     * The group number passed did not designate a valid group.
     */
    TOX_ERR_GROUP_SET_ROLE_GROUP_NOT_FOUND,

    /**
     * The ID passed did not designate a valid peer. Note: you cannot set your
     * own role.
     */
    TOX_ERR_GROUP_SET_ROLE_PEER_NOT_FOUND,

    /**
     * The caller does not have the required permissions for this action.
     */
    TOX_ERR_GROUP_SET_ROLE_PERMISSIONS,

    /**
     * The role assignment is invalid. This will occur if you try to set a
     * peer's role to the role they already have.
     */
    TOX_ERR_GROUP_SET_ROLE_ASSIGNMENT,

    /**
     * The role was not successfully set. This may occur if the packet failed to
     * send, or if the role limit has been reached.
     */
    TOX_ERR_GROUP_SET_ROLE_FAIL_ACTION,

    /**
     * The caller attempted to set their own role.
     */
    TOX_ERR_GROUP_SET_ROLE_SELF,

} Tox_Err_Group_Set_Role;

const char *tox_err_group_set_role_to_string(Tox_Err_Group_Set_Role value);

/**
 * Set a peer's role.
 *
 * This function will first remove the peer's previous role and then assign them
 * a new role. It will also send a packet to the rest of the group, requesting
 * that they perform the role reassignment.
 *
 * Only Founders may promote peers to the Moderator role, and only Founders and
 * Moderators may set peers to the Observer or User role. Moderators may not set
 * the role of other Moderators or the Founder. Peers may not be promoted to the
 * Founder role.
 *
 * @param group_number The group number of the group the in which you wish set
 *   the peer's role.
 * @param peer_id The ID of the peer whose role you wish to set.
 * @param role The role you wish to set the peer to.
 *
 * @return true on success.
 */
bool tox_group_set_role(Tox *tox, Tox_Group_Number group_number, Tox_Group_Peer_Number peer_id, Tox_Group_Role role,
                        Tox_Err_Group_Set_Role *error);

typedef enum Tox_Err_Group_Kick_Peer {

    /**
     * The function returned successfully.
     */
    TOX_ERR_GROUP_KICK_PEER_OK,

    /**
     * The group number passed did not designate a valid group.
     */
    TOX_ERR_GROUP_KICK_PEER_GROUP_NOT_FOUND,

    /**
     * The ID passed did not designate a valid peer.
     */
    TOX_ERR_GROUP_KICK_PEER_PEER_NOT_FOUND,

    /**
     * The caller does not have the required permissions for this action.
     */
    TOX_ERR_GROUP_KICK_PEER_PERMISSIONS,

    /**
     * The peer could not be kicked from the group.
     */
    TOX_ERR_GROUP_KICK_PEER_FAIL_ACTION,

    /**
     * The packet failed to send.
     */
    TOX_ERR_GROUP_KICK_PEER_FAIL_SEND,

    /**
     * The caller attempted to set their own role.
     */
    TOX_ERR_GROUP_KICK_PEER_SELF,

} Tox_Err_Group_Kick_Peer;

const char *tox_err_group_kick_peer_to_string(Tox_Err_Group_Kick_Peer value);

/**
 * Kick a peer.
 *
 * This function allows peers with the Founder or Moderator role to silently
 * instruct all other peers in the group to remove a particular peer from their
 * peer list.
 *
 * Note: This function will not trigger the `group_peer_exit` event for the
 * caller.
 *
 * @param group_number The group number of the group the action is intended for.
 * @param peer_id The ID of the peer who will be kicked.
 *
 * @return true on success.
 */
bool tox_group_kick_peer(const Tox *tox, Tox_Group_Number group_number, Tox_Group_Peer_Number peer_id,
                         Tox_Err_Group_Kick_Peer *error);

/**
 * Represents moderation events. These should be used with the
 * `group_moderation` event.
 */
typedef enum Tox_Group_Mod_Event {

    /**
     * A peer has been kicked from the group.
     */
    TOX_GROUP_MOD_EVENT_KICK,

    /**
     * A peer as been given the observer role.
     */
    TOX_GROUP_MOD_EVENT_OBSERVER,

    /**
     * A peer has been given the user role.
     */
    TOX_GROUP_MOD_EVENT_USER,

    /**
     * A peer has been given the moderator role.
     */
    TOX_GROUP_MOD_EVENT_MODERATOR,

} Tox_Group_Mod_Event;

const char *tox_group_mod_event_to_string(Tox_Group_Mod_Event value);

/**
 * @param group_number The group number of the group the event is intended for.
 * @param source_peer_id The ID of the peer who initiated the event.
 * @param target_peer_id The ID of the peer who is the target of the event.
 * @param mod_type The type of event.
 */
typedef void tox_group_moderation_cb(
    Tox *tox, Tox_Group_Number group_number, Tox_Group_Peer_Number source_peer_id, Tox_Group_Peer_Number target_peer_id,
    Tox_Group_Mod_Event mod_type, void *user_data);

/**
 * Set the callback for the `group_moderation` event. Pass NULL to unset.
 *
 * This event is triggered when a moderator or founder executes a moderation
 * event, with the exception of the peer who initiates the event. It is also
 * triggered when the observer and moderator lists are silently modified (this
 * may occur during group syncing).
 *
 * If either peer id does not designate a valid peer in the group chat, the
 * client should manually update all peer roles.
 */
void tox_callback_group_moderation(Tox *tox, tox_group_moderation_cb *callback);

/** @} */

/** @} */

#ifdef __cplusplus
} /* extern "C" */
#endif

//!TOKSTYLE-
#ifndef DOXYGEN_IGNORE

#ifndef TOX_HIDE_DEPRECATED
typedef Tox_Err_Options_New TOX_ERR_OPTIONS_NEW;
typedef Tox_Err_New TOX_ERR_NEW;
typedef Tox_Err_Bootstrap TOX_ERR_BOOTSTRAP;
typedef Tox_Err_Set_Info TOX_ERR_SET_INFO;
typedef Tox_Err_Friend_Add TOX_ERR_FRIEND_ADD;
typedef Tox_Err_Friend_Delete TOX_ERR_FRIEND_DELETE;
typedef Tox_Err_Friend_By_Public_Key TOX_ERR_FRIEND_BY_PUBLIC_KEY;
typedef Tox_Err_Friend_Get_Public_Key TOX_ERR_FRIEND_GET_PUBLIC_KEY;
typedef Tox_Err_Friend_Get_Last_Online TOX_ERR_FRIEND_GET_LAST_ONLINE;
typedef Tox_Err_Friend_Query TOX_ERR_FRIEND_QUERY;
typedef Tox_Err_Set_Typing TOX_ERR_SET_TYPING;
typedef Tox_Err_Friend_Send_Message TOX_ERR_FRIEND_SEND_MESSAGE;
typedef Tox_Err_File_Control TOX_ERR_FILE_CONTROL;
typedef Tox_Err_File_Seek TOX_ERR_FILE_SEEK;
typedef Tox_Err_File_Get TOX_ERR_FILE_GET;
typedef Tox_Err_File_Send TOX_ERR_FILE_SEND;
typedef Tox_Err_File_Send_Chunk TOX_ERR_FILE_SEND_CHUNK;
typedef Tox_Err_Conference_New TOX_ERR_CONFERENCE_NEW;
typedef Tox_Err_Conference_Delete TOX_ERR_CONFERENCE_DELETE;
typedef Tox_Err_Conference_Peer_Query TOX_ERR_CONFERENCE_PEER_QUERY;
typedef Tox_Err_Conference_Set_Max_Offline TOX_ERR_CONFERENCE_SET_MAX_OFFLINE;
typedef Tox_Err_Conference_By_Id TOX_ERR_CONFERENCE_BY_ID;
typedef Tox_Err_Conference_By_Uid TOX_ERR_CONFERENCE_BY_UID;
typedef Tox_Err_Conference_Invite TOX_ERR_CONFERENCE_INVITE;
typedef Tox_Err_Conference_Join TOX_ERR_CONFERENCE_JOIN;
typedef Tox_Err_Conference_Send_Message TOX_ERR_CONFERENCE_SEND_MESSAGE;
typedef Tox_Err_Conference_Title TOX_ERR_CONFERENCE_TITLE;
typedef Tox_Err_Conference_Get_Type TOX_ERR_CONFERENCE_GET_TYPE;
typedef Tox_Err_Friend_Custom_Packet TOX_ERR_FRIEND_CUSTOM_PACKET;
typedef Tox_Err_Get_Port TOX_ERR_GET_PORT;
typedef Tox_User_Status TOX_USER_STATUS;
typedef Tox_Message_Type TOX_MESSAGE_TYPE;
typedef Tox_Proxy_Type TOX_PROXY_TYPE;
typedef Tox_Savedata_Type TOX_SAVEDATA_TYPE;
typedef Tox_Connection TOX_CONNECTION;
typedef Tox_File_Control TOX_FILE_CONTROL;
typedef Tox_Conference_Type TOX_CONFERENCE_TYPE;
typedef enum Tox_File_Kind TOX_FILE_KIND;
#endif /* TOX_HIDE_DEPRECATED */

#endif
//!TOKSTYLE+

#endif /* C_TOXCORE_TOXCORE_TOX_H */
