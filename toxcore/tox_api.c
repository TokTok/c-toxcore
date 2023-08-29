/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2023 The TokTok team.
 */
#include "tox.h"

#include "ccompat.h"
#include "tox_private.h"

uint32_t tox_version_major(void)
{
    return TOX_VERSION_MAJOR;
}
uint32_t tox_version_minor(void)
{
    return TOX_VERSION_MINOR;
}
uint32_t tox_version_patch(void)
{
    return TOX_VERSION_PATCH;
}
uint32_t tox_public_key_size(void)
{
    return TOX_PUBLIC_KEY_SIZE;
}
uint32_t tox_secret_key_size(void)
{
    return TOX_SECRET_KEY_SIZE;
}
uint32_t tox_conference_uid_size(void)
{
    return TOX_CONFERENCE_UID_SIZE;
}
uint32_t tox_conference_id_size(void)
{
    return TOX_CONFERENCE_ID_SIZE;
}
uint32_t tox_nospam_size(void)
{
    return TOX_NOSPAM_SIZE;
}
uint32_t tox_address_size(void)
{
    return TOX_ADDRESS_SIZE;
}
uint32_t tox_max_name_length(void)
{
    return TOX_MAX_NAME_LENGTH;
}
uint32_t tox_max_status_message_length(void)
{
    return TOX_MAX_STATUS_MESSAGE_LENGTH;
}
uint32_t tox_max_friend_request_length(void)
{
    return TOX_MAX_FRIEND_REQUEST_LENGTH;
}
uint32_t tox_max_message_length(void)
{
    return TOX_MAX_MESSAGE_LENGTH;
}
uint32_t tox_max_custom_packet_size(void)
{
    return TOX_MAX_CUSTOM_PACKET_SIZE;
}
uint32_t tox_hash_length(void)
{
    return TOX_HASH_LENGTH;
}
uint32_t tox_file_id_length(void)
{
    return TOX_FILE_ID_LENGTH;
}
uint32_t tox_max_filename_length(void)
{
    return TOX_MAX_FILENAME_LENGTH;
}
uint32_t tox_max_hostname_length(void)
{
    return TOX_MAX_HOSTNAME_LENGTH;
}
uint32_t tox_group_max_topic_length(void)
{
    return TOX_GROUP_MAX_TOPIC_LENGTH;
}
uint32_t tox_group_max_part_length(void)
{
    return TOX_GROUP_MAX_PART_LENGTH;
}
uint32_t tox_group_max_message_length(void)
{
    return TOX_GROUP_MAX_MESSAGE_LENGTH;
}
uint32_t tox_group_max_custom_lossy_packet_length(void)
{
    return TOX_GROUP_MAX_CUSTOM_LOSSY_PACKET_LENGTH;
}
uint32_t tox_group_max_custom_lossless_packet_length(void)
{
    return TOX_GROUP_MAX_CUSTOM_LOSSLESS_PACKET_LENGTH;
}
uint32_t tox_group_max_group_name_length(void)
{
    return TOX_GROUP_MAX_GROUP_NAME_LENGTH;
}
uint32_t tox_group_max_password_size(void)
{
    return TOX_GROUP_MAX_PASSWORD_SIZE;
}
uint32_t tox_group_chat_id_size(void)
{
    return TOX_GROUP_CHAT_ID_SIZE;
}
uint32_t tox_group_peer_public_key_size(void)
{
    return TOX_GROUP_PEER_PUBLIC_KEY_SIZE;
}
uint32_t tox_dht_node_ip_string_size(void)
{
    return TOX_DHT_NODE_IP_STRING_SIZE;
}
uint32_t tox_dht_node_public_key_size(void)
{
    return TOX_DHT_NODE_PUBLIC_KEY_SIZE;
}
