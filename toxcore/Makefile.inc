lib_LTLIBRARIES += libtoxcore.la

libtoxcore_la_include_HEADERS = \
                        ../toxcore/tox.h \
                        ../toxcore/tox_dispatch.h \
                        ../toxcore/tox_events.h \
                        ../toxcore/tox_log.h \
                        ../toxcore/tox_memory.h \
                        ../toxcore/tox_network.h \
                        ../toxcore/tox_system.h \
                        ../toxcore/tox_time.h

libtoxcore_la_includedir = $(includedir)/tox/toxcore

libtoxcore_la_SOURCES = ../third_party/cmp/cmp.c \
                        ../third_party/cmp/cmp.h \
                        ../toxcore/announce.c \
                        ../toxcore/announce.h \
                        ../toxcore/bin_pack.c \
                        ../toxcore/bin_pack.h \
                        ../toxcore/bin_unpack.c \
                        ../toxcore/bin_unpack.h \
                        ../toxcore/ccompat.c \
                        ../toxcore/ccompat.h \
                        ../toxcore/crypto_core.c \
                        ../toxcore/crypto_core.h \
                        ../toxcore/DHT.c \
                        ../toxcore/DHT.h \
                        ../toxcore/events/conference_connected.c \
                        ../toxcore/events/conference_invite.c \
                        ../toxcore/events/conference_message.c \
                        ../toxcore/events/conference_peer_list_changed.c \
                        ../toxcore/events/conference_peer_name.c \
                        ../toxcore/events/conference_title.c \
                        ../toxcore/events/events_alloc.c \
                        ../toxcore/events/events_alloc.h \
                        ../toxcore/events/file_chunk_request.c \
                        ../toxcore/events/file_recv.c \
                        ../toxcore/events/file_recv_chunk.c \
                        ../toxcore/events/file_recv_control.c \
                        ../toxcore/events/friend_connection_status.c \
                        ../toxcore/events/friend_lossless_packet.c \
                        ../toxcore/events/friend_lossy_packet.c \
                        ../toxcore/events/friend_message.c \
                        ../toxcore/events/friend_name.c \
                        ../toxcore/events/friend_read_receipt.c \
                        ../toxcore/events/friend_request.c \
                        ../toxcore/events/friend_status.c \
                        ../toxcore/events/friend_status_message.c \
                        ../toxcore/events/friend_typing.c \
                        ../toxcore/events/self_connection_status.c \
                        ../toxcore/forwarding.c \
                        ../toxcore/forwarding.h \
                        ../toxcore/friend_connection.c \
                        ../toxcore/friend_connection.h \
                        ../toxcore/friend_requests.c \
                        ../toxcore/friend_requests.h \
                        ../toxcore/group_announce.c \
                        ../toxcore/group_announce.h \
                        ../toxcore/group.c \
                        ../toxcore/group_chats.c \
                        ../toxcore/group_chats.h \
                        ../toxcore/group_common.h \
                        ../toxcore/group_connection.c \
                        ../toxcore/group_connection.h \
                        ../toxcore/group.h \
                        ../toxcore/group_moderation.c \
                        ../toxcore/group_moderation.h \
                        ../toxcore/group_onion_announce.c \
                        ../toxcore/group_onion_announce.h \
                        ../toxcore/group_pack.c \
                        ../toxcore/group_pack.h \
                        ../toxcore/LAN_discovery.c \
                        ../toxcore/LAN_discovery.h \
                        ../toxcore/list.c \
                        ../toxcore/list.h \
                        ../toxcore/logger.c \
                        ../toxcore/logger.h \
                        ../toxcore/mem.c \
                        ../toxcore/mem.h \
                        ../toxcore/Messenger.c \
                        ../toxcore/Messenger.h \
                        ../toxcore/mono_time.c \
                        ../toxcore/mono_time.h \
                        ../toxcore/net_crypto.c \
                        ../toxcore/net_crypto.h \
                        ../toxcore/network.c \
                        ../toxcore/network.h \
                        ../toxcore/onion_announce.c \
                        ../toxcore/onion_announce.h \
                        ../toxcore/onion.c \
                        ../toxcore/onion_client.c \
                        ../toxcore/onion_client.h \
                        ../toxcore/onion.h \
                        ../toxcore/os_log.c \
                        ../toxcore/os_log.h \
                        ../toxcore/os_memory.c \
                        ../toxcore/os_memory.h \
                        ../toxcore/os_network.c \
                        ../toxcore/os_network.h \
                        ../toxcore/os_network_impl.h \
                        ../toxcore/os_random.c \
                        ../toxcore/os_random.h \
                        ../toxcore/os_system.c \
                        ../toxcore/os_system.h \
                        ../toxcore/ping_array.c \
                        ../toxcore/ping_array.h \
                        ../toxcore/ping.c \
                        ../toxcore/ping.h \
                        ../toxcore/shared_key_cache.c \
                        ../toxcore/shared_key_cache.h \
                        ../toxcore/state.c \
                        ../toxcore/state.h \
                        ../toxcore/TCP_client.c \
                        ../toxcore/TCP_client.h \
                        ../toxcore/TCP_common.c \
                        ../toxcore/TCP_common.h \
                        ../toxcore/TCP_connection.c \
                        ../toxcore/TCP_connection.h \
                        ../toxcore/TCP_server.c \
                        ../toxcore/TCP_server.h \
                        ../toxcore/timed_auth.c \
                        ../toxcore/timed_auth.h \
                        ../toxcore/tox_api.c \
                        ../toxcore/tox_attributes.h \
                        ../toxcore/tox.c \
                        ../toxcore/tox_dispatch.c \
                        ../toxcore/tox_dispatch.h \
                        ../toxcore/tox_events.c \
                        ../toxcore/tox_events.h \
                        ../toxcore/tox.h \
                        ../toxcore/tox_log.c \
                        ../toxcore/tox_log.h \
                        ../toxcore/tox_log_impl.h \
                        ../toxcore/tox_memory.c \
                        ../toxcore/tox_memory.h \
                        ../toxcore/tox_memory_impl.h \
                        ../toxcore/tox_network.c \
                        ../toxcore/tox_network.h \
                        ../toxcore/tox_network_impl.h \
                        ../toxcore/tox_private.c \
                        ../toxcore/tox_private.h \
                        ../toxcore/tox_random.c \
                        ../toxcore/tox_random.h \
                        ../toxcore/tox_random_impl.h \
                        ../toxcore/tox_struct.h \
                        ../toxcore/tox_system.c \
                        ../toxcore/tox_system.h \
                        ../toxcore/tox_system_impl.h \
                        ../toxcore/tox_time.c \
                        ../toxcore/tox_time.h \
                        ../toxcore/tox_time_impl.h \
                        ../toxcore/tox_unpack.c \
                        ../toxcore/tox_unpack.h \
                        ../toxcore/util.c \
                        ../toxcore/util.h

libtoxcore_la_CFLAGS =  -I$(top_srcdir) \
                        -I$(top_srcdir)/toxcore \
                        $(LIBSODIUM_CFLAGS) \
                        $(NACL_CFLAGS) \
                        $(MSGPACK_CFLAGS) \
                        $(PTHREAD_CFLAGS) \
                        -DCMP_NO_FLOAT=1

libtoxcore_la_LDFLAGS = $(LT_LDFLAGS) \
                        $(EXTRA_LT_LDFLAGS) \
                        $(LIBSODIUM_LDFLAGS) \
                        $(NACL_LDFLAGS) \
                        $(MSGPACK_LDFLAGS) \
                        $(MATH_LDFLAGS) \
                        $(RT_LIBS) \
                        $(WINSOCK2_LIBS)

libtoxcore_la_LIBADD =  $(LIBSODIUM_LIBS) \
                        $(NACL_OBJECTS) \
                        $(NACL_LIBS) \
                        $(MSGPACK_LIBS) \
                        $(PTHREAD_LIBS)

if SET_SO_VERSION

EXTRA_libtoxcore_la_DEPENDENCIES = ../so.version

endif
