#! /bin/bash

_HOME2_=$(dirname $0)
export _HOME2_
_HOME_=$(cd $_HOME2_;pwd)
export _HOME_

echo $_HOME_
cd $_HOME_

cd ..

echo '
/*
 * Copyright © 2023 Zoff
 *
 * This file is part of Tox, the free peer to peer instant messenger.
 *
 * Tox is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Tox is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Tox.  If not, see <http://www.gnu.org/licenses/>.
 */

' > amalgamation/toxcore_amalgamation.c

cat \
toxcore/ccompat.h \
\
toxcore/attributes.h \
toxcore/logger.h \
toxcore/mono_time.h \
toxcore/crypto_core.h \
toxcore/network.h \
toxcore/DHT.h \
toxcore/shared_key_cache.h \
toxcore/onion.h \
toxcore/forwarding.h \
toxcore/TCP_client.h \
toxcore/TCP_connection.h \
toxcore/net_crypto.h \
toxcore/onion_client.h \
toxcore/TCP_common.h \
toxcore/TCP_server.h \
\
toxcore/group_moderation.h \
toxcore/group_common.h \
toxcore/group_announce.h \
toxcore/onion_announce.h \
toxcore/group_onion_announce.h \
toxcore/state.h \
\
third_party/cmp/*.h \
\
toxcore/bin_pack.h \
toxcore/bin_unpack.h \
\
toxencryptsave/*.h \
\
toxcore/tox.h \
toxcore/tox_events.h \
toxcore/events/*.h \
\
toxcore/announce.h \
\
\
toxcore/friend_connection.h \
toxcore/friend_requests.h \
toxcore/group_chats.h \
toxcore/group_connection.h \
toxcore/group.h \
toxcore/group_pack.h \
toxcore/LAN_discovery.h \
toxcore/list.h \
toxcore/Messenger.h \
toxcore/ping_array.h \
toxcore/ping.h \
toxcore/timed_auth.h \
toxcore/tox_dispatch.h \
toxcore/tox_private.h \
toxcore/tox_struct.h \
toxcore/tox_unpack.h \
toxcore/util.h \
\
toxutil/toxutil.h \
\
toxav/ring_buffer.h \
toxav/bwcontroller.h \
toxav/msi.h \
toxav/rtp.h \
toxav/ts_buffer.h \
toxav/toxav_hacks.h \
toxav/groupav.h \
toxav/toxav.h \
toxav/video.h \
toxav/audio.h \
toxav/tox_generic.h \
toxav/codecs/toxav_codecs.h \
\
    toxcore/*.c toxcore/*/*.c toxencryptsave/*.c \
    toxav/*.c toxav/codecs/*/*.c third_party/cmp/*.c \
    toxutil/toxutil.c \
    |grep -v '#include "' >> amalgamation/toxcore_amalgamation.c
#
#
#
echo '
/*
 * Copyright © 2023 Zoff
 *
 * This file is part of Tox, the free peer to peer instant messenger.
 *
 * Tox is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Tox is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Tox.  If not, see <http://www.gnu.org/licenses/>.
 */

' > amalgamation/toxcore_amalgamation_no_toxav.c

cat \
toxcore/ccompat.h \
\
toxcore/attributes.h \
toxcore/logger.h \
toxcore/mono_time.h \
toxcore/crypto_core.h \
toxcore/network.h \
toxcore/DHT.h \
toxcore/shared_key_cache.h \
toxcore/onion.h \
toxcore/forwarding.h \
toxcore/TCP_client.h \
toxcore/TCP_connection.h \
toxcore/net_crypto.h \
toxcore/onion_client.h \
toxcore/TCP_common.h \
toxcore/TCP_server.h \
\
toxcore/group_moderation.h \
toxcore/group_common.h \
toxcore/group_announce.h \
toxcore/onion_announce.h \
toxcore/group_onion_announce.h \
toxcore/state.h \
\
third_party/cmp/*.h \
\
toxcore/bin_pack.h \
toxcore/bin_unpack.h \
\
toxencryptsave/*.h \
\
toxcore/tox.h \
toxcore/tox_events.h \
toxcore/events/*.h \
\
toxcore/announce.h \
\
\
toxcore/friend_connection.h \
toxcore/friend_requests.h \
toxcore/group_chats.h \
toxcore/group_connection.h \
toxcore/group.h \
toxcore/group_pack.h \
toxcore/LAN_discovery.h \
toxcore/list.h \
toxcore/Messenger.h \
toxcore/ping_array.h \
toxcore/ping.h \
toxcore/timed_auth.h \
toxcore/tox_dispatch.h \
toxcore/tox_private.h \
toxcore/tox_struct.h \
toxcore/tox_unpack.h \
toxcore/util.h \
\
toxutil/toxutil.h \
\
    toxcore/*.c toxcore/*/*.c toxencryptsave/*.c \
    third_party/cmp/*.c \
    toxutil/toxutil.c \
    |grep -v '#include "' >> amalgamation/toxcore_amalgamation_no_toxav.c
#
#
#
ls -hal amalgamation/toxcore_amalgamation.c
ls -hal amalgamation/toxcore_amalgamation_no_toxav.c
#
#
gcc -O3 -fPIC -DHAVE_H265_ENCODER amalgamation/toxcore_amalgamation.c \
    $(pkg-config --cflags --libs libsodium opus vpx libavcodec libavutil x264 x265) -pthread \
    -c -o amalgamation/libtoxcore.o
#
ls -hal amalgamation/libtoxcore.o
#
#
ar rcs amalgamation/libtoxcore.a amalgamation/libtoxcore.o
#
ls -hal amalgamation/libtoxcore.a

