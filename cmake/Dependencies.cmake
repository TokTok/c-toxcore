###############################################################################
#
# :: For systems that have pkg-config.
#
###############################################################################

find_package(PkgConfig REQUIRED)

find_package(Threads REQUIRED)

find_library(NSL_LIBRARIES    nsl   )
find_library(RT_LIBRARIES     rt    )
find_library(SOCKET_LIBRARIES socket)

# For toxcore.
pkg_search_module(LIBSODIUM   libsodium IMPORTED_TARGET REQUIRED)

# For toxav.
pkg_search_module(OPUS        opus      IMPORTED_TARGET)
if(NOT OPUS_FOUND)
  pkg_search_module(OPUS      Opus      IMPORTED_TARGET)
endif()
pkg_search_module(VPX         vpx       IMPORTED_TARGET)
if(NOT VPX_FOUND)
  pkg_search_module(VPX       libvpx    IMPORTED_TARGET)
endif()

# For tox-bootstrapd.
pkg_search_module(LIBCONFIG   libconfig IMPORTED_TARGET)

if(MSVC)
  # For toxcore.
  find_package(PThreads4W REQUIRED)
  find_package(unofficial-sodium REQUIRED)
endif()
