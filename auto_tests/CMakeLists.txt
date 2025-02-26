set(TEST_TIMEOUT_SECONDS "" CACHE STRING "Limit runtime of each test to the number of seconds specified")

add_library(auto_test_support
  auto_test_support.c
  auto_test_support.h)
target_link_libraries(auto_test_support PRIVATE misc_tools)
if(TARGET toxcore_static)
  target_link_libraries(auto_test_support PRIVATE toxcore_static)
else()
  target_link_libraries(auto_test_support PRIVATE toxcore_shared)
endif()
if(TARGET pthreads4w::pthreads4w)
  target_link_libraries(auto_test_support PRIVATE pthreads4w::pthreads4w)
elseif(TARGET PThreads4W::PThreads4W)
  target_link_libraries(auto_test_support PRIVATE PThreads4W::PThreads4W)
elseif(TARGET Threads::Threads)
  target_link_libraries(auto_test_support PRIVATE Threads::Threads)
endif()

function(auto_test target)
  add_executable(auto_${target}_test ${target}_test.c)
  target_link_libraries(auto_${target}_test PRIVATE misc_tools auto_test_support)
  if(TARGET toxcore_static)
    target_link_libraries(auto_${target}_test PRIVATE toxcore_static)
  else()
    target_link_libraries(auto_${target}_test PRIVATE toxcore_shared)
  endif()
  if(TARGET pthreads4w::pthreads4w)
    target_link_libraries(auto_${target}_test PRIVATE pthreads4w::pthreads4w)
  elseif(TARGET PThreads4W::PThreads4W)
    target_link_libraries(auto_${target}_test PRIVATE PThreads4W::PThreads4W)
  elseif(TARGET Threads::Threads)
    target_link_libraries(auto_${target}_test PRIVATE Threads::Threads)
  endif()
  add_test(NAME ${target} COMMAND ${CROSSCOMPILING_EMULATOR} auto_${target}_test)
  set_tests_properties(${target} PROPERTIES TIMEOUT "${TEST_TIMEOUT_SECONDS}")
  # add the source dir as environment variable, so the testdata can be found
  set_tests_properties(${target} PROPERTIES ENVIRONMENT "LLVM_PROFILE_FILE=${target}.profraw;srcdir=${CMAKE_CURRENT_SOURCE_DIR}")
endfunction()

auto_test(TCP)
auto_test(announce)
auto_test(conference)
auto_test(conference_double_invite)
auto_test(conference_invite_merge)
auto_test(conference_peer_nick)
auto_test(conference_simple)
auto_test(conference_two)
auto_test(crypto)
#auto_test(dht)  # Doesn't work with UNITY_BUILD.
auto_test(dht_nodes_response_api)
auto_test(encryptsave)
auto_test(file_saving)
auto_test(file_streaming)
auto_test(file_transfer)
auto_test(forwarding)
auto_test(friend_connection)
auto_test(friend_request)
auto_test(friend_request_spam)
auto_test(group_general)
auto_test(group_invite)
auto_test(group_message)
auto_test(group_moderation)
auto_test(group_save)
auto_test(group_state)
auto_test(group_sync)
auto_test(group_tcp)
auto_test(group_topic)
auto_test(invalid_tcp_proxy)
auto_test(invalid_udp_proxy)
auto_test(lan_discovery)
auto_test(lossless_packet)
auto_test(lossy_packet)
auto_test(netprof)
auto_test(network)
auto_test(onion)
auto_test(overflow_recvq)
auto_test(overflow_sendq)
auto_test(reconnect)
auto_test(save_friend)
auto_test(save_load)
auto_test(send_message)
auto_test(set_name)
auto_test(set_status_message)
auto_test(tox_dispatch)
auto_test(tox_events)
auto_test(tox_many)
auto_test(tox_many_tcp)
auto_test(tox_strncasecmp)
auto_test(typing)
auto_test(version)
auto_test(save_compatibility)

target_include_directories(auto_encryptsave_test SYSTEM PRIVATE ${LIBSODIUM_INCLUDE_DIRS})

if(NON_HERMETIC_TESTS)
  auto_test(bootstrap)
  auto_test(tcp_relay)
endif()

if(BUILD_TOXAV)
  auto_test(conference_av)
  auto_test(toxav_basic)
  auto_test(toxav_many)

  if(TARGET libvpx::libvpx)
    target_link_libraries(auto_toxav_basic_test PRIVATE libvpx::libvpx)
    target_link_libraries(auto_toxav_many_test PRIVATE libvpx::libvpx)
  elseif(TARGET PkgConfig::VPX)
    target_link_libraries(auto_toxav_basic_test PRIVATE PkgConfig::VPX)
    target_link_libraries(auto_toxav_many_test PRIVATE PkgConfig::VPX)
  else()
    target_link_libraries(auto_toxav_basic_test PRIVATE ${VPX_LIBRARIES})
    target_link_directories(auto_toxav_basic_test PRIVATE ${VPX_LIBRARY_DIRS})
    target_include_directories(auto_toxav_basic_test SYSTEM PRIVATE ${VPX_INCLUDE_DIRS})
    target_compile_options(auto_toxav_basic_test PRIVATE ${VPX_CFLAGS_OTHER})

    target_link_libraries(auto_toxav_many_test PRIVATE ${VPX_LIBRARIES})
    target_link_directories(auto_toxav_many_test PRIVATE ${VPX_LIBRARY_DIRS})
    target_include_directories(auto_toxav_many_test SYSTEM PRIVATE ${VPX_INCLUDE_DIRS})
    target_compile_options(auto_toxav_many_test PRIVATE ${VPX_CFLAGS_OTHER})
  endif()
endif()

if(PROXY_TEST)
  auto_test(proxy)
endif()
