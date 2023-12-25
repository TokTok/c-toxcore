add_executable(save-generator save-generator.c)
target_link_libraries(save-generator PRIVATE toxcore_static misc_tools)

add_executable(strkey strkey.c)
target_link_libraries(strkey PRIVATE toxcore_static ${LIBSODIUM_LIBRARIES})

add_executable(create_bootstrap_keys create_bootstrap_keys.c)
target_link_libraries(create_bootstrap_keys PRIVATE ${LIBSODIUM_LIBRARIES})

add_executable(create_minimal_savedata create_minimal_savedata.c)
target_link_libraries(create_minimal_savedata PRIVATE ${LIBSODIUM_LIBRARIES})

add_executable(create_savedata create_savedata.c)
target_link_libraries(create_savedata PRIVATE toxcore_static ${LIBSODIUM_LIBRARIES})

add_executable(sign sign.c)
target_link_libraries(sign PRIVATE ${LIBSODIUM_LIBRARIES} misc_tools)

add_executable(cracker_simple cracker_simple.c)
target_link_libraries(cracker_simple PRIVATE ${LIBSODIUM_LIBRARIES} misc_tools)

# MSVC doesn't support OpenMP
if(NOT MSVC)
  find_package(OpenMP)
  if(OpenMP_C_FOUND)
    add_executable(cracker cracker.c)
    target_link_libraries(cracker PRIVATE ${LIBSODIUM_LIBRARIES} OpenMP::OpenMP_C)
  endif()
endif()
