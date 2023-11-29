cmake_minimum_required(VERSION 3.5)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-missing-field-initializers -Wno-format")

file(GLOB toxcore_SRCS "toxcore/*.[ch]" "toxcore/*/*.[ch]")
set(COMPONENT_SRCS
  ${toxcore_SRCS}
  other/docker/esp32/main/app_main.cc
  other/docker/esp32/main/tox_main.cc
  other/docker/esp32/main/tox_main.h
  third_party/cmp/cmp.c
  third_party/cmp/cmp.h
  toxencryptsave/defines.h)
set(COMPONENT_ADD_INCLUDEDIRS "")

register_component()
