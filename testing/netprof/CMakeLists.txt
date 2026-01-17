set(netprof_lib_SOURCES
  app.cc
  command_registry.cc
  layout_engine.cc
  model_utils.cc
  node_wrapper.cc
  packet_utils.cc
  simulation_manager.cc
  ui.cc
  views/bottom_bar.cc
  views/command_log.cc
  views/command_palette.cc
  views/dht_filter.cc
  views/dht_topology.cc
  views/event_log.cc
  views/focusable.cc
  views/hud.cc
  views/inspector.cc
  views/topology.cc
)

add_library(netprof_core STATIC ${netprof_lib_SOURCES})

target_include_directories(netprof_core PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

target_link_libraries(netprof_core PUBLIC support)

if(TARGET nlohmann_json::nlohmann_json)
  target_link_libraries(netprof_core PUBLIC nlohmann_json::nlohmann_json)
else()
  target_link_libraries(netprof_core PUBLIC PkgConfig::NLOHMANN_JSON)
endif()

if(TARGET ftxui::component)
  target_link_libraries(netprof_core PUBLIC ftxui::component ftxui::dom ftxui::screen)
elseif(TARGET PkgConfig::FTXUI)
  target_link_libraries(netprof_core PUBLIC PkgConfig::FTXUI)
else()
  target_link_libraries(netprof_core PUBLIC PkgConfig::FTXUI_COMPONENT PkgConfig::FTXUI_DOM PkgConfig::FTXUI_SCREEN)
endif()

if(TARGET pthreads4w::pthreads4w)
  target_link_libraries(netprof_core PUBLIC pthreads4w::pthreads4w)
elseif(TARGET PThreads4W::PThreads4W)
  target_link_libraries(netprof_core PUBLIC PThreads4W::PThreads4W)
elseif(TARGET Threads::Threads)
  target_link_libraries(netprof_core PUBLIC Threads::Threads)
endif()

if(TARGET toxcore_static)
  target_link_libraries(netprof_core PRIVATE toxcore_static)
else()
  target_link_libraries(netprof_core PRIVATE toxcore_shared)
endif()

if(FTXUI_VERSION_MAJOR)
  target_compile_definitions(netprof_core PUBLIC FTXUI_VERSION_MAJOR=${FTXUI_VERSION_MAJOR})
endif()

add_executable(netprof main.cc)
target_link_libraries(netprof PRIVATE netprof_core)

# Tests
if(UNITTEST AND TARGET GTest::gtest_main)
  add_library(netprof_test_support STATIC ui_test_support.cc)
  target_link_libraries(netprof_test_support PUBLIC netprof_core GTest::gtest GTest::gmock)

  function(netprof_test target source)
    add_executable(${target} ${source})
    target_link_libraries(${target} PRIVATE netprof_test_support netprof_core GTest::gtest_main GTest::gmock)
    if(TARGET toxcore_static)
      target_link_libraries(${target} PRIVATE toxcore_static)
    else()
      target_link_libraries(${target} PRIVATE toxcore_shared)
    endif()
    add_test(NAME ${target} COMMAND ${target})
  endfunction()

  netprof_test(netprof_layout_engine_test layout_engine_test.cc)
  netprof_test(netprof_node_wrapper_test node_wrapper_test.cc)
  netprof_test(netprof_simulation_manager_test simulation_manager_test.cc)
  netprof_test(netprof_ui_test ui_test.cc)
  netprof_test(netprof_model_utils_test model_utils_test.cc)
  netprof_test(netprof_app_test app_test.cc)
endif()
