cmake_minimum_required(VERSION 3.28)

project(anvil_loader_consumer LANGUAGES CXX)

if(CONSUMER_MODE STREQUAL "add_subdirectory")
  add_subdirectory(${ANVIL_SOURCE_DIR} anvil-subproject)
elseif(CONSUMER_MODE STREQUAL "fetchcontent")
  include(FetchContent)
  FetchContent_Declare(
    anvil
    GIT_REPOSITORY ${ANVIL_GIT_REPOSITORY}
    GIT_TAG ${ANVIL_GIT_TAG}
  )
  FetchContent_MakeAvailable(anvil)
elseif(CONSUMER_MODE STREQUAL "find_package")
  find_package(anvil CONFIG REQUIRED)
else()
  message(FATAL_ERROR "unknown CONSUMER_MODE: ${CONSUMER_MODE}")
endif()

add_executable(anvil_loader_consumer main.cpp)
set_target_properties(anvil_loader_consumer PROPERTIES ENABLE_EXPORTS ON)
target_link_libraries(anvil_loader_consumer
  PRIVATE anvil::loader
  PRIVATE anvil::sdk
  PRIVATE anvil::store
)

add_library(anvil_consumer_plugin SHARED plugin.cpp)
target_link_libraries(anvil_consumer_plugin PRIVATE anvil::sdk)
set_target_properties(anvil_consumer_plugin PROPERTIES
  CXX_VISIBILITY_PRESET hidden
  VISIBILITY_INLINES_HIDDEN YES
  PREFIX ""
)

target_compile_definitions(anvil_loader_consumer PRIVATE
  ANVIL_CONSUMER_PLUGIN="$<TARGET_FILE:anvil_consumer_plugin>"
)
add_dependencies(anvil_loader_consumer anvil_consumer_plugin)
