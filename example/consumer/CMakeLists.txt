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
target_link_libraries(anvil_loader_consumer
  PRIVATE anvil::loader
  PRIVATE anvil::sdk
)
