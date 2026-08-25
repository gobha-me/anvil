cmake_minimum_required(VERSION 3.28)

project(anvil VERSION 0.7.0 LANGUAGES CXX)

if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
  message(FATAL_ERROR "anvil::loader currently requires Linux ELF/glibc")
endif()

include(GNUInstallDirs)

option(ANVIL_TESTS "Build and register the Anvil test suite" ${PROJECT_IS_TOP_LEVEL})
option(ANVIL_INSTALL "Generate Anvil install and package-config rules" ${PROJECT_IS_TOP_LEVEL})
option(ANVIL_SERVER "Build the Anvil SSH server" ${PROJECT_IS_TOP_LEVEL})

set(ANVIL_WARNING_FLAGS
  -Wall
  -Wextra
  -Wpedantic
  -Wconversion
  -Wsign-conversion
)

add_library(anvil_sdk INTERFACE)
add_library(anvil::sdk ALIAS anvil_sdk)

set_target_properties(anvil_sdk PROPERTIES
  EXPORT_NAME sdk
)

target_compile_features(anvil_sdk INTERFACE cxx_std_23)
target_include_directories(anvil_sdk
  INTERFACE
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)

add_library(anvil_loader STATIC
  src/loader.cpp
)
add_library(anvil::loader ALIAS anvil_loader)

set_target_properties(anvil_loader PROPERTIES
  EXPORT_NAME loader
  POSITION_INDEPENDENT_CODE ON
)

target_compile_features(anvil_loader PUBLIC cxx_std_23)
target_compile_options(anvil_loader PRIVATE ${ANVIL_WARNING_FLAGS})
target_compile_definitions(anvil_loader PRIVATE _GNU_SOURCE=1)
target_include_directories(anvil_loader
  PUBLIC
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)
target_link_libraries(anvil_loader PRIVATE ${CMAKE_DL_LIBS})

if(ANVIL_SERVER)
  enable_language(C)
  include(cmake/deps/libssh.cmake)

  add_library(anvil_server STATIC
    src/server.cpp
  )
  target_compile_features(anvil_server PUBLIC cxx_std_23)
  target_compile_options(anvil_server PRIVATE ${ANVIL_WARNING_FLAGS})
  target_include_directories(anvil_server PUBLIC ${PROJECT_SOURCE_DIR}/src)
  target_link_libraries(anvil_server PUBLIC ${ANVIL_LIBSSH_TARGET})

  add_executable(anvil src/main.cpp)
  target_compile_features(anvil PRIVATE cxx_std_23)
  target_compile_options(anvil PRIVATE ${ANVIL_WARNING_FLAGS})
  target_link_libraries(anvil PRIVATE anvil_server)
endif()

if(ANVIL_TESTS)
  include(CTest)
  enable_testing()

  find_package(Catch2 3 QUIET)
  if(NOT Catch2_FOUND)
    include(FetchContent)
    FetchContent_Declare(
      Catch2
      GIT_REPOSITORY https://github.com/catchorg/Catch2.git
      GIT_TAG v3.5.2
    )
    FetchContent_MakeAvailable(Catch2)
  endif()

  add_subdirectory(test)
endif()

if(ANVIL_INSTALL)
  include(CMakePackageConfigHelpers)

  install(TARGETS anvil_loader anvil_sdk
    EXPORT anvilTargets
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
  )
  if(ANVIL_SERVER)
    install(TARGETS anvil RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR})
  endif()
  install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
  install(EXPORT anvilTargets
    FILE anvilTargets.cmake
    NAMESPACE anvil::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/anvil
  )

  configure_package_config_file(
    cmake/anvilConfig.cmake.in
    ${PROJECT_BINARY_DIR}/anvilConfig.cmake
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/anvil
  )
  write_basic_package_version_file(
    ${PROJECT_BINARY_DIR}/anvilConfigVersion.cmake
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
  )
  install(FILES
    ${PROJECT_BINARY_DIR}/anvilConfig.cmake
    ${PROJECT_BINARY_DIR}/anvilConfigVersion.cmake
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/anvil
  )
endif()
