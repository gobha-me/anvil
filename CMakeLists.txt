cmake_minimum_required(VERSION 3.28)

project(anvil VERSION 0.30.0 LANGUAGES CXX)

if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
  message(FATAL_ERROR "anvil::loader currently requires Linux ELF/glibc")
endif()

include(GNUInstallDirs)

option(ANVIL_TESTS "Build and register the Anvil test suite" ${PROJECT_IS_TOP_LEVEL})
option(ANVIL_INSTALL "Generate Anvil install and package-config rules" ${PROJECT_IS_TOP_LEVEL})
option(ANVIL_SERVER "Build the Anvil SSH server" ${PROJECT_IS_TOP_LEVEL})
option(ANVIL_HARDENING "Enable the optimized production hardening profile" OFF)

if(ANVIL_SERVER)
  enable_language(C)
endif()

include(cmake/hardening.cmake)

set(ANVIL_WARNING_FLAGS
  -Wall
  -Wextra
  -Wpedantic
  -Wconversion
  -Wsign-conversion
)

function(anvil_apply_input_safety target)
  target_compile_definitions(${target} PRIVATE
    "$<$<COMPILE_LANGUAGE:CXX>:_GLIBCXX_ASSERTIONS>"
  )
  if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    target_compile_options(${target} PRIVATE -Werror=stack-usage=8192)
  elseif(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    target_compile_options(${target} PRIVATE
      -Wframe-larger-than=8192
      "-Werror=frame-larger-than="
    )
  endif()
endfunction()

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
anvil_apply_input_safety(anvil_loader)

add_library(anvil_store STATIC
  src/store.cpp
)
add_library(anvil::store ALIAS anvil_store)

set_target_properties(anvil_store PROPERTIES
  EXPORT_NAME store
  POSITION_INDEPENDENT_CODE ON
)

target_compile_features(anvil_store PUBLIC cxx_std_23)
target_compile_options(anvil_store PRIVATE ${ANVIL_WARNING_FLAGS})
target_include_directories(anvil_store
  PUBLIC
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>
)
anvil_apply_input_safety(anvil_store)

if(ANVIL_SERVER)
  include(cmake/deps/libssh.cmake)
  include(cmake/deps/termforge.cmake)
  include(cmake/deps/httplib.cmake)
  include(cmake/deps/sqlite3.cmake)
  include(cmake/deps/utf8proc.cmake)
  find_package(OpenSSL REQUIRED COMPONENTS Crypto)
  find_package(Threads REQUIRED)

  add_library(anvil_server STATIC
    src/admission.cpp
    src/authentication.cpp
    src/backup.cpp
    src/canonical_message.cpp
    src/health.cpp
    src/server.cpp
    src/session_resources.cpp
    src/sqlite_store.cpp
    src/terminal_session.cpp
    src/text_sanitization.cpp
  )
  target_compile_features(anvil_server PUBLIC cxx_std_23)
  target_compile_options(anvil_server PRIVATE ${ANVIL_WARNING_FLAGS})
  target_compile_definitions(anvil_server PRIVATE _GNU_SOURCE=1)
  target_include_directories(anvil_server PUBLIC ${PROJECT_SOURCE_DIR}/src)
  # cpp-httplib is header-only. Keep Anvil's stack-frame gate from becoming a
  # policy for upstream inline parser functions compiled through health.cpp.
  target_include_directories(anvil_server SYSTEM PRIVATE
    $<TARGET_PROPERTY:httplib::httplib,INTERFACE_INCLUDE_DIRECTORIES>
  )
  target_link_libraries(anvil_server
    PUBLIC ${ANVIL_LIBSSH_TARGET}
    PRIVATE anvil::store termforge::lib httplib::httplib SQLite::SQLite3
            OpenSSL::Crypto Threads::Threads utf8proc::utf8proc
  )
  anvil_apply_input_safety(anvil_server)

  add_executable(anvil src/main.cpp)
  target_compile_features(anvil PRIVATE cxx_std_23)
  target_compile_options(anvil PRIVATE ${ANVIL_WARNING_FLAGS})
  target_link_libraries(anvil PRIVATE anvil_server)
  anvil_apply_input_safety(anvil)
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

  install(TARGETS anvil_loader anvil_sdk anvil_store
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
