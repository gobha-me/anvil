set(_fixture_sources
  valid
  compatible_short
  lying_size
  mismatched
  mismatched_sanitizer
  missing_tag
  missing_factory
  missing_destroy
  null_factory
  null_tag
  short_tag
)

set(_fixture_targets "")

foreach(_fixture IN LISTS _fixture_sources)
  add_library(fixture_${_fixture} SHARED fixtures/${_fixture}.cpp)
  list(APPEND _fixture_targets fixture_${_fixture})
  target_compile_features(fixture_${_fixture} PRIVATE cxx_std_23)
  target_compile_options(fixture_${_fixture} PRIVATE ${ANVIL_WARNING_FLAGS})
  target_link_libraries(fixture_${_fixture} PRIVATE anvil::sdk)
  set_target_properties(fixture_${_fixture} PROPERTIES
    CXX_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN YES
    PREFIX ""
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/fixtures
  )
endforeach()

add_library(fixture_sdk_types SHARED fixtures/sdk_types.cpp)
target_compile_features(fixture_sdk_types PRIVATE cxx_std_23)
target_compile_options(fixture_sdk_types PRIVATE ${ANVIL_WARNING_FLAGS})
target_link_libraries(fixture_sdk_types PRIVATE anvil::sdk)
set_target_properties(fixture_sdk_types PROPERTIES
  CXX_VISIBILITY_PRESET hidden
  VISIBILITY_INLINES_HIDDEN YES
  PREFIX ""
  LIBRARY_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/fixtures
)

add_library(fixture_sdk_wrapper SHARED fixtures/sdk_wrapper.cpp)
target_compile_features(fixture_sdk_wrapper PRIVATE cxx_std_23)
target_compile_options(fixture_sdk_wrapper PRIVATE ${ANVIL_WARNING_FLAGS})
target_link_libraries(fixture_sdk_wrapper PRIVATE anvil::sdk)
set_target_properties(fixture_sdk_wrapper PROPERTIES
  CXX_VISIBILITY_PRESET hidden
  VISIBILITY_INLINES_HIDDEN YES
  PREFIX ""
  LIBRARY_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/fixtures
)

add_library(fixture_sdk_wrapper_throwing_factory SHARED
  fixtures/sdk_wrapper_throwing_factory.cpp
)
target_compile_features(fixture_sdk_wrapper_throwing_factory PRIVATE cxx_std_23)
target_compile_options(fixture_sdk_wrapper_throwing_factory
  PRIVATE ${ANVIL_WARNING_FLAGS}
)
target_link_libraries(fixture_sdk_wrapper_throwing_factory PRIVATE anvil::sdk)
set_target_properties(fixture_sdk_wrapper_throwing_factory PROPERTIES
  CXX_VISIBILITY_PRESET hidden
  VISIBILITY_INLINES_HIDDEN YES
  PREFIX ""
  LIBRARY_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/fixtures
)

# A successful dlsym with address zero is distinct from a missing symbol. GNU
# ld and the GNU-compatible linker used by Clang both support an absolute
# symbol for this adversarial fixture.
target_link_options(fixture_null_tag PRIVATE
  -Wl,--defsym,anvil_abi_tag=0
)

# Sanitizers intentionally pad globals and publish the padded size in the ELF
# symbol table. Keep this one malformed-size fixture literal so it continues to
# exercise the loader's pre-copy size check in sanitizer builds.
target_compile_options(fixture_short_tag PRIVATE -fno-sanitize=all)
target_link_options(fixture_short_tag PRIVATE -fno-sanitize=all)

add_executable(anvil_loader_tests test_loader.cpp)
set_target_properties(anvil_loader_tests PROPERTIES ENABLE_EXPORTS ON)
target_compile_features(anvil_loader_tests PRIVATE cxx_std_23)
target_compile_options(anvil_loader_tests PRIVATE ${ANVIL_WARNING_FLAGS})
target_link_libraries(anvil_loader_tests
  PRIVATE anvil::loader
  PRIVATE Catch2::Catch2WithMain
)
add_dependencies(anvil_loader_tests ${_fixture_targets})

foreach(_fixture IN LISTS _fixture_sources)
  target_compile_definitions(anvil_loader_tests PRIVATE
    ANVIL_FIXTURE_${_fixture}="$<TARGET_FILE:fixture_${_fixture}>"
  )
endforeach()

add_executable(anvil_sdk_tests test_sdk_types.cpp)
target_compile_features(anvil_sdk_tests PRIVATE cxx_std_23)
target_compile_options(anvil_sdk_tests PRIVATE ${ANVIL_WARNING_FLAGS})
target_link_libraries(anvil_sdk_tests
  PRIVATE anvil::sdk
  PRIVATE fixture_sdk_types
  PRIVATE Catch2::Catch2WithMain
)

add_executable(anvil_sdk_wrapper_tests test_sdk_wrapper.cpp)
set_target_properties(anvil_sdk_wrapper_tests PROPERTIES ENABLE_EXPORTS ON)
target_compile_features(anvil_sdk_wrapper_tests PRIVATE cxx_std_23)
target_compile_options(anvil_sdk_wrapper_tests PRIVATE ${ANVIL_WARNING_FLAGS})
target_compile_definitions(anvil_sdk_wrapper_tests PRIVATE
  ANVIL_FIXTURE_sdk_wrapper="$<TARGET_FILE:fixture_sdk_wrapper>"
  ANVIL_FIXTURE_wrapper_throwing_factory="$<TARGET_FILE:fixture_sdk_wrapper_throwing_factory>"
)
target_link_libraries(anvil_sdk_wrapper_tests
  PRIVATE anvil::loader
  PRIVATE anvil::sdk
  PRIVATE Catch2::Catch2WithMain
)
add_dependencies(anvil_sdk_wrapper_tests
  fixture_sdk_wrapper
  fixture_sdk_wrapper_throwing_factory
)

add_executable(anvil_store_tests test_store.cpp)
target_compile_features(anvil_store_tests PRIVATE cxx_std_23)
target_compile_options(anvil_store_tests PRIVATE ${ANVIL_WARNING_FLAGS})
target_link_libraries(anvil_store_tests
  PRIVATE anvil::store
  PRIVATE Catch2::Catch2WithMain
)

add_executable(anvil_cross_stdlib_host cross_stdlib_host.cpp)
set_target_properties(anvil_cross_stdlib_host PROPERTIES ENABLE_EXPORTS ON)
target_compile_features(anvil_cross_stdlib_host PRIVATE cxx_std_23)
target_compile_options(anvil_cross_stdlib_host PRIVATE ${ANVIL_WARNING_FLAGS})
target_link_libraries(anvil_cross_stdlib_host
  PRIVATE anvil::loader
  PRIVATE anvil::sdk
)
add_dependencies(anvil_cross_stdlib_host fixture_sdk_wrapper)

add_test(
  NAME sdk_wrapper_host
  COMMAND anvil_cross_stdlib_host $<TARGET_FILE:fixture_sdk_wrapper>
)

add_test(
  NAME sdk_wrapper_fixture_contract
  COMMAND
    ${CMAKE_COMMAND}
    -DANVIL_FIXTURE_SOURCE=${CMAKE_CURRENT_SOURCE_DIR}/fixtures/sdk_wrapper.cpp
    -DANVIL_FIXTURE_LIBRARY=$<TARGET_FILE:fixture_sdk_wrapper>
    -DANVIL_NM=${CMAKE_NM}
    -P ${PROJECT_SOURCE_DIR}/cmake/verify_sdk_wrapper_fixture.cmake
)

add_test(
  NAME sdk_non_pod_span_rejected
  COMMAND
    ${CMAKE_CXX_COMPILER}
    -std=c++23
    -fsyntax-only
    -I${PROJECT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/fixtures/non_pod_span.cpp
)
set_tests_properties(sdk_non_pod_span_rejected PROPERTIES WILL_FAIL TRUE)

add_test(
  NAME sdk_temporary_string_rejected
  COMMAND
    ${CMAKE_CXX_COMPILER}
    -std=c++23
    -fsyntax-only
    -I${PROJECT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/fixtures/temporary_string.cpp
)
set_tests_properties(sdk_temporary_string_rejected PROPERTIES WILL_FAIL TRUE)

add_test(
  NAME sdk_temporary_range_rejected
  COMMAND
    ${CMAKE_CXX_COMPILER}
    -std=c++23
    -fsyntax-only
    -I${PROJECT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/fixtures/temporary_range.cpp
)
set_tests_properties(sdk_temporary_range_rejected PROPERTIES WILL_FAIL TRUE)

add_test(
  NAME sdk_boundary_has_no_standard_library_surface
  COMMAND
    ${CMAKE_COMMAND}
    -DANVIL_SDK_DIR=${PROJECT_SOURCE_DIR}/include/anvil/sdk
    -P ${PROJECT_SOURCE_DIR}/cmake/verify_sdk_boundary.cmake
)

find_package(Python3 REQUIRED COMPONENTS Interpreter)
add_test(
  NAME sdk_abi_history_rules
  COMMAND
    ${Python3_EXECUTABLE} -B
    ${CMAKE_CURRENT_SOURCE_DIR}/test_sdk_abi_history.py
)

add_test(
  NAME elf_hardening_verifier_rules
  COMMAND
    ${Python3_EXECUTABLE} -B
    ${CMAKE_CURRENT_SOURCE_DIR}/test_elf_hardening.py
)

if(CMAKE_CXX_COMPILER_ID MATCHES "Clang" AND
   CMAKE_CXX_COMPILER_VERSION VERSION_GREATER_EQUAL 20)
  add_test(
    NAME sdk_abi_history_matches_headers
    COMMAND
      ${Python3_EXECUTABLE}
      -B
      ${PROJECT_SOURCE_DIR}/cmake/verify_sdk_abi.py
      --compiler ${CMAKE_CXX_COMPILER}
      --include-dir ${PROJECT_SOURCE_DIR}/include
      --history ${PROJECT_SOURCE_DIR}/cmake/sdk_abi_history.json
  )
endif()

include(Catch)
catch_discover_tests(anvil_loader_tests)
catch_discover_tests(anvil_sdk_tests)
catch_discover_tests(anvil_sdk_wrapper_tests)
catch_discover_tests(anvil_store_tests)

if(ANVIL_SERVER)
  add_executable(anvil_failure_test_server failure_server_main.cpp)
  target_compile_features(anvil_failure_test_server PRIVATE cxx_std_23)
  target_compile_options(anvil_failure_test_server PRIVATE ${ANVIL_WARNING_FLAGS})
  target_link_libraries(anvil_failure_test_server PRIVATE anvil_server)

  add_executable(anvil_server_tests
    test_admission.cpp
    test_canonical_message.cpp
    test_health.cpp
    test_server.cpp
    test_sqlite_store.cpp
  )
  target_compile_features(anvil_server_tests PRIVATE cxx_std_23)
  target_compile_options(anvil_server_tests PRIVATE ${ANVIL_WARNING_FLAGS})
  target_link_libraries(anvil_server_tests
    PRIVATE anvil_server
    PRIVATE anvil::store
    PRIVATE Catch2::Catch2WithMain
  )
  catch_discover_tests(anvil_server_tests)

  add_executable(anvil_health_test_server health_test_server.cpp)
  target_compile_features(anvil_health_test_server PRIVATE cxx_std_23)
  target_compile_options(anvil_health_test_server PRIVATE ${ANVIL_WARNING_FLAGS})
  target_link_libraries(anvil_health_test_server PRIVATE anvil_server)

  add_test(
    NAME health_http_contract
    COMMAND
      ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/test_health_http.py
      $<TARGET_FILE:anvil_health_test_server>
      $<TARGET_FILE:anvil>
  )
  set_tests_properties(health_http_contract PROPERTIES TIMEOUT 60)

  add_test(
    NAME ssh_server_end_to_end
    COMMAND
      ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/test_ssh_server.py
      $<TARGET_FILE:anvil>
  )
  set_tests_properties(ssh_server_end_to_end PROPERTIES TIMEOUT 45)

  add_test(
    NAME ssh_session_lifecycle
    COMMAND
      ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/test_ssh_lifecycle.py
      $<TARGET_FILE:anvil>
  )
  set_tests_properties(ssh_session_lifecycle PROPERTIES TIMEOUT 45)

  add_test(
    NAME ssh_session_failure_isolation
    COMMAND
      ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/test_ssh_failure_isolation.py
      $<TARGET_FILE:anvil_failure_test_server>
  )
  set_tests_properties(ssh_session_failure_isolation PROPERTIES TIMEOUT 60)
  get_filename_component(_anvil_test_toolchain "${CMAKE_TOOLCHAIN_FILE}" NAME)
  if(_anvil_test_toolchain MATCHES "^(address|address-undefined|thread|undefined)\\.cmake$")
    # Sanitizer runtimes own fatal-signal handling and may convert or retain an
    # externally delivered SIGSEGV. SIGKILL still proves the worker boundary
    # and cannot be intercepted; default and hardened builds exercise SIGSEGV.
    set_tests_properties(ssh_session_failure_isolation PROPERTIES
      ENVIRONMENT "ANVIL_TEST_FATAL_SIGNAL=SIGKILL"
    )
  endif()

  add_test(
    NAME ssh_pty_resize
    COMMAND
      ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/test_ssh_resize.py
      $<TARGET_FILE:anvil>
  )
  set_tests_properties(ssh_pty_resize PROPERTIES TIMEOUT 45)

  add_test(
    NAME ssh_admission_limits
    COMMAND
      ${Python3_EXECUTABLE}
      ${CMAKE_CURRENT_SOURCE_DIR}/test_ssh_admission.py
      $<TARGET_FILE:anvil>
  )
  set_tests_properties(ssh_admission_limits PROPERTIES TIMEOUT 60)
endif()
