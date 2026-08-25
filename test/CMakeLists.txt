set(_fixture_sources
  valid
  mismatched
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
  set_target_properties(fixture_${_fixture} PROPERTIES
    CXX_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN YES
    PREFIX ""
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/fixtures
  )
endforeach()

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

include(Catch)
catch_discover_tests(anvil_loader_tests)
