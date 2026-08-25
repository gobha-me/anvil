if(NOT DEFINED ANVIL_FIXTURE_SOURCE OR NOT DEFINED ANVIL_FIXTURE_LIBRARY OR
   NOT DEFINED ANVIL_NM)
  message(FATAL_ERROR
    "ANVIL_FIXTURE_SOURCE, ANVIL_FIXTURE_LIBRARY, and ANVIL_NM are required"
  )
endif()

file(READ "${ANVIL_FIXTURE_SOURCE}" _anvil_fixture_source)
foreach(_anvil_forbidden IN ITEMS "anvil::Str" "anvil::Span")
  string(FIND "${_anvil_fixture_source}" "${_anvil_forbidden}" _anvil_position)
  if(NOT _anvil_position EQUAL -1)
    message(FATAL_ERROR
      "author fixture contains raw boundary type '${_anvil_forbidden}'"
    )
  endif()
endforeach()

execute_process(
  COMMAND "${ANVIL_NM}" -D --defined-only --format=posix
          "${ANVIL_FIXTURE_LIBRARY}"
  RESULT_VARIABLE _anvil_nm_result
  OUTPUT_VARIABLE _anvil_symbols
  ERROR_VARIABLE _anvil_nm_error
)
if(NOT _anvil_nm_result EQUAL 0)
  message(FATAL_ERROR "symbol audit failed: ${_anvil_nm_error}")
endif()

string(REPLACE "\n" ";" _anvil_symbol_lines "${_anvil_symbols}")
set(_anvil_strong_exports "")
foreach(_anvil_line IN LISTS _anvil_symbol_lines)
  if(_anvil_line MATCHES "^([^ ]+) [ABCDGIRST] ")
    set(_anvil_symbol "${CMAKE_MATCH_1}")
    if(NOT _anvil_symbol MATCHES "^__(odr_asan|start_asan|stop_asan)")
      list(APPEND _anvil_strong_exports "${_anvil_symbol}")
    endif()
  endif()
endforeach()
list(SORT _anvil_strong_exports)

set(_anvil_expected_exports
  anvil_abi_tag
  anvil_plugin_create
  anvil_plugin_destroy
)
if(NOT "${_anvil_strong_exports}" STREQUAL "${_anvil_expected_exports}")
  message(FATAL_ERROR
    "unexpected strong plugin exports: ${_anvil_strong_exports}"
  )
endif()
