if(NOT ANVIL_HARDENING)
  return()
endif()

if(CMAKE_CONFIGURATION_TYPES)
  message(FATAL_ERROR
    "ANVIL_HARDENING requires a single-config Release or RelWithDebInfo build"
  )
endif()

if(NOT CMAKE_BUILD_TYPE MATCHES "^(Release|RelWithDebInfo)$")
  message(FATAL_ERROR
    "ANVIL_HARDENING requires Release or RelWithDebInfo; "
    "_FORTIFY_SOURCE is ineffective without optimization"
  )
endif()

if(NOT CMAKE_CXX_COMPILER_ID MATCHES "^(GNU|Clang)$")
  message(FATAL_ERROR "ANVIL_HARDENING supports GCC and Clang only")
endif()

include(CheckCCompilerFlag)
include(CheckCXXCompilerFlag)
include(CheckPIESupported)

function(_anvil_require_compile_flag language flag check_name)
  if(language STREQUAL "C")
    check_c_compiler_flag("${flag}" ${check_name})
  else()
    check_cxx_compiler_flag("${flag}" ${check_name})
  endif()

  if(NOT ${check_name})
    message(FATAL_ERROR
      "${CMAKE_${language}_COMPILER_ID} ${CMAKE_${language}_COMPILER_VERSION} "
      "does not support required hardening flag ${flag}"
    )
  endif()

  add_compile_options("$<$<COMPILE_LANGUAGE:${language}>:${flag}>")
endfunction()

set(_anvil_hardening_flags
  -fstack-protector-strong
  -fstack-clash-protection
  -ftrivial-auto-var-init=zero
)

foreach(_flag IN LISTS _anvil_hardening_flags)
  string(MAKE_C_IDENTIFIER "${_flag}" _flag_id)
  _anvil_require_compile_flag(CXX "${_flag}" "ANVIL_CXX_HAS_${_flag_id}")
  if(ANVIL_SERVER)
    _anvil_require_compile_flag(C "${_flag}" "ANVIL_C_HAS_${_flag_id}")
  endif()
endforeach()

string(TOLOWER "${CMAKE_SYSTEM_PROCESSOR}" _anvil_processor)
if(_anvil_processor MATCHES "^(x86_64|amd64|i[3-6]86)$")
  _anvil_require_compile_flag(
    CXX -fcf-protection=full ANVIL_CXX_HAS_CET_PROTECTION
  )
  if(ANVIL_SERVER)
    _anvil_require_compile_flag(
      C -fcf-protection=full ANVIL_C_HAS_CET_PROTECTION
    )
  endif()
endif()

add_compile_definitions(
  _FORTIFY_SOURCE=3
  "$<$<COMPILE_LANGUAGE:CXX>:_GLIBCXX_ASSERTIONS>"
)

set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(_anvil_pie_languages CXX)
if(ANVIL_SERVER)
  list(APPEND _anvil_pie_languages C)
endif()
check_pie_supported(
  LANGUAGES ${_anvil_pie_languages}
  OUTPUT_VARIABLE _anvil_pie_error
)
foreach(_language IN LISTS _anvil_pie_languages)
  if(NOT CMAKE_${_language}_LINK_PIE_SUPPORTED)
    message(FATAL_ERROR
      "${_language} PIE is required for ANVIL_HARDENING: ${_anvil_pie_error}"
    )
  endif()
endforeach()

add_link_options(
  -Wl,-z,relro,-z,now
  -Wl,-z,noexecstack
)
