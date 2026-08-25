if(NOT DEFINED ANVIL_SDK_DIR)
  message(FATAL_ERROR "ANVIL_SDK_DIR is required")
endif()

file(GLOB _anvil_sdk_headers "${ANVIL_SDK_DIR}/*.hpp")

set(_anvil_forbidden_tokens
  "std::"
  "#include <string>"
  "#include <string_view>"
  "#include <vector>"
  "#include <memory>"
  "#include <functional>"
  "#include <span>"
)

foreach(_anvil_sdk_header IN LISTS _anvil_sdk_headers)
  file(READ "${_anvil_sdk_header}" _anvil_sdk_source)
  foreach(_anvil_token IN LISTS _anvil_forbidden_tokens)
    string(FIND "${_anvil_sdk_source}" "${_anvil_token}" _anvil_position)
    if(NOT _anvil_position EQUAL -1)
      message(FATAL_ERROR
        "forbidden token '${_anvil_token}' found in ${_anvil_sdk_header}"
      )
    endif()
  endforeach()
endforeach()
