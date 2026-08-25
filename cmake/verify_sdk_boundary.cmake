if(NOT DEFINED ANVIL_SDK_HEADER)
  message(FATAL_ERROR "ANVIL_SDK_HEADER is required")
endif()

file(READ "${ANVIL_SDK_HEADER}" _anvil_sdk_source)

set(_anvil_forbidden_tokens
  "std::"
  "#include <string>"
  "#include <string_view>"
  "#include <vector>"
  "#include <memory>"
  "#include <functional>"
  "#include <span>"
)

foreach(_anvil_token IN LISTS _anvil_forbidden_tokens)
  string(FIND "${_anvil_sdk_source}" "${_anvil_token}" _anvil_position)
  if(NOT _anvil_position EQUAL -1)
    message(FATAL_ERROR
      "forbidden token '${_anvil_token}' found in ${ANVIL_SDK_HEADER}"
    )
  endif()
endforeach()
