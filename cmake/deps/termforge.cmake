find_package(termforge CONFIG QUIET)

if(NOT TARGET termforge::lib)
  include(FetchContent)
  FetchContent_Declare(
    termforge
    GIT_REPOSITORY https://github.com/gobha-me/termforge.git
    GIT_TAG v0.57.16
    GIT_SHALLOW TRUE
    EXCLUDE_FROM_ALL
  )
  FetchContent_MakeAvailable(termforge)
endif()

if(NOT TARGET termforge::lib)
  message(FATAL_ERROR "TermForge did not provide termforge::lib")
endif()
