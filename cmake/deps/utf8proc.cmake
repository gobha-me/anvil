find_package(utf8proc CONFIG QUIET)

if(TARGET utf8proc AND NOT TARGET utf8proc::utf8proc)
  add_library(utf8proc::utf8proc ALIAS utf8proc)
endif()

if(NOT TARGET utf8proc::utf8proc)
  include(FetchContent)
  set(UTF8PROC_INSTALL OFF CACHE BOOL "" FORCE)
  set(UTF8PROC_ENABLE_TESTING OFF CACHE BOOL "" FORCE)
  FetchContent_Declare(
    utf8proc
    GIT_REPOSITORY https://github.com/JuliaStrings/utf8proc.git
    GIT_TAG v2.11.3
    GIT_SHALLOW TRUE
    EXCLUDE_FROM_ALL
  )
  FetchContent_MakeAvailable(utf8proc)
endif()

if(TARGET utf8proc AND NOT TARGET utf8proc::utf8proc)
  add_library(utf8proc::utf8proc ALIAS utf8proc)
endif()

if(NOT TARGET utf8proc::utf8proc)
  message(FATAL_ERROR "utf8proc did not provide utf8proc::utf8proc")
endif()
