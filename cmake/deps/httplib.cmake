find_package(httplib 0.53.1 CONFIG QUIET)

if(NOT TARGET httplib::httplib)
  include(FetchContent)
  set(HTTPLIB_USE_OPENSSL_IF_AVAILABLE OFF CACHE BOOL "" FORCE)
  set(HTTPLIB_USE_ZLIB_IF_AVAILABLE OFF CACHE BOOL "" FORCE)
  set(HTTPLIB_USE_BROTLI_IF_AVAILABLE OFF CACHE BOOL "" FORCE)
  set(HTTPLIB_USE_ZSTD_IF_AVAILABLE OFF CACHE BOOL "" FORCE)
  set(HTTPLIB_INSTALL OFF CACHE BOOL "" FORCE)
  set(HTTPLIB_TEST OFF CACHE BOOL "" FORCE)
  FetchContent_Declare(
    httplib
    GIT_REPOSITORY https://github.com/yhirose/cpp-httplib.git
    GIT_TAG v0.53.1
    GIT_SHALLOW TRUE
    EXCLUDE_FROM_ALL
  )
  FetchContent_MakeAvailable(httplib)
endif()

if(NOT TARGET httplib::httplib)
  message(FATAL_ERROR "cpp-httplib did not provide httplib::httplib")
endif()
