find_package(libssh 0.11.5 CONFIG QUIET)

if(TARGET ssh::ssh)
  set(ANVIL_LIBSSH_TARGET ssh::ssh)
elseif(TARGET ssh)
  set(ANVIL_LIBSSH_TARGET ssh)
elseif(TARGET libssh::libssh)
  set(ANVIL_LIBSSH_TARGET libssh::libssh)
else()
  find_package(PkgConfig QUIET)
  if(PkgConfig_FOUND)
    pkg_check_modules(ANVIL_SYSTEM_LIBSSH QUIET IMPORTED_TARGET libssh>=0.11.5)
  endif()

  if(TARGET PkgConfig::ANVIL_SYSTEM_LIBSSH)
    set(ANVIL_LIBSSH_TARGET PkgConfig::ANVIL_SYSTEM_LIBSSH)
  else()
    set(ANVIL_LIBSSH_URI
      "https://gitlab.com/libssh/libssh-mirror.git"
      CACHE STRING "libssh fallback repository"
    )
    set(ANVIL_LIBSSH_TAG
      "07430deb9b97b751ec5ea5a7fc307f40bf042e0a"
      CACHE STRING "libssh fallback revision (libssh-0.12.2)"
    )

    # Anvil only needs the server transport. Keep the fallback small, static,
    # and out of Anvil's install component because it is private to the
    # executable. These normal variables seed libssh's option() calls under
    # CMP0077 without permanently changing a parent project's cache.
    set(BUILD_SHARED_LIBS OFF)
    set(WITH_EXAMPLES OFF)
    set(WITH_GSSAPI OFF)
    set(WITH_NACL OFF)
    set(WITH_PCAP OFF)
    set(WITH_SFTP OFF)
    set(WITH_SERVER ON)
    set(WITH_SYMBOL_VERSIONING OFF)
    set(WITH_ZLIB OFF)

    include(FetchContent)
    FetchContent_Declare(
      libssh
      GIT_REPOSITORY "${ANVIL_LIBSSH_URI}"
      GIT_TAG "${ANVIL_LIBSSH_TAG}"
      GIT_SHALLOW FALSE
      EXCLUDE_FROM_ALL
    )
    FetchContent_MakeAvailable(libssh)
    set(ANVIL_LIBSSH_TARGET ssh::ssh)
  endif()
endif()
