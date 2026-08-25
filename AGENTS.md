# AGENTS.md — conventions for Anvil

Anvil is a C++23 terminal BBS. The current executable code is the standalone
plugin loader; the design and issue tracker define the later server work.

- Support GCC 13+ and Clang 20+ through CMake 3.28+.
- Build public libraries so they work through `add_subdirectory`,
  `FetchContent`, and installed `find_package` use.
- Treat plugin inputs, paths, symbols, and ABI metadata as hostile.
- Keep the plugin boundary free of standard-library types. Host-only loader
  types may use the standard library.
- Test failure paths first, especially lifetime and dynamic-loader ordering.
- Run both compiler builds, sanitizer builds, and the consumer harness before
  opening a pull request.
