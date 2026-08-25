#pragma once

#include <cstdlib>
#include <fstream>
#include <string_view>

inline auto append_event(std::string_view event) noexcept -> void {
  const char *path = std::getenv("ANVIL_LOADER_EVENT_FILE");
  if (path == nullptr || *path == '\0')
    return;

  try {
    std::ofstream out{path, std::ios::app};
    out << event << '\n';
  } catch (...) {
  }
}
