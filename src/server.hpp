#pragma once

#include <chrono>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace anvil::server {

struct AuthorizedKeySpec {
  std::string user;
  std::string path;
};

struct Config {
  std::string bind_address{"127.0.0.1"};
  std::uint16_t port{2222};
  std::uint32_t max_sessions{64};
  std::chrono::seconds idle_timeout{300};
  std::chrono::seconds idle_warning{30};
  std::chrono::seconds session_cap{86'400};
  std::string host_key_path;
  std::vector<AuthorizedKeySpec> authorized_keys;
};

struct ParseResult {
  Config config;
  bool show_help{};
};

[[nodiscard]] ParseResult parse_arguments(std::span<const std::string_view> arguments);
[[nodiscard]] std::string_view usage() noexcept;
int run(const Config& config);

}  // namespace anvil::server
