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

struct RateLimit {
  std::uint32_t count{};
  std::chrono::seconds period{};
};

struct Config {
  std::string bind_address{"127.0.0.1"};
  std::uint16_t port{2222};
  std::uint32_t max_sessions{64};
  std::uint32_t max_sessions_per_ip{4};
  RateLimit connection_rate{10, std::chrono::seconds(10)};
  RateLimit auth_attempt_rate{6, std::chrono::seconds(60)};
  std::uint32_t max_auth_attempts_per_session{6};
  std::uint32_t max_tracked_ips{4096};
  std::chrono::seconds idle_timeout{300};
  std::chrono::seconds idle_warning{30};
  std::chrono::seconds session_cap{86'400};
  void (*session_input_hook_for_testing)(std::string_view){};
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
