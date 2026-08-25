#include <array>
#include <catch2/catch_test_macros.hpp>
#include <stdexcept>
#include <string_view>

#include "server.hpp"
#include "terminal_session.hpp"

TEST_CASE("server CLI requires host and authorized keys") {
  const std::array<std::string_view, 0> arguments{};
  CHECK_THROWS_AS(anvil::server::parse_arguments(arguments), std::runtime_error);
}

TEST_CASE("server CLI parses an explicit endpoint and repeated keys") {
  const std::array arguments{
      std::string_view{"--bind-address"},
      std::string_view{"::1"},
      std::string_view{"--port"},
      std::string_view{"22022"},
      std::string_view{"--max-sessions"},
      std::string_view{"12"},
      std::string_view{"--idle-timeout-seconds"},
      std::string_view{"600"},
      std::string_view{"--idle-warning-seconds"},
      std::string_view{"45"},
      std::string_view{"--session-cap-seconds"},
      std::string_view{"7200"},
      std::string_view{"--host-key"},
      std::string_view{"host_key"},
      std::string_view{"--authorized-key"},
      std::string_view{"alice=alice.pub"},
      std::string_view{"--authorized-key"},
      std::string_view{"bob=bob.pub"},
  };

  const auto parsed = anvil::server::parse_arguments(arguments);

  CHECK_FALSE(parsed.show_help);
  CHECK(parsed.config.bind_address == "::1");
  CHECK(parsed.config.port == 22022);
  CHECK(parsed.config.max_sessions == 12);
  CHECK(parsed.config.idle_timeout.count() == 600);
  CHECK(parsed.config.idle_warning.count() == 45);
  CHECK(parsed.config.session_cap.count() == 7200);
  REQUIRE(parsed.config.authorized_keys.size() == 2);
  CHECK(parsed.config.authorized_keys[0].user == "alice");
  CHECK(parsed.config.authorized_keys[0].path == "alice.pub");
  CHECK(parsed.config.authorized_keys[1].user == "bob");
}

TEST_CASE("server CLI rejects malformed hostile values") {
  const auto parse = [](std::string_view option, std::string_view value) {
    const std::array arguments{
        std::string_view{"--host-key"},
        std::string_view{"host_key"},
        std::string_view{"--authorized-key"},
        std::string_view{"user=key.pub"},
        option,
        value,
    };
    return anvil::server::parse_arguments(arguments);
  };

  CHECK_THROWS_AS(parse("--port", "0"), std::runtime_error);
  CHECK_THROWS_AS(parse("--port", "65536"), std::runtime_error);
  CHECK_THROWS_AS(parse("--port", "22x"), std::runtime_error);
  CHECK_THROWS_AS(parse("--max-sessions", "0"), std::runtime_error);
  CHECK_THROWS_AS(parse("--max-sessions", "4097"), std::runtime_error);
  CHECK_THROWS_AS(parse("--idle-timeout-seconds", "0"), std::runtime_error);
  CHECK_THROWS_AS(parse("--idle-timeout-seconds", "1x"), std::runtime_error);
  CHECK_THROWS_AS(parse("--idle-timeout-seconds", "4294967296"), std::runtime_error);
  CHECK_THROWS_AS(parse("--idle-warning-seconds", "0"), std::runtime_error);
  CHECK_THROWS_AS(parse("--session-cap-seconds", "0"), std::runtime_error);
  CHECK_THROWS_AS(parse("--authorized-key", "=key.pub"), std::runtime_error);
  CHECK_THROWS_AS(parse("--authorized-key", "user="), std::runtime_error);
  CHECK_THROWS_AS(parse("--unknown", "value"), std::runtime_error);
}

TEST_CASE("server CLI applies lifecycle defaults and validates warning order") {
  const std::array required{
      std::string_view{"--host-key"},
      std::string_view{"host_key"},
      std::string_view{"--authorized-key"},
      std::string_view{"user=key.pub"},
  };
  const auto parsed = anvil::server::parse_arguments(required);
  CHECK(parsed.config.idle_timeout.count() == 300);
  CHECK(parsed.config.idle_warning.count() == 30);
  CHECK(parsed.config.session_cap.count() == 86'400);

  const std::array invalid{
      std::string_view{"--host-key"},
      std::string_view{"host_key"},
      std::string_view{"--authorized-key"},
      std::string_view{"user=key.pub"},
      std::string_view{"--idle-timeout-seconds"},
      std::string_view{"30"},
      std::string_view{"--idle-warning-seconds"},
      std::string_view{"30"},
  };
  CHECK_THROWS_AS(anvil::server::parse_arguments(invalid), std::runtime_error);
}

TEST_CASE("server CLI help does not require operational arguments") {
  const std::array arguments{std::string_view{"--help"}};
  const auto parsed = anvil::server::parse_arguments(arguments);
  CHECK(parsed.show_help);
}

TEST_CASE("SSH terminal dimensions bound hostile peer claims") {
  using anvil::server::TerminalDimensions;

  CHECK((anvil::server::normalize_initial_dimensions(120, 40, 1200, 800) ==
         TerminalDimensions{120, 40, 1200, 800}));
  CHECK((anvil::server::normalize_initial_dimensions(0, 0, 0, 0) ==
         TerminalDimensions{80, 24, 0, 0}));
  CHECK((anvil::server::normalize_initial_dimensions(1001, 24, -1, 100) ==
         TerminalDimensions{80, 24, 0, 0}));

  CHECK((anvil::server::normalize_resize_dimensions(200, 60, 0, 0) ==
         TerminalDimensions{200, 60, 0, 0}));
  CHECK_FALSE(anvil::server::normalize_resize_dimensions(0, 60, 0, 0));
  CHECK_FALSE(anvil::server::normalize_resize_dimensions(80, 1001, 0, 0));
  CHECK((anvil::server::normalize_resize_dimensions(80, 24, 65'536, 1) ==
         TerminalDimensions{80, 24, 0, 0}));
}

TEST_CASE("SSH terminal type is a bounded printable hint") {
  CHECK(anvil::server::normalize_terminal_type(nullptr).empty());
  CHECK(anvil::server::normalize_terminal_type("xterm-256color") == "xterm-256color");
  CHECK(anvil::server::normalize_terminal_type("xterm\x1b[31m").empty());
  const std::string oversized(257, 'x');
  CHECK(anvil::server::normalize_terminal_type(oversized.c_str()).empty());
}
