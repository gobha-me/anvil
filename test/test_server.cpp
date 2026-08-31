#include <array>
#include <catch2/catch_test_macros.hpp>
#include <chrono>
#include <stdexcept>
#include <string_view>

#include "server.hpp"
#include "terminal_session.hpp"

TEST_CASE("server CLI requires a host key") {
  const std::array<std::string_view, 0> arguments{};
  CHECK_THROWS_AS(anvil::server::parse_arguments(arguments),
                  std::runtime_error);
}

TEST_CASE("server CLI permits guest and registration service without bootstrap "
          "keys") {
  const std::array arguments{
      std::string_view{"--host-key"},
      std::string_view{"host_key"},
  };
  const auto parsed = anvil::server::parse_arguments(arguments);
  CHECK(parsed.config.authorized_keys.empty());
}

TEST_CASE("server CLI parses an explicit endpoint and repeated keys") {
  const std::array arguments{
      std::string_view{"--bind-address"},
      std::string_view{"::1"},
      std::string_view{"--port"},
      std::string_view{"22022"},
      std::string_view{"--health-bind-address"},
      std::string_view{"127.0.0.2"},
      std::string_view{"--health-port"},
      std::string_view{"22023"},
      std::string_view{"--database"},
      std::string_view{"state/anvil.db"},
      std::string_view{"--registration-mode"},
      std::string_view{"invite"},
      std::string_view{"--max-sessions"},
      std::string_view{"12"},
      std::string_view{"--max-sessions-per-ip"},
      std::string_view{"3"},
      std::string_view{"--connection-rate-limit"},
      std::string_view{"20/30"},
      std::string_view{"--auth-attempt-rate-limit"},
      std::string_view{"4/120"},
      std::string_view{"--max-auth-attempts-per-session"},
      std::string_view{"2"},
      std::string_view{"--max-tracked-ips"},
      std::string_view{"100"},
      std::string_view{"--idle-timeout-seconds"},
      std::string_view{"600"},
      std::string_view{"--idle-warning-seconds"},
      std::string_view{"45"},
      std::string_view{"--session-cap-seconds"},
      std::string_view{"7200"},
      std::string_view{"--session-memory-bytes"},
      std::string_view{"134217728"},
      std::string_view{"--session-cpu-burst-ms"},
      std::string_view{"75"},
      std::string_view{"--session-output-bytes-per-second"},
      std::string_view{"2000000"},
      std::string_view{"--session-image-bytes"},
      std::string_view{"67108864"},
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
  CHECK(parsed.config.health_bind_address == "127.0.0.2");
  CHECK(parsed.config.health_port == 22023);
  CHECK(parsed.config.database_path == "state/anvil.db");
  CHECK(parsed.config.registration_mode ==
        anvil::server::RegistrationMode::invite);
  CHECK(parsed.config.max_sessions == 12);
  CHECK(parsed.config.max_sessions_per_ip == 3);
  CHECK(parsed.config.connection_rate.count == 20);
  CHECK(parsed.config.connection_rate.period.count() == 30);
  CHECK(parsed.config.auth_attempt_rate.count == 4);
  CHECK(parsed.config.auth_attempt_rate.period.count() == 120);
  CHECK(parsed.config.max_auth_attempts_per_session == 2);
  CHECK(parsed.config.max_tracked_ips == 100);
  CHECK(parsed.config.idle_timeout.count() == 600);
  CHECK(parsed.config.idle_warning.count() == 45);
  CHECK(parsed.config.session_cap.count() == 7200);
  CHECK(parsed.config.session_resources.memory_bytes == 134'217'728U);
  CHECK(parsed.config.session_resources.cpu_burst ==
        std::chrono::milliseconds(75));
  CHECK(parsed.config.session_resources.output_bytes_per_second == 2'000'000U);
  CHECK(parsed.config.session_resources.image_bytes == 67'108'864U);
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
  CHECK_THROWS_AS(parse("--health-port", "0"), std::runtime_error);
  CHECK_THROWS_AS(parse("--health-port", "65536"), std::runtime_error);
  CHECK_THROWS_AS(parse("--max-sessions", "0"), std::runtime_error);
  CHECK_THROWS_AS(parse("--max-sessions", "4097"), std::runtime_error);
  CHECK_THROWS_AS(parse("--max-sessions-per-ip", "0"), std::runtime_error);
  CHECK_THROWS_AS(parse("--connection-rate-limit", "10"), std::runtime_error);
  CHECK_THROWS_AS(parse("--connection-rate-limit", "0/10"), std::runtime_error);
  CHECK_THROWS_AS(parse("--connection-rate-limit", "10/0"), std::runtime_error);
  CHECK_THROWS_AS(parse("--auth-attempt-rate-limit", "1/2/3"),
                  std::runtime_error);
  CHECK_THROWS_AS(parse("--max-auth-attempts-per-session", "0"),
                  std::runtime_error);
  CHECK_THROWS_AS(parse("--max-tracked-ips", "65537"), std::runtime_error);
  CHECK_THROWS_AS(parse("--registration-mode", "OPEN"), std::runtime_error);
  CHECK_THROWS_AS(
      parse("--max-tracked-ips", "18446744073709551616000000000000000000"),
      std::runtime_error);
  CHECK_THROWS_AS(parse("--idle-timeout-seconds", "0"), std::runtime_error);
  CHECK_THROWS_AS(parse("--idle-timeout-seconds", "1x"), std::runtime_error);
  CHECK_THROWS_AS(parse("--idle-timeout-seconds", "4294967296"),
                  std::runtime_error);
  CHECK_THROWS_AS(parse("--idle-warning-seconds", "0"), std::runtime_error);
  CHECK_THROWS_AS(parse("--session-cap-seconds", "0"), std::runtime_error);
  CHECK_THROWS_AS(parse("--session-memory-bytes", "0"), std::runtime_error);
  CHECK_THROWS_AS(parse("--session-memory-bytes", "1099511627777"),
                  std::runtime_error);
  CHECK_THROWS_AS(parse("--session-cpu-burst-ms", "0"), std::runtime_error);
  CHECK_THROWS_AS(parse("--session-cpu-burst-ms", "60001"), std::runtime_error);
  CHECK_THROWS_AS(parse("--session-output-bytes-per-second", "0"),
                  std::runtime_error);
  CHECK_THROWS_AS(parse("--session-output-bytes-per-second", "1000000001"),
                  std::runtime_error);
  CHECK_THROWS_AS(parse("--session-image-bytes", "1x"), std::runtime_error);
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
  CHECK(parsed.config.session_resources.memory_bytes == (64U << 20U));
  CHECK(parsed.config.session_resources.cpu_burst ==
        std::chrono::milliseconds(50));
  CHECK(parsed.config.session_resources.output_bytes_per_second == 1'000'000U);
  CHECK(parsed.config.session_resources.image_bytes == (32U << 20U));
  CHECK(parsed.config.max_sessions == 64);
  CHECK(parsed.config.health_bind_address == "127.0.0.1");
  CHECK(parsed.config.health_port == 8080);
  CHECK(parsed.config.database_path == "anvil.db");
  CHECK(parsed.config.registration_mode ==
        anvil::server::RegistrationMode::open);
  CHECK(parsed.config.backup_directory.empty());
  CHECK(parsed.config.backup_interval.count() == 86'400);
  CHECK(parsed.config.backup_retention.count() == 604'800);
  CHECK(parsed.config.max_sessions_per_ip == 4);
  CHECK(parsed.config.connection_rate.count == 10);
  CHECK(parsed.config.connection_rate.period.count() == 10);
  CHECK(parsed.config.auth_attempt_rate.count == 6);
  CHECK(parsed.config.auth_attempt_rate.period.count() == 60);
  CHECK(parsed.config.max_auth_attempts_per_session == 6);
  CHECK(parsed.config.max_tracked_ips == 4096);

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

  const std::array invalid_cross_field{
      std::string_view{"--host-key"},
      std::string_view{"host_key"},
      std::string_view{"--authorized-key"},
      std::string_view{"user=key.pub"},
      std::string_view{"--max-sessions"},
      std::string_view{"2"},
      std::string_view{"--max-sessions-per-ip"},
      std::string_view{"3"},
  };
  CHECK_THROWS_AS(anvil::server::parse_arguments(invalid_cross_field),
                  std::runtime_error);

  const std::array conflicting_ports{
      std::string_view{"--host-key"},       std::string_view{"host_key"},
      std::string_view{"--authorized-key"}, std::string_view{"user=key.pub"},
      std::string_view{"--port"},           std::string_view{"8080"},
  };
  CHECK_THROWS_AS(anvil::server::parse_arguments(conflicting_ports),
                  std::runtime_error);
}

TEST_CASE("server CLI separates scheduled and offline backup modes") {
  const std::array scheduled{
      std::string_view{"--host-key"},
      std::string_view{"host_key"},
      std::string_view{"--authorized-key"},
      std::string_view{"user=key.pub"},
      std::string_view{"--backup-directory"},
      std::string_view{"backups"},
      std::string_view{"--backup-interval-seconds"},
      std::string_view{"60"},
      std::string_view{"--backup-retention-seconds"},
      std::string_view{"600"},
  };
  const auto parsed = anvil::server::parse_arguments(scheduled);
  CHECK(parsed.config.operation == anvil::server::Operation::serve);
  CHECK(parsed.config.backup_directory == "backups");
  CHECK(parsed.config.backup_interval.count() == 60);
  CHECK(parsed.config.backup_retention.count() == 600);

  const std::array one_shot{
      std::string_view{"--backup-now"}, std::string_view{"backups"},
      std::string_view{"--database"},   std::string_view{"state/anvil.db"},
      std::string_view{"--host-key"},   std::string_view{"state/host_key"},
  };
  CHECK(anvil::server::parse_arguments(one_shot).config.operation ==
        anvil::server::Operation::backup_once);

  const std::array maintenance_registration{
      std::string_view{"--backup-now"},
      std::string_view{"backups"},
      std::string_view{"--database"},
      std::string_view{"state/anvil.db"},
      std::string_view{"--host-key"},
      std::string_view{"state/host_key"},
      std::string_view{"--registration-mode"},
      std::string_view{"closed"},
  };
  CHECK_THROWS_AS(anvil::server::parse_arguments(maintenance_registration),
                  std::runtime_error);

  const std::array restore{
      std::string_view{"--restore-backup"}, std::string_view{"snapshot"},
      std::string_view{"--database"},       std::string_view{"state/anvil.db"},
      std::string_view{"--host-key"},       std::string_view{"state/host_key"},
  };
  CHECK(anvil::server::parse_arguments(restore).config.operation ==
        anvil::server::Operation::restore);

  const std::array missing_destination{
      std::string_view{"--backup-now"},
      std::string_view{"backups"},
      std::string_view{"--host-key"},
      std::string_view{"state/host_key"},
  };
  CHECK_THROWS_AS(anvil::server::parse_arguments(missing_destination),
                  std::runtime_error);

  const std::array schedule_without_directory{
      std::string_view{"--host-key"},
      std::string_view{"host_key"},
      std::string_view{"--authorized-key"},
      std::string_view{"user=key.pub"},
      std::string_view{"--backup-retention-seconds"},
      std::string_view{"600"},
  };
  CHECK_THROWS_AS(anvil::server::parse_arguments(schedule_without_directory),
                  std::runtime_error);
}

TEST_CASE("server CLI help does not require operational arguments") {
  const std::array arguments{std::string_view{"--help"}};
  const auto parsed = anvil::server::parse_arguments(arguments);
  CHECK(parsed.show_help);
  CHECK(anvil::server::usage().find("--registration-mode") !=
        std::string_view::npos);
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
  using anvil::server::RemoteBytes;

  CHECK(anvil::server::normalize_terminal_type(RemoteBytes::from_text({}))
            .empty());
  CHECK(anvil::server::normalize_terminal_type(
            RemoteBytes::from_text("xterm-256color")) == "xterm-256color");
  CHECK(anvil::server::normalize_terminal_type(
            RemoteBytes::from_text("xterm\x1b[31m"))
            .empty());
  const std::string oversized(257, 'x');
  CHECK(
      anvil::server::normalize_terminal_type(RemoteBytes::from_text(oversized))
          .empty());
}
