#pragma once

#include <chrono>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

#include <sys/types.h>

#include "terminal_session.hpp"

namespace anvil::server {

enum class ComponentKind : std::uint8_t { storage, plugin };
enum class ComponentState : std::uint8_t { not_configured, ready, failed };

struct ComponentStatus {
  ComponentKind kind{};
  ComponentState state{};
  std::string name;
  std::string version;
  std::string reason;
};

struct HealthSession {
  std::uint64_t id{};
  pid_t worker{};
  std::uint64_t resident_bytes{};
  SessionTelemetry telemetry;
};

struct HealthSnapshot {
  bool accepting{};
  std::chrono::steady_clock::time_point heartbeat{};
  std::chrono::steady_clock::time_point started{};
  std::uint64_t supervisor_resident_bytes{};
  std::uint64_t health_resident_bytes{};
  std::uint64_t registered_users{};
  std::uint64_t door_sessions{};
  std::vector<HealthSession> sessions;
  std::vector<ComponentStatus> components;
};

struct HealthResponse {
  int status{};
  std::string content_type;
  std::string body;
};

[[nodiscard]] HealthResponse render_liveness(
    const HealthSnapshot &snapshot, std::chrono::steady_clock::time_point now);
[[nodiscard]] HealthResponse render_readiness(
    const HealthSnapshot &snapshot, std::chrono::steady_clock::time_point now);
[[nodiscard]] HealthResponse render_metrics(
    const HealthSnapshot &snapshot, std::chrono::steady_clock::time_point now);

class HealthMonitor {
 public:
  struct Config {
    std::string bind_address{"127.0.0.1"};
    std::uint16_t port{8080};
    std::uint32_t max_sessions{64};
    std::vector<int> close_in_child;
  };

  static auto start(const Config &config) -> std::unique_ptr<HealthMonitor>;
  ~HealthMonitor();

  HealthMonitor(const HealthMonitor &) = delete;
  auto operator=(const HealthMonitor &) -> HealthMonitor & = delete;
  HealthMonitor(HealthMonitor &&) = delete;
  auto operator=(HealthMonitor &&) -> HealthMonitor & = delete;

  void heartbeat(bool accepting);
  void set_component(const ComponentStatus &component);
  void session_started(std::uint64_t id, pid_t worker);
  void session_updated(std::uint64_t id, pid_t worker, const SessionTelemetry &telemetry);
  void session_finished(std::uint64_t id);
  [[nodiscard]] bool alive();
  [[nodiscard]] pid_t pid() const noexcept;
  void detach_in_worker() noexcept;
  void shutdown() noexcept;

 private:
  class Impl;
  explicit HealthMonitor(std::unique_ptr<Impl> impl);
  std::unique_ptr<Impl> impl_;
};

}  // namespace anvil::server
