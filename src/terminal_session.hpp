#pragma once

#include <chrono>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>

#include "remote_bytes.hpp"
#include "session_resources.hpp"

namespace anvil::store {
class Store;
}

namespace anvil::server {

struct SessionIdentity;
struct InvitePolicy;
enum class RegistrationMode : std::uint8_t;

struct TerminalDimensions {
  int columns{80};
  int rows{24};
  int pixel_width{};
  int pixel_height{};

  [[nodiscard]] auto operator==(const TerminalDimensions &) const noexcept
      -> bool = default;
};

inline constexpr std::size_t max_remote_terminal_type_size = 256U;

struct SessionTelemetry {
  std::uint64_t frames{};
  std::uint64_t accepted_frames{};
  std::uint64_t cell_bytes{};
  std::uint64_t image_transmit_bytes{};
  std::uint64_t image_edit_bytes{};
  std::uint64_t last_frame_cell_bytes{};
  std::uint64_t last_frame_image_transmit_bytes{};
  std::uint64_t last_frame_image_edit_bytes{};
  std::chrono::milliseconds first_frame_latency{};

  [[nodiscard]] auto operator==(const SessionTelemetry &) const noexcept
      -> bool = default;
};

enum class SessionFailureReason {
  none,
  app_returned_failure,
  standard_exception,
  unknown_exception,
  memory_limit,
  output_limit,
  image_limit,
};

struct SessionCpuProgress {
  bool ready{};
  std::uint64_t generation{};
  std::chrono::nanoseconds consumed{};
};

using SessionInputHook = void (*)(std::string_view, SessionResources &);

[[nodiscard]] TerminalDimensions
normalize_initial_dimensions(int columns, int rows, int pixel_width,
                             int pixel_height) noexcept;
[[nodiscard]] std::optional<TerminalDimensions>
normalize_resize_dimensions(int columns, int rows, int pixel_width,
                            int pixel_height) noexcept;
[[nodiscard]] std::string normalize_terminal_type(RemoteBytes terminal_type);

class TerminalSession {
public:
  TerminalSession(int io_descriptor, std::string terminal_type,
                  TerminalDimensions dimensions,
                  std::chrono::steady_clock::time_point channel_opened,
                  SessionResourceLimits resource_limits,
                  RegistrationMode registration_mode,
                  const InvitePolicy &invite_policy, SessionIdentity identity,
                  store::Store &identity_store,
                  SessionInputHook input_hook_for_testing = nullptr);
  ~TerminalSession();

  TerminalSession(const TerminalSession &) = delete;
  auto operator=(const TerminalSession &) -> TerminalSession & = delete;
  TerminalSession(TerminalSession &&) = delete;
  auto operator=(TerminalSession &&) -> TerminalSession & = delete;

  void start();
  void post_resize(TerminalDimensions dimensions);
  void post_notice(std::string notice);
  void request_stop();
  void join();

  [[nodiscard]] bool finished() const noexcept;
  [[nodiscard]] bool failed() const noexcept;
  [[nodiscard]] SessionFailureReason failure_reason() const noexcept;
  [[nodiscard]] ResourceLimitReason limit_reason() const noexcept;
  [[nodiscard]] SessionCpuProgress cpu_progress() const noexcept;
  [[nodiscard]] SessionTelemetry telemetry() const noexcept;

private:
  class Impl;
  std::unique_ptr<Impl> impl_;
};

} // namespace anvil::server
