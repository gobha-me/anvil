#pragma once

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <expected>
#include <string>
#include <string_view>
#include <utility>

namespace anvil::server {

enum class ResourceLimitReason : std::uint8_t {
  none,
  memory,
  cpu,
  output,
  image,
  duration,
};

struct SessionResourceLimits {
  std::uint64_t memory_bytes{64U << 20U};
  std::chrono::nanoseconds cpu_burst{std::chrono::milliseconds(250)};
  std::uint64_t output_bytes_per_second{1'000'000U};
  std::uint64_t image_bytes{32U << 20U};
};

class ResourceLimitError final : public std::exception {
public:
  explicit ResourceLimitError(ResourceLimitReason reason) noexcept
      : reason_(reason) {}

  [[nodiscard]] ResourceLimitReason reason() const noexcept { return reason_; }
  [[nodiscard]] const char *what() const noexcept override;

private:
  ResourceLimitReason reason_;
};

class SessionResources {
public:
  using Clock = std::chrono::steady_clock;

  explicit SessionResources(SessionResourceLimits limits,
                            Clock::time_point now = Clock::now());

  SessionResources(const SessionResources &) = delete;
  auto operator=(const SessionResources &) -> SessionResources & = delete;

  [[nodiscard]] const SessionResourceLimits &limits() const noexcept {
    return limits_;
  }
  [[nodiscard]] ResourceLimitReason limit_reason() const noexcept;
  void mark_exceeded(ResourceLimitReason reason) noexcept;

  [[nodiscard]] bool reserve_memory(std::uint64_t bytes) noexcept;
  void release_memory(std::uint64_t bytes) noexcept;
  [[nodiscard]] std::uint64_t memory_bytes() const noexcept;

  [[nodiscard]] bool reserve_image(std::uint64_t source_payload_bytes) noexcept;
  void reconcile_image(std::uint64_t source_payload_bytes) noexcept;
  [[nodiscard]] std::uint64_t image_bytes() const noexcept;

  [[nodiscard]] std::expected<Clock::duration, ResourceLimitReason>
  output_delay(std::size_t frame_bytes, Clock::time_point now) noexcept;
  void consume_output(std::size_t frame_bytes) noexcept;

private:
  [[nodiscard]] static bool reserve(std::atomic<std::uint64_t> &used,
                                    std::uint64_t limit,
                                    std::uint64_t amount) noexcept;

  SessionResourceLimits limits_;
  std::atomic<ResourceLimitReason> limit_reason_{ResourceLimitReason::none};
  std::atomic<std::uint64_t> memory_bytes_{};
  std::atomic<std::uint64_t> image_bytes_{};
  Clock::time_point output_updated_;
  long double output_tokens_{};
};

class WorkerMemoryGuard {
public:
  static auto arm(std::uint64_t headroom_bytes)
      -> std::expected<WorkerMemoryGuard, std::string>;

  WorkerMemoryGuard(const WorkerMemoryGuard &) = delete;
  auto operator=(const WorkerMemoryGuard &) -> WorkerMemoryGuard & = delete;
  WorkerMemoryGuard(WorkerMemoryGuard &&) noexcept = default;
  auto operator=(WorkerMemoryGuard &&) noexcept
      -> WorkerMemoryGuard & = default;

  [[nodiscard]] bool exceeded() const noexcept;
  void release_emergency_reserve() noexcept;
  [[nodiscard]] std::uint64_t baseline_bytes() const noexcept {
    return baseline_bytes_;
  }
  [[nodiscard]] std::uint64_t ceiling_bytes() const noexcept {
    return ceiling_bytes_;
  }

private:
  WorkerMemoryGuard(std::uint64_t baseline_bytes, std::uint64_t ceiling_bytes,
                    std::string emergency_reserve)
      : baseline_bytes_(baseline_bytes), ceiling_bytes_(ceiling_bytes),
        emergency_reserve_(std::move(emergency_reserve)) {}

  std::uint64_t baseline_bytes_{};
  std::uint64_t ceiling_bytes_{};
  std::string emergency_reserve_;
};

[[nodiscard]] std::uint64_t current_address_space_bytes() noexcept;
[[nodiscard]] std::string_view
resource_limit_name(ResourceLimitReason reason) noexcept;
[[nodiscard]] std::string_view
resource_limit_message(ResourceLimitReason reason) noexcept;

} // namespace anvil::server
