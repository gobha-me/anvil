#pragma once

#include <atomic>
#include <chrono>
#include <expected>
#include <span>

#include <termforge/core/byte_sink.hpp>

#include "session_resources.hpp"

namespace anvil::server::detail {

class SessionSink final : public termforge::ByteSink {
public:
  SessionSink(int descriptor, SessionResources &resources,
              const std::atomic<bool> &stop_requested,
              std::chrono::steady_clock::duration stall_timeout =
                  std::chrono::seconds{5}) noexcept;

  [[nodiscard]] auto write(std::span<const char> bytes)
      -> std::expected<void, termforge::ErrorEvent> override;

private:
  using Clock = std::chrono::steady_clock;

  [[nodiscard]] auto await_output_budget(std::size_t frame_bytes)
      -> std::expected<void, termforge::ErrorEvent>;
  [[nodiscard]] auto write_complete_frame(std::span<const char> bytes)
      -> std::expected<void, termforge::ErrorEvent>;
  [[nodiscard]] auto wait_until_writable(Clock::time_point deadline) const
      -> std::expected<void, termforge::ErrorEvent>;

  int descriptor_;
  SessionResources &resources_;
  const std::atomic<bool> &stop_requested_;
  Clock::duration stall_timeout_;
};

} // namespace anvil::server::detail
