#include "session_sink.hpp"

#include <poll.h>
#include <sys/socket.h>

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstddef>
#include <string>
#include <thread>
#include <utility>

namespace anvil::server::detail {
namespace {

using namespace std::chrono_literals;

[[nodiscard]] auto output_error(std::string message)
    -> std::unexpected<termforge::ErrorEvent> {
  return std::unexpected(termforge::ErrorEvent{termforge::Severity::Error,
                                               "ssh", std::move(message)});
}

} // namespace

SessionSink::SessionSink(int descriptor, SessionResources &resources,
                         const std::atomic<bool> &stop_requested,
                         Clock::duration stall_timeout) noexcept
    : descriptor_(descriptor), resources_(resources),
      stop_requested_(stop_requested), stall_timeout_(stall_timeout) {}

auto SessionSink::write(std::span<const char> bytes)
    -> std::expected<void, termforge::ErrorEvent> {
  if (auto admitted = await_output_budget(bytes.size()); !admitted) {
    return admitted;
  }
  return write_complete_frame(bytes);
}

auto SessionSink::await_output_budget(std::size_t frame_bytes)
    -> std::expected<void, termforge::ErrorEvent> {
  for (;;) {
    const auto delay = resources_.output_delay(frame_bytes, Clock::now());
    if (!delay) {
      return std::unexpected(termforge::ErrorEvent{
          termforge::Severity::Error, "resource.output",
          "session output frame exceeds the configured one-second burst"});
    }
    if (*delay <= Clock::duration::zero()) {
      resources_.consume_output(frame_bytes);
      return {};
    }
    if (stop_requested_.load(std::memory_order_acquire)) {
      return output_error("session output stopped");
    }
    std::this_thread::sleep_for(
        std::min(*delay, std::chrono::duration_cast<Clock::duration>(10ms)));
  }
}

auto SessionSink::write_complete_frame(std::span<const char> bytes)
    -> std::expected<void, termforge::ErrorEvent> {
  const auto deadline = Clock::now() + stall_timeout_;
  std::size_t offset = 0;
  while (offset < bytes.size()) {
    const auto count = ::send(descriptor_, bytes.data() + offset,
                              bytes.size() - offset, MSG_NOSIGNAL);
    if (count > 0) {
      offset += static_cast<std::size_t>(count);
      continue;
    }
    if (count < 0 && errno == EINTR) {
      continue;
    }
    if (count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
      if (auto writable = wait_until_writable(deadline); !writable) {
        return writable;
      }
      continue;
    }
    return output_error("SSH output channel closed");
  }
  return {};
}

auto SessionSink::wait_until_writable(Clock::time_point deadline) const
    -> std::expected<void, termforge::ErrorEvent> {
  const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
      deadline - Clock::now());
  if (remaining <= 0ms) {
    return output_error(
        "SSH output stalled before a complete frame could be queued");
  }
  pollfd descriptor{.fd = descriptor_, .events = POLLOUT, .revents = 0};
  const auto ready =
      ::poll(&descriptor, 1, static_cast<int>(remaining.count()));
  if (ready > 0 || (ready < 0 && errno == EINTR)) {
    return {};
  }
  return output_error(
      ready == 0 ? "SSH output stalled before a complete frame could be queued"
                 : "SSH output wait failed");
}

} // namespace anvil::server::detail
