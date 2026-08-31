#include "session_resources.hpp"

#include <fcntl.h>
#include <sys/resource.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <charconv>
#include <cmath>
#include <limits>
#include <stdexcept>
#include <string_view>

namespace anvil::server {
namespace {

constexpr std::size_t emergency_reserve_size = 256U * 1024U;
constexpr long double nanoseconds_per_second = 1'000'000'000.0L;

[[nodiscard]] std::uint64_t saturating_add(std::uint64_t left,
                                           std::uint64_t right) noexcept {
  if (right > std::numeric_limits<std::uint64_t>::max() - left) {
    return std::numeric_limits<std::uint64_t>::max();
  }
  return left + right;
}

} // namespace

const char *ResourceLimitError::what() const noexcept {
  return "session resource limit exceeded";
}

SessionResources::SessionResources(SessionResourceLimits limits,
                                   Clock::time_point now)
    : limits_(limits), output_updated_(now),
      output_tokens_(static_cast<long double>(limits.output_bytes_per_second)) {
  if (limits_.memory_bytes == 0U ||
      limits_.cpu_burst <= Clock::duration::zero() ||
      limits_.output_bytes_per_second == 0U || limits_.image_bytes == 0U) {
    throw std::invalid_argument("session resource limits must be positive");
  }
}

ResourceLimitReason SessionResources::limit_reason() const noexcept {
  return limit_reason_.load(std::memory_order_acquire);
}

void SessionResources::mark_exceeded(ResourceLimitReason reason) noexcept {
  if (reason == ResourceLimitReason::none) {
    return;
  }
  auto expected = ResourceLimitReason::none;
  static_cast<void>(limit_reason_.compare_exchange_strong(
      expected, reason, std::memory_order_acq_rel, std::memory_order_acquire));
}

bool SessionResources::reserve(std::atomic<std::uint64_t> &used,
                               std::uint64_t limit,
                               std::uint64_t amount) noexcept {
  auto current = used.load(std::memory_order_acquire);
  for (;;) {
    if (amount > limit || current > limit - amount) {
      return false;
    }
    if (used.compare_exchange_weak(current, current + amount,
                                   std::memory_order_acq_rel,
                                   std::memory_order_acquire)) {
      return true;
    }
  }
}

bool SessionResources::reserve_memory(std::uint64_t bytes) noexcept {
  if (reserve(memory_bytes_, limits_.memory_bytes, bytes)) {
    return true;
  }
  mark_exceeded(ResourceLimitReason::memory);
  return false;
}

void SessionResources::release_memory(std::uint64_t bytes) noexcept {
  auto current = memory_bytes_.load(std::memory_order_acquire);
  for (;;) {
    const auto wanted = bytes >= current ? 0U : current - bytes;
    if (memory_bytes_.compare_exchange_weak(current, wanted,
                                            std::memory_order_acq_rel,
                                            std::memory_order_acquire)) {
      return;
    }
  }
}

std::uint64_t SessionResources::memory_bytes() const noexcept {
  return memory_bytes_.load(std::memory_order_acquire);
}

bool SessionResources::reserve_image(
    std::uint64_t source_payload_bytes) noexcept {
  if (reserve(image_bytes_, limits_.image_bytes, source_payload_bytes)) {
    return true;
  }
  mark_exceeded(ResourceLimitReason::image);
  return false;
}

void SessionResources::reconcile_image(
    std::uint64_t source_payload_bytes) noexcept {
  image_bytes_.store(source_payload_bytes, std::memory_order_release);
  if (source_payload_bytes > limits_.image_bytes) {
    mark_exceeded(ResourceLimitReason::image);
  }
}

std::uint64_t SessionResources::image_bytes() const noexcept {
  return image_bytes_.load(std::memory_order_acquire);
}

std::expected<SessionResources::Clock::duration, ResourceLimitReason>
SessionResources::output_delay(std::size_t frame_bytes,
                               Clock::time_point now) noexcept {
  if (frame_bytes > limits_.output_bytes_per_second) {
    mark_exceeded(ResourceLimitReason::output);
    return std::unexpected(ResourceLimitReason::output);
  }
  if (now > output_updated_) {
    const auto elapsed =
        std::chrono::duration<long double>(now - output_updated_).count();
    output_tokens_ = std::min<long double>(
        static_cast<long double>(limits_.output_bytes_per_second),
        output_tokens_ + elapsed * static_cast<long double>(
                                       limits_.output_bytes_per_second));
    output_updated_ = now;
  }
  const auto wanted = static_cast<long double>(frame_bytes);
  if (output_tokens_ >= wanted) {
    return Clock::duration::zero();
  }
  const auto missing = wanted - output_tokens_;
  const auto delay_nanoseconds =
      std::ceil(missing * nanoseconds_per_second /
                static_cast<long double>(limits_.output_bytes_per_second));
  if (delay_nanoseconds >=
      static_cast<long double>(std::numeric_limits<std::int64_t>::max())) {
    mark_exceeded(ResourceLimitReason::output);
    return std::unexpected(ResourceLimitReason::output);
  }
  return std::chrono::nanoseconds(static_cast<std::int64_t>(delay_nanoseconds));
}

void SessionResources::consume_output(std::size_t frame_bytes) noexcept {
  output_tokens_ = std::max<long double>(
      0.0L, output_tokens_ - static_cast<long double>(frame_bytes));
}

std::uint64_t current_address_space_bytes() noexcept {
  const int descriptor = ::open("/proc/self/statm", O_RDONLY | O_CLOEXEC);
  if (descriptor < 0) {
    return 0U;
  }
  std::array<char, 128> buffer{};
  ssize_t count = -1;
  do {
    count = ::read(descriptor, buffer.data(), buffer.size() - 1U);
  } while (count < 0 && errno == EINTR);
  static_cast<void>(::close(descriptor));
  if (count <= 0) {
    return 0U;
  }
  std::uint64_t pages = 0U;
  const auto parsed =
      std::from_chars(buffer.data(), buffer.data() + count, pages);
  const auto page_size = ::sysconf(_SC_PAGESIZE);
  if (parsed.ec != std::errc{} || page_size <= 0) {
    return 0U;
  }
  const auto page_bytes = static_cast<std::uint64_t>(page_size);
  if (pages > std::numeric_limits<std::uint64_t>::max() / page_bytes) {
    return std::numeric_limits<std::uint64_t>::max();
  }
  return pages * page_bytes;
}

auto WorkerMemoryGuard::arm(std::uint64_t headroom_bytes)
    -> std::expected<WorkerMemoryGuard, std::string> {
  std::string emergency_reserve(emergency_reserve_size, '\0');
  const auto baseline = current_address_space_bytes();
  if (baseline == 0U) {
    return std::unexpected("cannot read worker address-space usage");
  }
  const auto ceiling = saturating_add(baseline, headroom_bytes);
  if (ceiling == std::numeric_limits<std::uint64_t>::max() ||
      ceiling > std::numeric_limits<rlim_t>::max()) {
    return std::unexpected("session memory ceiling overflows RLIMIT_AS");
  }
  rlimit existing{};
  if (::getrlimit(RLIMIT_AS, &existing) != 0) {
    return std::unexpected("cannot read RLIMIT_AS");
  }
  if (existing.rlim_max != RLIM_INFINITY && ceiling > existing.rlim_max) {
    return std::unexpected(
        "session memory ceiling exceeds the worker hard limit");
  }
  const rlimit wanted{static_cast<rlim_t>(ceiling),
                      static_cast<rlim_t>(ceiling)};
  if (::setrlimit(RLIMIT_AS, &wanted) != 0) {
    return std::unexpected("cannot apply the session memory ceiling");
  }
  return WorkerMemoryGuard(baseline, ceiling, std::move(emergency_reserve));
}

bool WorkerMemoryGuard::exceeded() const noexcept {
  const auto current = current_address_space_bytes();
  return current == 0U || current > ceiling_bytes_;
}

void WorkerMemoryGuard::release_emergency_reserve() noexcept {
  std::string{}.swap(emergency_reserve_);
}

std::string_view resource_limit_name(ResourceLimitReason reason) noexcept {
  switch (reason) {
  case ResourceLimitReason::none:
    return "none";
  case ResourceLimitReason::memory:
    return "memory";
  case ResourceLimitReason::cpu:
    return "cpu";
  case ResourceLimitReason::output:
    return "output";
  case ResourceLimitReason::image:
    return "image";
  case ResourceLimitReason::duration:
    return "duration";
  }
  return "unknown";
}

std::string_view resource_limit_message(ResourceLimitReason reason) noexcept {
  switch (reason) {
  case ResourceLimitReason::memory:
    return "Anvil: this session exceeded its memory limit; closing.\r\n";
  case ResourceLimitReason::cpu:
    return "Anvil: this session exceeded its CPU time slice; closing.\r\n";
  case ResourceLimitReason::output:
    return "Anvil: this session exceeded its output limit; closing.\r\n";
  case ResourceLimitReason::image:
    return "Anvil: this session exceeded its terminal image quota; "
           "closing.\r\n";
  case ResourceLimitReason::duration:
    return "Anvil: maximum session duration reached; closing.\r\n";
  case ResourceLimitReason::none:
    break;
  }
  return "Anvil: this session exceeded a resource limit; closing.\r\n";
}

} // namespace anvil::server
