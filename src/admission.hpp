#pragma once

#include <sys/socket.h>

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <unordered_map>

#include "server.hpp"

namespace anvil::server {

struct PeerAddress {
  std::array<std::uint8_t, 16> bytes{};
  std::uint32_t scope_id{};
  std::uint8_t size{};

  [[nodiscard]] static std::optional<PeerAddress> from_sockaddr(const sockaddr *address,
                                                                socklen_t length) noexcept;

  friend bool operator==(const PeerAddress &, const PeerAddress &) = default;
};

struct PeerAddressHash {
  [[nodiscard]] std::size_t operator()(const PeerAddress &address) const noexcept;
};

enum class AdmissionDecision {
  allowed,
  global_concurrency,
  per_ip_concurrency,
  connection_rate,
  auth_attempt_rate,
  tracking_capacity,
};

class AdmissionController {
 public:
  using Clock = std::chrono::steady_clock;

  AdmissionController(std::uint32_t max_sessions, std::uint32_t max_sessions_per_ip,
                      RateLimit connection_rate, RateLimit auth_attempt_rate,
                      std::uint32_t max_tracked_ips);

  [[nodiscard]] AdmissionDecision admit(const PeerAddress &peer, Clock::time_point now);
  void release(const PeerAddress &peer, Clock::time_point now) noexcept;
  void denied_auth_attempt(const PeerAddress &peer, Clock::time_point now) noexcept;
  void exhaust_auth_attempts(const PeerAddress &peer, Clock::time_point now) noexcept;

  [[nodiscard]] std::size_t active_sessions() const noexcept { return active_sessions_; }
  [[nodiscard]] std::size_t tracked_ips() const noexcept { return peers_.size(); }

 private:
  class TokenBucket {
   public:
    TokenBucket() = default;
    TokenBucket(RateLimit rate, Clock::time_point now);

    [[nodiscard]] bool consume(Clock::time_point now) noexcept;
    [[nodiscard]] bool available(Clock::time_point now) noexcept;
    void exhaust(Clock::time_point now) noexcept;

   private:
    void refill(Clock::time_point now) noexcept;

    RateLimit rate_{};
    long double tokens_{};
    Clock::time_point updated_at_{};
  };

  struct PeerState {
    PeerState(RateLimit connection_rate, RateLimit auth_attempt_rate, Clock::time_point now)
        : connections(connection_rate, now), auth_attempts(auth_attempt_rate, now),
          last_seen(now) {}

    TokenBucket connections;
    TokenBucket auth_attempts;
    Clock::time_point last_seen;
    std::uint32_t active_sessions{};
  };

  using PeerMap = std::unordered_map<PeerAddress, PeerState, PeerAddressHash>;

  void prune(Clock::time_point now);

  std::uint32_t max_sessions_;
  std::uint32_t max_sessions_per_ip_;
  RateLimit connection_rate_;
  RateLimit auth_attempt_rate_;
  std::uint32_t max_tracked_ips_;
  std::chrono::seconds idle_retention_;
  PeerMap peers_;
  std::size_t active_sessions_{};
};

}  // namespace anvil::server
