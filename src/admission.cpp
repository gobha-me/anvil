#include "admission.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>

#include <algorithm>
#include <cstring>
#include <stdexcept>

namespace anvil::server {
namespace {

constexpr std::uint64_t hash_offset = 1469598103934665603ULL;
constexpr std::uint64_t hash_prime = 1099511628211ULL;

void hash_byte(std::uint64_t &hash, std::uint8_t byte) noexcept {
  hash ^= byte;
  hash *= hash_prime;
}

}  // namespace

std::optional<PeerAddress> PeerAddress::from_sockaddr(const sockaddr *address,
                                                      socklen_t length) noexcept {
  if (address == nullptr) {
    return std::nullopt;
  }
  PeerAddress result;
  if (address->sa_family == AF_INET && length >= sizeof(sockaddr_in)) {
    const auto *ipv4 = reinterpret_cast<const sockaddr_in *>(address);
    std::memcpy(result.bytes.data(), &ipv4->sin_addr, sizeof(ipv4->sin_addr));
    result.size = 4;
    return result;
  }
  if (address->sa_family == AF_INET6 && length >= sizeof(sockaddr_in6)) {
    const auto *ipv6 = reinterpret_cast<const sockaddr_in6 *>(address);
    if (IN6_IS_ADDR_V4MAPPED(&ipv6->sin6_addr)) {
      std::memcpy(result.bytes.data(), ipv6->sin6_addr.s6_addr + 12, 4);
      result.size = 4;
      return result;
    }
    std::memcpy(result.bytes.data(), &ipv6->sin6_addr, sizeof(ipv6->sin6_addr));
    result.scope_id = ipv6->sin6_scope_id;
    result.size = 16;
    return result;
  }
  return std::nullopt;
}

std::size_t PeerAddressHash::operator()(const PeerAddress &address) const noexcept {
  auto hash = hash_offset;
  hash_byte(hash, address.size);
  for (std::size_t index = 0; index < address.size; ++index) {
    hash_byte(hash, address.bytes[index]);
  }
  for (unsigned int shift = 0; shift < 32U; shift += 8U) {
    hash_byte(hash, static_cast<std::uint8_t>(address.scope_id >> shift));
  }
  return static_cast<std::size_t>(hash);
}

AdmissionController::TokenBucket::TokenBucket(RateLimit rate, Clock::time_point now)
    : rate_(rate), tokens_(rate.count), updated_at_(now) {}

void AdmissionController::TokenBucket::refill(Clock::time_point now) noexcept {
  if (now <= updated_at_) {
    return;
  }
  const auto elapsed = std::chrono::duration<long double>(now - updated_at_).count();
  const auto period = std::chrono::duration<long double>(rate_.period).count();
  tokens_ = std::min<long double>(rate_.count,
                                  tokens_ + elapsed * static_cast<long double>(rate_.count) / period);
  updated_at_ = now;
}

bool AdmissionController::TokenBucket::consume(Clock::time_point now) noexcept {
  refill(now);
  if (tokens_ < 1.0L) {
    return false;
  }
  tokens_ -= 1.0L;
  return true;
}

bool AdmissionController::TokenBucket::available(Clock::time_point now) noexcept {
  refill(now);
  return tokens_ >= 1.0L;
}

void AdmissionController::TokenBucket::exhaust(Clock::time_point now) noexcept {
  refill(now);
  tokens_ = 0.0L;
}

AdmissionController::AdmissionController(std::uint32_t max_sessions,
                                         std::uint32_t max_sessions_per_ip,
                                         RateLimit connection_rate,
                                         RateLimit auth_attempt_rate,
                                         std::uint32_t max_tracked_ips)
    : max_sessions_(max_sessions), max_sessions_per_ip_(max_sessions_per_ip),
      connection_rate_(connection_rate), auth_attempt_rate_(auth_attempt_rate),
      max_tracked_ips_(max_tracked_ips),
      idle_retention_(std::max(connection_rate.period, auth_attempt_rate.period)) {
  if (max_sessions_ == 0U || max_sessions_per_ip_ == 0U ||
      max_sessions_per_ip_ > max_sessions_ || max_tracked_ips_ < max_sessions_ ||
      connection_rate_.count == 0U || connection_rate_.period <= std::chrono::seconds::zero() ||
      auth_attempt_rate_.count == 0U ||
      auth_attempt_rate_.period <= std::chrono::seconds::zero()) {
    throw std::invalid_argument("invalid SSH admission limit configuration");
  }
  peers_.reserve(max_tracked_ips_);
}

AdmissionDecision AdmissionController::admit(const PeerAddress &peer, Clock::time_point now) {
  auto found = peers_.find(peer);
  if (found == peers_.end()) {
    if (active_sessions_ >= max_sessions_) {
      return AdmissionDecision::global_concurrency;
    }
    if (peers_.size() >= max_tracked_ips_) {
      prune(now);
    }
    if (peers_.size() >= max_tracked_ips_) {
      return AdmissionDecision::tracking_capacity;
    }
    found = peers_.emplace(peer, PeerState(connection_rate_, auth_attempt_rate_, now)).first;
  }

  auto &state = found->second;
  state.last_seen = now;
  if (!state.connections.consume(now)) {
    return AdmissionDecision::connection_rate;
  }
  if (!state.auth_attempts.available(now)) {
    return AdmissionDecision::auth_attempt_rate;
  }
  if (active_sessions_ >= max_sessions_) {
    return AdmissionDecision::global_concurrency;
  }
  if (state.active_sessions >= max_sessions_per_ip_) {
    return AdmissionDecision::per_ip_concurrency;
  }
  ++state.active_sessions;
  ++active_sessions_;
  return AdmissionDecision::allowed;
}

void AdmissionController::release(const PeerAddress &peer, Clock::time_point now) noexcept {
  const auto found = peers_.find(peer);
  if (found == peers_.end() || found->second.active_sessions == 0U) {
    return;
  }
  --found->second.active_sessions;
  --active_sessions_;
  found->second.last_seen = now;
}

void AdmissionController::denied_auth_attempt(const PeerAddress &peer,
                                              Clock::time_point now) noexcept {
  const auto found = peers_.find(peer);
  if (found == peers_.end()) {
    return;
  }
  if (!found->second.auth_attempts.consume(now)) {
    found->second.auth_attempts.exhaust(now);
  }
  found->second.last_seen = now;
}

void AdmissionController::exhaust_auth_attempts(const PeerAddress &peer,
                                                Clock::time_point now) noexcept {
  const auto found = peers_.find(peer);
  if (found == peers_.end()) {
    return;
  }
  found->second.auth_attempts.exhaust(now);
  found->second.last_seen = now;
}

void AdmissionController::prune(Clock::time_point now) {
  for (auto entry = peers_.begin(); entry != peers_.end();) {
    const auto idle = entry->second.active_sessions == 0U &&
                      now - entry->second.last_seen >= idle_retention_;
    if (idle) {
      entry = peers_.erase(entry);
    } else {
      ++entry;
    }
  }
}

}  // namespace anvil::server
