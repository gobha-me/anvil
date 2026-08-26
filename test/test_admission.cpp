#include <arpa/inet.h>
#include <netinet/in.h>

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <stdexcept>
#include <string>
#include <string_view>

#include "admission.hpp"

namespace {

using anvil::server::AdmissionController;
using anvil::server::AdmissionDecision;
using anvil::server::PeerAddress;
using anvil::server::RateLimit;
using namespace std::chrono_literals;

[[nodiscard]] PeerAddress ipv4(std::string_view text) {
  sockaddr_in address{};
  address.sin_family = AF_INET;
  const std::string value(text);
  REQUIRE(::inet_pton(AF_INET, value.c_str(), &address.sin_addr) == 1);
  const auto peer = PeerAddress::from_sockaddr(reinterpret_cast<const sockaddr *>(&address),
                                                sizeof(address));
  REQUIRE(peer.has_value());
  return *peer;
}

}  // namespace

TEST_CASE("peer addresses normalize IPv4-mapped IPv6") {
  sockaddr_in6 mapped{};
  mapped.sin6_family = AF_INET6;
  REQUIRE(::inet_pton(AF_INET6, "::ffff:192.0.2.42", &mapped.sin6_addr) == 1);
  const auto normalized = PeerAddress::from_sockaddr(
      reinterpret_cast<const sockaddr *>(&mapped), sizeof(mapped));
  REQUIRE(normalized.has_value());
  CHECK(*normalized == ipv4("192.0.2.42"));

  sockaddr unsupported{};
  unsupported.sa_family = AF_UNIX;
  CHECK_FALSE(PeerAddress::from_sockaddr(&unsupported, sizeof(unsupported)));
  CHECK_FALSE(PeerAddress::from_sockaddr(nullptr, 0));
}

TEST_CASE("admission enforces connection and concurrency limits before allocation") {
  const auto start = AdmissionController::Clock::time_point{};
  AdmissionController admission(2, 1, RateLimit{2, 10s}, RateLimit{2, 20s}, 4);
  const auto first = ipv4("192.0.2.1");
  const auto second = ipv4("192.0.2.2");
  const auto third = ipv4("192.0.2.3");

  CHECK(admission.admit(first, start) == AdmissionDecision::allowed);
  CHECK(admission.admit(first, start) == AdmissionDecision::per_ip_concurrency);
  CHECK(admission.admit(second, start) == AdmissionDecision::allowed);
  CHECK(admission.admit(third, start) == AdmissionDecision::global_concurrency);
  CHECK(admission.active_sessions() == 2);
  CHECK(admission.tracked_ips() == 2);

  admission.release(first, start);
  CHECK(admission.admit(first, start) == AdmissionDecision::connection_rate);
  CHECK(admission.admit(first, start + 5s) == AdmissionDecision::allowed);
  CHECK(admission.active_sessions() == 2);
}

TEST_CASE("denied authentication attempts block later key exchange and refill") {
  const auto start = AdmissionController::Clock::time_point{};
  AdmissionController admission(2, 2, RateLimit{10, 10s}, RateLimit{2, 20s}, 4);
  const auto peer = ipv4("198.51.100.7");

  CHECK(admission.admit(peer, start) == AdmissionDecision::allowed);
  admission.denied_auth_attempt(peer, start);
  admission.denied_auth_attempt(peer, start);
  admission.release(peer, start);

  CHECK(admission.admit(peer, start) == AdmissionDecision::auth_attempt_rate);
  CHECK(admission.admit(peer, start + 10s) == AdmissionDecision::allowed);
  admission.release(peer, start + 10s);

  admission.exhaust_auth_attempts(peer, start + 10s);
  CHECK(admission.admit(peer, start + 19s) == AdmissionDecision::auth_attempt_rate);
  CHECK(admission.admit(peer, start + 20s) == AdmissionDecision::allowed);
}

TEST_CASE("inactive limiter state is bounded and evicted after refill") {
  const auto start = AdmissionController::Clock::time_point{};
  AdmissionController admission(1, 1, RateLimit{1, 10s}, RateLimit{1, 20s}, 1);
  const auto first = ipv4("203.0.113.1");
  const auto second = ipv4("203.0.113.2");

  CHECK(admission.admit(first, start) == AdmissionDecision::allowed);
  admission.release(first, start);
  CHECK(admission.admit(second, start + 19s) == AdmissionDecision::tracking_capacity);
  CHECK(admission.admit(second, start + 20s) == AdmissionDecision::allowed);
  CHECK(admission.tracked_ips() == 1);
}

TEST_CASE("admission rejects invalid programmatic configuration") {
  CHECK_THROWS_AS(AdmissionController(0, 1, RateLimit{1, 1s}, RateLimit{1, 1s}, 1),
                  std::invalid_argument);
  CHECK_THROWS_AS(AdmissionController(2, 3, RateLimit{1, 1s}, RateLimit{1, 1s}, 2),
                  std::invalid_argument);
  CHECK_THROWS_AS(AdmissionController(2, 1, RateLimit{1, 1s}, RateLimit{0, 1s}, 2),
                  std::invalid_argument);
}
