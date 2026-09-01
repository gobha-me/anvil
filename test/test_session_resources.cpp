#include <sys/wait.h>
#include <unistd.h>

#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <cstdint>
#include <stdexcept>

#include "session_resources.hpp"

using namespace std::chrono_literals;

TEST_CASE("session resource defaults are the conservative operator baseline") {
  const anvil::server::SessionResourceLimits limits;
  CHECK(limits.memory_bytes == (64U << 20U));
  CHECK(limits.cpu_burst == 250ms);
  CHECK(limits.output_bytes_per_second == 1'000'000U);
  CHECK(limits.image_bytes == (32U << 20U));
}

TEST_CASE("session resource construction rejects disabled limits") {
  CHECK_THROWS_AS(anvil::server::SessionResources({.memory_bytes = 0U}),
                  std::invalid_argument);
  CHECK_THROWS_AS(anvil::server::SessionResources(
                      {.cpu_burst = std::chrono::nanoseconds::zero()}),
                  std::invalid_argument);
  CHECK_THROWS_AS(
      anvil::server::SessionResources({.output_bytes_per_second = 0U}),
      std::invalid_argument);
  CHECK_THROWS_AS(anvil::server::SessionResources({.image_bytes = 0U}),
                  std::invalid_argument);
}

TEST_CASE("memory reservations fail closed without corrupting accounting") {
  anvil::server::SessionResources resources({.memory_bytes = 64U});
  CHECK(resources.reserve_memory(40U));
  CHECK_FALSE(resources.reserve_memory(25U));
  CHECK(resources.memory_bytes() == 40U);
  CHECK(resources.limit_reason() == anvil::server::ResourceLimitReason::memory);
  resources.release_memory(12U);
  CHECK(resources.memory_bytes() == 28U);
  resources.release_memory(100U);
  CHECK(resources.memory_bytes() == 0U);
}

TEST_CASE(
    "image quota reserves before upload and reconciles driver residency") {
  anvil::server::SessionResources resources({.image_bytes = 32U});
  CHECK(resources.reserve_image(20U));
  CHECK(resources.reserve_image(12U));
  CHECK_FALSE(resources.reserve_image(1U));
  CHECK(resources.image_bytes() == 32U);
  CHECK(resources.limit_reason() == anvil::server::ResourceLimitReason::image);

  anvil::server::SessionResources reconciled({.image_bytes = 32U});
  reconciled.reconcile_image(12U);
  CHECK(reconciled.reserve_image(20U));
  reconciled.reconcile_image(8U);
  CHECK(reconciled.image_bytes() == 8U);
  reconciled.reconcile_image(33U);
  CHECK(reconciled.limit_reason() == anvil::server::ResourceLimitReason::image);
}

TEST_CASE("output budget delays whole frames and refuses an impossible frame") {
  const auto start = anvil::server::SessionResources::Clock::time_point{};
  anvil::server::SessionResources resources({.output_bytes_per_second = 1'000U},
                                            start);

  REQUIRE(resources.output_delay(600U, start).value() == 0ns);
  resources.consume_output(600U);
  REQUIRE(resources.output_delay(600U, start).value() == 200ms);
  REQUIRE(resources.output_delay(600U, start + 199ms).value() == 1ms);
  REQUIRE(resources.output_delay(600U, start + 200ms).value() == 0ns);
  resources.consume_output(600U);

  const auto refused = resources.output_delay(1'001U, start + 1s);
  REQUIRE_FALSE(refused.has_value());
  CHECK(refused.error() == anvil::server::ResourceLimitReason::output);
  CHECK(resources.limit_reason() == anvil::server::ResourceLimitReason::output);
}

TEST_CASE("the first resource failure remains the reported cause") {
  anvil::server::SessionResources resources({});
  resources.mark_exceeded(anvil::server::ResourceLimitReason::cpu);
  resources.mark_exceeded(anvil::server::ResourceLimitReason::memory);
  CHECK(resources.limit_reason() == anvil::server::ResourceLimitReason::cpu);
  CHECK(anvil::server::resource_limit_name(resources.limit_reason()) == "cpu");
  CHECK(anvil::server::resource_limit_message(resources.limit_reason())
            .find("CPU") != std::string_view::npos);
}

TEST_CASE(
    "a worker memory guard installs an incremental address-space ceiling") {
  REQUIRE(anvil::server::current_address_space_bytes() > 0U);
  const auto child = ::fork();
  REQUIRE(child >= 0);
  if (child == 0) {
    constexpr std::uint64_t headroom = 16U << 20U;
    auto guard = anvil::server::WorkerMemoryGuard::arm(headroom);
    if (!guard ||
        guard->ceiling_bytes() - guard->baseline_bytes() != headroom ||
        guard->exceeded()) {
      std::_Exit(1);
    }
    std::_Exit(0);
  }
  int status = 0;
  REQUIRE(::waitpid(child, &status, 0) == child);
  CHECK(WIFEXITED(status));
  CHECK(WEXITSTATUS(status) == 0);
}
