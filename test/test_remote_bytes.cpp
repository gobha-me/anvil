#include <catch2/catch_test_macros.hpp>

#include <array>
#include <cstddef>
#include <string_view>
#include <vector>

#include "remote_bytes.hpp"

TEST_CASE("remote byte views reject invalid pointer and length pairs") {
  const auto invalid = anvil::server::RemoteBytes::from_raw(nullptr, 1U);
  REQUIRE_FALSE(invalid.has_value());
  CHECK(invalid.error() == anvil::server::RemoteBytesError::null_data);

  const auto empty = anvil::server::RemoteBytes::from_raw(nullptr, 0U);
  REQUIRE(empty.has_value());
  CHECK(empty->empty());
  CHECK(empty->text().empty());
}

TEST_CASE("remote byte views preserve every byte without taking ownership") {
  const std::array payload{std::byte{0x00}, std::byte{0x1b}, std::byte{0xff}};
  const auto remote = anvil::server::RemoteBytes::from_span(payload);

  CHECK(remote.size() == payload.size());
  CHECK(remote.bytes().data() == payload.data());
  CHECK(remote.bytes()[0] == std::byte{0x00});
  CHECK(remote.bytes()[1] == std::byte{0x1b});
  CHECK(remote.bytes()[2] == std::byte{0xff});
}

TEST_CASE("remote text requires an explicit provenance mark") {
  constexpr std::string_view payload{"remote text"};
  const auto remote = anvil::server::RemoteBytes::from_text(payload);

  CHECK(remote.text() == payload);
  CHECK(remote.bytes().size() == payload.size());
}

TEST_CASE("remote C strings must terminate within their adapter bound") {
  const auto null_input =
      anvil::server::RemoteBytes::from_bounded_c_string(nullptr, 5U);
  REQUIRE_FALSE(null_input.has_value());
  CHECK(null_input.error() == anvil::server::RemoteBytesError::null_data);

  constexpr std::array terminated{'x', 't', 'e', 'r', 'm', '\0'};
  const auto accepted =
      anvil::server::RemoteBytes::from_bounded_c_string(terminated.data(), 5U);
  REQUIRE(accepted.has_value());
  CHECK(accepted->text() == "xterm");

  constexpr std::array unterminated{'x', 't', 'e', 'r', 'm', '!'};
  const auto rejected = anvil::server::RemoteBytes::from_bounded_c_string(
      unterminated.data(), 5U);
  REQUIRE_FALSE(rejected.has_value());
  CHECK(rejected.error() ==
        anvil::server::RemoteBytesError::missing_terminator);
}

TEST_CASE("remote bytes are capped before destination mutation") {
  std::vector<std::byte> destination{std::byte{0x01}, std::byte{0x02}};
  const std::array payload{std::byte{0x03}, std::byte{0x04}};

  REQUIRE(anvil::server::append_remote_bytes(
              destination,
              anvil::server::RemoteBytes::from_span(payload), 4U)
              .has_value());
  REQUIRE(destination.size() == 4U);
  CHECK(destination[3] == std::byte{0x04});

  const auto before = destination;
  const std::array overflow{std::byte{0x05}};
  const auto rejected = anvil::server::append_remote_bytes(
      destination, anvil::server::RemoteBytes::from_span(overflow), 4U);
  REQUIRE_FALSE(rejected.has_value());
  CHECK(rejected.error() ==
        anvil::server::RemoteBytesError::capacity_exceeded);
  CHECK(destination == before);

  std::vector<std::byte> already_oversized(2U);
  const auto rejected_existing = anvil::server::append_remote_bytes(
      already_oversized, anvil::server::RemoteBytes::from_span({}), 1U);
  REQUIRE_FALSE(rejected_existing.has_value());
  CHECK(rejected_existing.error() ==
        anvil::server::RemoteBytesError::capacity_exceeded);
  CHECK(already_oversized.size() == 2U);
}
