#include "canonical_message.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstddef>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>

namespace {

[[nodiscard]] auto hex(const std::vector<std::byte> &bytes) -> std::string {
  std::ostringstream output;
  output << std::hex << std::setfill('0');
  for (const auto byte : bytes) {
    output << std::setw(2) << std::to_integer<unsigned int>(byte);
  }
  return output.str();
}

} // namespace

TEST_CASE("canonical messages have a stable versioned byte representation") {
  const anvil::store::detail::CanonicalMessage message{
      .message_id = "m-1",
      .board_id = "00000000-0000-0000-0000-000000000001",
      .thread_id = "t-1",
      .parent_message_id = std::nullopt,
      .author_handle = "alice",
      .author_origin = "remote.test",
      .body = "hello",
      .posted_at = {-2},
  };

  CHECK(hex(anvil::store::detail::canonical_message_bytes(message)) ==
        "414e56494c4d534700000001"
        "00000000000000036d2d31"
        "000000000000002430303030303030302d303030302d303030302d303030302d"
        "303030303030303030303031"
        "0000000000000003742d31"
        "00"
        "0000000000000005616c696365"
        "01000000000000000b72656d6f74652e74657374"
        "000000000000000568656c6c6f"
        "fffffffffffffffe");
}

TEST_CASE("canonical messages distinguish null and empty origins") {
  anvil::store::detail::CanonicalMessage message{
      .message_id = "m",
      .board_id = "00000000-0000-0000-0000-000000000001",
      .thread_id = "t",
      .parent_message_id = "",
      .author_handle = "alice",
      .author_origin = std::nullopt,
      .body = "body",
      .posted_at = {1},
  };
  const auto without_origin =
      anvil::store::detail::canonical_message_bytes(message);
  message.author_origin = "";
  const auto with_empty_origin =
      anvil::store::detail::canonical_message_bytes(message);

  CHECK(without_origin != with_empty_origin);
}

TEST_CASE("canonical messages preserve exact UTF-8 without normalization") {
  anvil::store::detail::CanonicalMessage message{
      .message_id = "m",
      .board_id = "00000000-0000-0000-0000-000000000001",
      .thread_id = "t",
      .parent_message_id = std::nullopt,
      .author_handle = "alice",
      .author_origin = std::nullopt,
      .body = "\xc3\xa9",
      .posted_at = {1},
  };
  const auto composed = anvil::store::detail::canonical_message_bytes(message);
  message.body = "e\xcc\x81";
  const auto decomposed =
      anvil::store::detail::canonical_message_bytes(message);

  CHECK(composed != decomposed);
}
