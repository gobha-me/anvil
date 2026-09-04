#include <catch2/catch_test_macros.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "text_sanitization.hpp"

namespace {

using anvil::server::UserTextError;
using anvil::server::UserTextField;

[[nodiscard]] auto prepare(UserTextField field, std::string_view input) {
  return anvil::server::prepare_user_text_for_ingest(
      field, anvil::server::RemoteBytes::from_text(input));
}

struct FieldLimitCase {
  UserTextField field;
  std::size_t graphemes;
  std::size_t bytes;
  std::string_view name;
};

constexpr std::array kFieldLimits{
    FieldLimitCase{UserTextField::handle, 32, 1'024, "handle"},
    FieldLimitCase{UserTextField::subject, 120, 3'840, "subject"},
    FieldLimitCase{UserTextField::post_body, 16'384, 524'288, "post body"},
    FieldLimitCase{UserTextField::profile_text, 1'024, 32'768,
                   "profile text"},
    FieldLimitCase{UserTextField::file_description, 1'024, 32'768,
                   "file description"},
    FieldLimitCase{UserTextField::oneliner, 280, 8'960, "one-liner"},
    FieldLimitCase{UserTextField::chat_message, 2'048, 65'536,
                   "chat message"},
};

[[nodiscard]] auto bounded_ascii(std::size_t graphemes) -> std::string {
  std::string value;
  value.reserve(graphemes + graphemes / 240);
  std::size_t produced = 0;
  std::size_t line_length = 0;
  while (produced < graphemes) {
    if (line_length == 240) {
      value.push_back('\n');
      ++produced;
      line_length = 0;
    } else {
      value.push_back('a');
      ++produced;
      ++line_length;
    }
  }
  return value;
}

[[nodiscard]] auto one_extended_grapheme(std::size_t bytes) -> std::string {
  std::string value{"a\xe2\x83\x9d"}; // base + U+20DD COMBINING ENCLOSING CIRCLE
  value.reserve(bytes);
  while (value.size() < bytes) value.append("\xcc\x81", 2); // U+0301
  return value;
}

[[nodiscard]] auto repeated(std::string_view value, std::size_t count)
    -> std::string {
  std::string result;
  result.reserve(value.size() * count);
  for (std::size_t index = 0; index < count; ++index) result.append(value);
  return result;
}

[[nodiscard]] auto control_free_utf8(std::string_view value) -> bool {
  std::size_t offset = 0;
  while (offset < value.size()) {
    const auto lead = static_cast<unsigned char>(value[offset]);
    std::uint32_t codepoint = 0;
    std::size_t length = 0;
    if (lead <= 0x7fU) {
      codepoint = lead;
      length = 1;
    } else if (lead >= 0xc2U && lead <= 0xdfU) {
      codepoint = lead & 0x1fU;
      length = 2;
    } else if (lead >= 0xe0U && lead <= 0xefU) {
      codepoint = lead & 0x0fU;
      length = 3;
    } else if (lead >= 0xf0U && lead <= 0xf4U) {
      codepoint = lead & 0x07U;
      length = 4;
    } else {
      return false;
    }
    if (offset + length > value.size()) {
      return false;
    }
    for (std::size_t index = 1; index < length; ++index) {
      const auto continuation =
          static_cast<unsigned char>(value[offset + index]);
      if (continuation < 0x80U || continuation > 0xbfU) {
        return false;
      }
      codepoint = (codepoint << 6U) | (continuation & 0x3fU);
    }
    if ((length == 2 && codepoint < 0x80U) ||
        (length == 3 && codepoint < 0x800U) ||
        (length == 4 && codepoint < 0x10000U) ||
        (codepoint >= 0xd800U && codepoint <= 0xdfffU) ||
        codepoint > 0x10ffffU) {
      return false;
    }
    if (codepoint < 0x20U || (codepoint >= 0x7fU && codepoint <= 0x9fU)) {
      return false;
    }
    offset += length;
  }
  return true;
}

void check_contract(std::string_view input) {
  const auto stored = anvil::server::sanitize_prose_for_storage(input);
  const auto rendered = anvil::server::sanitize_prose_for_render(input);
  CHECK(control_free_utf8(stored));
  CHECK(control_free_utf8(rendered));
  CHECK(anvil::server::sanitize_prose_for_render(stored) == stored);
  CHECK(anvil::server::sanitize_prose_for_render(rendered) == rendered);
  CHECK(anvil::server::sanitize_prose_for_storage(input) == stored);
}

} // namespace

TEST_CASE("stored prose makes every control visibly inert") {
  const std::string input = "first\nsecond\t\x1b[31mred\x1b[0m";
  CHECK(anvil::server::sanitize_prose_for_storage(input) ==
        "first^Jsecond^I^[[31mred^[[0m");
  CHECK(anvil::server::sanitize_prose_for_render(input) == "firstsecond red");

  const std::string unicode = "caf\xc3\xa9 \xe4\xb8\x96\xe7\x95\x8c";
  CHECK(anvil::server::sanitize_prose_for_storage(unicode) == unicode);
  CHECK(anvil::server::sanitize_prose_for_render(unicode) == unicode);
}

TEST_CASE("sanitization is total over hostile byte strings") {
  std::string every_byte;
  every_byte.reserve(256);
  for (unsigned int value = 0; value <= 0xffU; ++value) {
    every_byte.push_back(static_cast<char>(value));
  }
  check_contract(every_byte);

  std::uint32_t state = 0x6d2b79f5U;
  for (std::size_t sample = 0; sample < 1'024; ++sample) {
    std::string input;
    input.reserve(64);
    for (std::size_t index = 0; index < 64; ++index) {
      state ^= state << 13U;
      state ^= state >> 17U;
      state ^= state << 5U;
      input.push_back(static_cast<char>(state & 0xffU));
    }
    check_contract(input);
  }
}

TEST_CASE("real terminal attacks cannot survive either boundary") {
  const std::array attacks{
      std::string_view{"\x1b]0;owned\x07"},
      std::string_view{"\x1b]52;c;cGF5bG9hZA==\x1b\\"},
      std::string_view{"\x1b[?2004h"},
      std::string_view{"\x1b[>1u"},
      std::string_view{"\x1b[?1049h"},
      std::string_view{"\x1bP$qm\x1b\\"},
      std::string_view{"\x1b"
                       "c"},
      std::string_view{"\x9b"
                       "2J"},
      std::string_view{"\xc2\x9b"
                       "2J"},
      std::string_view{"\x1b[2J"},
  };

  for (const auto attack : attacks) {
    INFO("attack size: " << attack.size());
    const auto stored = anvil::server::sanitize_prose_for_storage(attack);
    const auto rendered = anvil::server::sanitize_prose_for_render(attack);
    CHECK(control_free_utf8(stored));
    CHECK(control_free_utf8(rendered));
    CHECK(stored.find('\x1b') == std::string::npos);
    CHECK(rendered.find('\x1b') == std::string::npos);
    CHECK(anvil::server::sanitize_prose_for_render(stored) == stored);
  }
}

TEST_CASE("malformed UTF-8 is visible in storage and absent at render") {
  const std::vector<std::string> malformed{
      std::string{"\xc0\x9b", 2},
      std::string{"\xed\xa0\x80", 3},
      std::string{"\xf4\x90\x80\x80", 4},
      std::string{"\xe2\x82", 2},
      std::string{"\xff", 1},
  };

  for (const auto &input : malformed) {
    const auto stored = anvil::server::sanitize_prose_for_storage(input);
    CHECK(control_free_utf8(stored));
    CHECK(stored.find("\\x") != std::string::npos);
    CHECK(anvil::server::sanitize_prose_for_render(input).empty());
  }
}

TEST_CASE("every user text field has an enforced grapheme and byte cap") {
  for (const auto &limit : kFieldLimits) {
    INFO(limit.name);
    auto exact = limit.field == UserTextField::handle
                     ? std::string(limit.graphemes, 'a')
                     : bounded_ascii(limit.graphemes);
    const auto accepted = prepare(limit.field, exact);
    REQUIRE(accepted.has_value());

    exact.push_back('a');
    const auto over_grapheme = prepare(limit.field, exact);
    REQUIRE_FALSE(over_grapheme.has_value());
    CHECK(over_grapheme.error() == UserTextError::too_many_graphemes);

    const std::string over_bytes(limit.bytes + 1, 'a');
    const auto rejected_bytes = prepare(limit.field, over_bytes);
    REQUIRE_FALSE(rejected_bytes.has_value());
    CHECK(rejected_bytes.error() == UserTextError::too_many_bytes);

    if (limit.field != UserTextField::handle) {
      const auto exact_bytes = one_extended_grapheme(limit.bytes);
      const auto accepted_bytes = prepare(limit.field, exact_bytes);
      REQUIRE(accepted_bytes.has_value());
      CHECK(accepted_bytes->size() == limit.bytes);

      auto one_byte_over = exact_bytes;
      one_byte_over.push_back('a');
      const auto rejected_one_byte = prepare(limit.field, one_byte_over);
      REQUIRE_FALSE(rejected_one_byte.has_value());
      CHECK(rejected_one_byte.error() == UserTextError::too_many_bytes);
    }
  }
}

TEST_CASE("ingest rejects every malformed UTF-8 class before sanitizing") {
  const std::array malformed{
      std::string{"\xc0\x9b", 2},
      std::string{"\xc1\xbf", 2},
      std::string{"\xc2", 1},
      std::string{"\xc2\x20", 2},
      std::string{"\xe0\x9f\xbf", 3},
      std::string{"\xe1\x80", 2},
      std::string{"\xe1\x80\x20", 3},
      std::string{"\xed\xa0\x80", 3},
      std::string{"\xf0\x8f\xbf\xbf", 4},
      std::string{"\xf0\x90\x80", 3},
      std::string{"\xf1\x80\x80\x20", 4},
      std::string{"\xf4\x90\x80\x80", 4},
      std::string{"\xf5\x80\x80\x80", 4},
      std::string{"\x80", 1},
      std::string{"\xf8", 1},
      std::string{"\xff", 1},
  };

  for (const auto &input : malformed) {
    const auto result = prepare(UserTextField::post_body, input);
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error() == UserTextError::invalid_utf8);
  }
}

TEST_CASE("ingest validation preserves fail-closed error precedence") {
  auto oversized_malformed = std::string(3'841, 'a');
  oversized_malformed.front() = static_cast<char>(0xff);
  const auto oversized = prepare(UserTextField::subject, oversized_malformed);
  REQUIRE_FALSE(oversized.has_value());
  CHECK(oversized.error() == UserTextError::too_many_bytes);

  const auto malformed_handle =
      prepare(UserTextField::handle, std::string{"\xff", 1});
  REQUIRE_FALSE(malformed_handle.has_value());
  CHECK(malformed_handle.error() == UserTextError::invalid_utf8);

  const auto non_ascii_handle = prepare(UserTextField::handle, "caf\xc3\xa9");
  REQUIRE_FALSE(non_ascii_handle.has_value());
  CHECK(non_ascii_handle.error() == UserTextError::invalid_handle);
}

TEST_CASE("extended grapheme clusters, not scalars or bytes, own the cap") {
  const std::array clusters{
      std::string_view{"e\xcc\x81"},
      std::string_view{"\xf0\x9f\x91\xa8\xe2\x80\x8d\xf0\x9f\x91\xa9"
                       "\xe2\x80\x8d\xf0\x9f\x91\xa7\xe2\x80\x8d"
                       "\xf0\x9f\x91\xa6"},
      std::string_view{"\xf0\x9f\x87\xba\xf0\x9f\x87\xb8"},
  };

  for (const auto cluster : clusters) {
    INFO("cluster bytes: " << cluster.size());
    const auto exact = repeated(cluster, 120);
    REQUIRE(prepare(UserTextField::subject, exact).has_value());

    const auto over = repeated(cluster, 121);
    const auto result = prepare(UserTextField::subject, over);
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error() == UserTextError::too_many_graphemes);
  }
}

TEST_CASE("raw CR LF and CRLF delimit lines capped at 240 graphemes") {
  const std::array separators{std::string_view{"\r"}, std::string_view{"\n"},
                              std::string_view{"\r\n"}};

  for (const auto separator : separators) {
    INFO("separator bytes: " << separator.size());
    const auto accepted = std::string(240, 'a') + std::string(separator) +
                          std::string(240, 'b');
    REQUIRE(prepare(UserTextField::post_body, accepted).has_value());

    const auto over = std::string(241, 'a') + std::string(separator) + "b";
    const auto result = prepare(UserTextField::post_body, over);
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error() == UserTextError::line_too_long);
  }
}

TEST_CASE("M1 handles use the exact ASCII grammar") {
  const std::array valid{std::string_view{"a"}, std::string_view{"Alice-_09"},
                         std::string_view{"--------------------------------"}};
  for (const auto handle : valid) {
    const auto result = prepare(UserTextField::handle, handle);
    REQUIRE(result.has_value());
    CHECK(*result == handle);
  }

  const std::array invalid{
      std::string_view{""},
      std::string_view{"two words"},
      std::string_view{"caf\xc3\xa9"},
      std::string_view{"alice\xe2\x80\xae"},
      std::string_view{"line\nbreak"},
  };
  for (const auto handle : invalid) {
    const auto result = prepare(UserTextField::handle, handle);
    REQUIRE_FALSE(result.has_value());
    CHECK(result.error() == UserTextError::invalid_handle);
  }
}

TEST_CASE("validated prose enters the existing visible storage boundary") {
  const auto result =
      prepare(UserTextField::post_body, "first\nsecond\t\x1b[31mred");
  REQUIRE(result.has_value());
  CHECK(*result == "first^Jsecond^I^[[31mred");
  CHECK(anvil::server::sanitize_prose_for_render(*result) == *result);
}

TEST_CASE("unknown user text fields fail closed") {
  const auto result = prepare(static_cast<UserTextField>(0xff), "text");
  REQUIRE_FALSE(result.has_value());
  CHECK(result.error() == UserTextError::unknown_field);
}
