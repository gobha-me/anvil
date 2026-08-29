#include <catch2/catch_test_macros.hpp>

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "text_sanitization.hpp"

namespace {

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
