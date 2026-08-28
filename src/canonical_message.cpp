#include "canonical_message.hpp"

#include <array>
#include <bit>
#include <cstdint>
#include <string_view>

namespace anvil::store::detail {
namespace {

void append_u32(std::vector<std::byte> &output, std::uint32_t value) {
  for (int shift = 24; shift >= 0; shift -= 8) {
    output.push_back(static_cast<std::byte>(
        (value >> static_cast<unsigned int>(shift)) & 0xffU));
  }
}

void append_u64(std::vector<std::byte> &output, std::uint64_t value) {
  for (int shift = 56; shift >= 0; shift -= 8) {
    output.push_back(static_cast<std::byte>(
        (value >> static_cast<unsigned int>(shift)) & 0xffU));
  }
}

void append_string(std::vector<std::byte> &output, std::string_view value) {
  append_u64(output, static_cast<std::uint64_t>(value.size()));
  for (const auto character : value) {
    output.push_back(
        static_cast<std::byte>(static_cast<unsigned char>(character)));
  }
}

void append_optional_string(std::vector<std::byte> &output,
                            const std::optional<std::string> &value) {
  output.push_back(value.has_value() ? std::byte{1} : std::byte{0});
  if (value.has_value()) {
    append_string(output, *value);
  }
}

} // namespace

auto canonical_message_bytes(const CanonicalMessage &message)
    -> std::vector<std::byte> {
  constexpr std::array magic{
      std::byte{'A'}, std::byte{'N'}, std::byte{'V'}, std::byte{'I'},
      std::byte{'L'}, std::byte{'M'}, std::byte{'S'}, std::byte{'G'},
  };
  std::vector<std::byte> output;
  output.reserve(64U + message.message_id.size() + message.board_id.size() +
                 message.thread_id.size() + message.author_handle.size() +
                 message.body.size());
  output.insert(output.end(), magic.begin(), magic.end());
  append_u32(output, 1U);
  append_string(output, message.message_id);
  append_string(output, message.board_id);
  append_string(output, message.thread_id);
  append_optional_string(output, message.parent_message_id);
  append_string(output, message.author_handle);
  append_optional_string(output, message.author_origin);
  append_string(output, message.body);
  append_u64(output, std::bit_cast<std::uint64_t>(message.posted_at.value));
  return output;
}

} // namespace anvil::store::detail
