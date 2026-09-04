#include "text_sanitization.hpp"

#include <termforge/core/text.hpp>
#include <utf8proc.h>

#include <array>
#include <cstddef>
#include <cstdint>

namespace anvil::server {
namespace {

struct UserTextPolicy {
  UserTextField field;
  std::size_t max_graphemes;
  std::size_t max_bytes;
};

struct GraphemeCounter {
  std::size_t count = 0;
  bool have_previous = false;
  utf8proc_int32_t previous = 0;
  utf8proc_int32_t state = 0;
};

struct IngestCounters {
  GraphemeCounter total;
  GraphemeCounter line;
};

struct DecodedCodepoint {
  utf8proc_int32_t value;
  std::size_t width;
};

constexpr std::size_t kMaxLineGraphemes = 240;
constexpr std::size_t kBytesPerGrapheme = 32;

constexpr std::array kUserTextPolicies{
    UserTextPolicy{UserTextField::handle, 32, 32 * kBytesPerGrapheme},
    UserTextPolicy{UserTextField::subject, 120, 120 * kBytesPerGrapheme},
    UserTextPolicy{UserTextField::post_body, 16'384,
                   16'384 * kBytesPerGrapheme},
    UserTextPolicy{UserTextField::profile_text, 1'024,
                   1'024 * kBytesPerGrapheme},
    UserTextPolicy{UserTextField::file_description, 1'024,
                   1'024 * kBytesPerGrapheme},
    UserTextPolicy{UserTextField::oneliner, 280,
                   280 * kBytesPerGrapheme},
    UserTextPolicy{UserTextField::chat_message, 2'048,
                   2'048 * kBytesPerGrapheme},
};

[[nodiscard]] constexpr auto policy_for(UserTextField field)
    -> const UserTextPolicy * {
  for (const auto &policy : kUserTextPolicies) {
    if (policy.field == field) return &policy;
  }
  return nullptr;
}

[[nodiscard]] constexpr auto is_handle_character(utf8proc_int32_t codepoint)
    -> bool {
  return (codepoint >= 'A' && codepoint <= 'Z') ||
         (codepoint >= 'a' && codepoint <= 'z') ||
         (codepoint >= '0' && codepoint <= '9') || codepoint == '_' ||
         codepoint == '-';
}

[[nodiscard]] auto decode_codepoint(std::string_view input, std::size_t offset)
    -> std::expected<DecodedCodepoint, UserTextError> {
  utf8proc_int32_t codepoint = 0;
  const auto remaining = input.substr(offset);
  const auto width = utf8proc_iterate(
      reinterpret_cast<const utf8proc_uint8_t *>(remaining.data()),
      static_cast<utf8proc_ssize_t>(remaining.size()), &codepoint);
  if (width <= 0) {
    return std::unexpected(UserTextError::invalid_utf8);
  }
  return DecodedCodepoint{codepoint, static_cast<std::size_t>(width)};
}

[[nodiscard]] auto
record_grapheme(GraphemeCounter &counter, utf8proc_int32_t codepoint,
                std::size_t maximum, UserTextError limit_error)
    -> std::expected<void, UserTextError> {
  const auto starts_grapheme = !counter.have_previous ||
                               utf8proc_grapheme_break_stateful(
                                   counter.previous, codepoint, &counter.state);
  if (starts_grapheme && ++counter.count > maximum) {
    return std::unexpected(limit_error);
  }
  counter.previous = codepoint;
  counter.have_previous = true;
  return {};
}

void reset_counter(GraphemeCounter &counter) noexcept {
  counter = GraphemeCounter{};
}

[[nodiscard]] auto
record_ingest_codepoint(UserTextField field, const UserTextPolicy &policy,
                        IngestCounters &counters, utf8proc_int32_t codepoint)
    -> std::expected<void, UserTextError> {
  if (field == UserTextField::handle && !is_handle_character(codepoint)) {
    return std::unexpected(UserTextError::invalid_handle);
  }
  if (auto recorded =
          record_grapheme(counters.total, codepoint, policy.max_graphemes,
                          UserTextError::too_many_graphemes);
      !recorded) {
    return recorded;
  }
  if (codepoint == '\r' || codepoint == '\n') {
    reset_counter(counters.line);
    return {};
  }
  return record_grapheme(counters.line, codepoint, kMaxLineGraphemes,
                         UserTextError::line_too_long);
}

[[nodiscard]] auto validate_ingest_text(UserTextField field,
                                        const UserTextPolicy &policy,
                                        std::string_view input)
    -> std::expected<void, UserTextError> {
  std::size_t offset = 0;
  IngestCounters counters;
  while (offset < input.size()) {
    auto decoded = decode_codepoint(input, offset);
    if (!decoded) {
      return std::unexpected(decoded.error());
    }
    if (auto recorded =
            record_ingest_codepoint(field, policy, counters, decoded->value);
        !recorded) {
      return recorded;
    }
    offset += decoded->width;
  }
  return {};
}

} // namespace

auto is_well_formed_utf8(std::string_view input) noexcept -> bool {
  std::size_t offset = 0;
  while (offset < input.size()) {
    utf8proc_int32_t codepoint = 0;
    const auto remaining = input.substr(offset);
    const auto width = utf8proc_iterate(
        reinterpret_cast<const utf8proc_uint8_t *>(remaining.data()),
        static_cast<utf8proc_ssize_t>(remaining.size()), &codepoint);
    if (width <= 0) {
      return false;
    }
    offset += static_cast<std::size_t>(width);
  }
  return true;
}

auto prepare_user_text_for_ingest(UserTextField field, RemoteBytes remote_input)
    -> std::expected<std::string, UserTextError> {
  const auto input = remote_input.text();
  const auto *policy = policy_for(field);
  if (policy == nullptr) {
    return std::unexpected(UserTextError::unknown_field);
  }
  if (input.size() > policy->max_bytes) {
    return std::unexpected(UserTextError::too_many_bytes);
  }
  if (auto valid = validate_ingest_text(field, *policy, input); !valid) {
    return std::unexpected(valid.error());
  }
  if (field == UserTextField::handle && input.empty()) {
    return std::unexpected(UserTextError::invalid_handle);
  }
  if (field == UserTextField::handle) {
    return std::string{input};
  }
  return sanitize_prose_for_storage(input);
}

auto sanitize_prose_for_storage(std::string_view input) -> std::string {
  return termforge::text::sanitize(input,
                                   termforge::text::SanitizeMode::Escape);
}

auto sanitize_prose_for_render(std::string_view input) -> std::string {
  return termforge::text::sanitize(input, termforge::text::SanitizeMode::Strip);
}

} // namespace anvil::server
