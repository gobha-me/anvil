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

} // namespace

auto prepare_user_text_for_ingest(UserTextField field, std::string_view input)
    -> std::expected<std::string, UserTextError> {
  const auto *policy = policy_for(field);
  if (policy == nullptr) return std::unexpected(UserTextError::unknown_field);
  if (input.size() > policy->max_bytes)
    return std::unexpected(UserTextError::too_many_bytes);

  std::size_t offset = 0;
  std::size_t graphemes = 0;
  std::size_t line_graphemes = 0;
  bool have_previous = false;
  bool have_line_previous = false;
  utf8proc_int32_t previous = 0;
  utf8proc_int32_t line_previous = 0;
  utf8proc_int32_t grapheme_state = 0;
  utf8proc_int32_t line_state = 0;

  while (offset < input.size()) {
    utf8proc_int32_t codepoint = 0;
    const auto remaining = input.substr(offset);
    const auto width = utf8proc_iterate(
        reinterpret_cast<const utf8proc_uint8_t *>(remaining.data()),
        static_cast<utf8proc_ssize_t>(remaining.size()), &codepoint);
    if (width <= 0) return std::unexpected(UserTextError::invalid_utf8);

    if (field == UserTextField::handle && !is_handle_character(codepoint))
      return std::unexpected(UserTextError::invalid_handle);

    if (!have_previous ||
        utf8proc_grapheme_break_stateful(previous, codepoint,
                                         &grapheme_state)) {
      ++graphemes;
      if (graphemes > policy->max_graphemes)
        return std::unexpected(UserTextError::too_many_graphemes);
    }
    previous = codepoint;
    have_previous = true;

    if (codepoint == '\r' || codepoint == '\n') {
      have_line_previous = false;
      line_graphemes = 0;
      line_state = 0;
    } else {
      if (!have_line_previous ||
          utf8proc_grapheme_break_stateful(line_previous, codepoint,
                                           &line_state)) {
        ++line_graphemes;
        if (line_graphemes > kMaxLineGraphemes)
          return std::unexpected(UserTextError::line_too_long);
      }
      line_previous = codepoint;
      have_line_previous = true;
    }

    offset += static_cast<std::size_t>(width);
  }

  if (field == UserTextField::handle && input.empty())
    return std::unexpected(UserTextError::invalid_handle);
  if (field == UserTextField::handle) return std::string{input};
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
