#pragma once

#include <cstdint>
#include <expected>
#include <string>
#include <string_view>

#include "remote_bytes.hpp"

namespace anvil::server {

enum class UserTextField : std::uint8_t {
  handle,
  subject,
  post_body,
  profile_text,
  file_description,
  oneliner,
  chat_message,
};

enum class UserTextError : std::uint8_t {
  unknown_field,
  too_many_bytes,
  invalid_utf8,
  invalid_handle,
  too_many_graphemes,
  line_too_long,
};

// Validate one complete user submission before any sanitizer can replace or
// escape malformed bytes. Prose is returned in the visible, inert storage
// form; handles use a strict ASCII grammar and are returned byte-for-byte.
[[nodiscard]] auto prepare_user_text_for_ingest(UserTextField field,
                                                RemoteBytes input)
    -> std::expected<std::string, UserTextError>;

// User-authored prose is made visibly inert before persistence. The result is
// printable, well-formed UTF-8 and is a fixed point of the render-time pass.
[[nodiscard]] auto sanitize_prose_for_storage(std::string_view input)
    -> std::string;

// Every render path repeats the hostile-text check. Valid stored prose is
// unchanged; bypassed, legacy, or corrupt input fails closed by stripping
// controls and complete terminal escape sequences.
[[nodiscard]] auto sanitize_prose_for_render(std::string_view input)
    -> std::string;

} // namespace anvil::server
