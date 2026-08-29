#include "text_sanitization.hpp"

#include <termforge/core/text.hpp>

namespace anvil::server {

auto sanitize_prose_for_storage(std::string_view input) -> std::string {
  return termforge::text::sanitize(input,
                                   termforge::text::SanitizeMode::Escape);
}

auto sanitize_prose_for_render(std::string_view input) -> std::string {
  return termforge::text::sanitize(input, termforge::text::SanitizeMode::Strip);
}

} // namespace anvil::server
