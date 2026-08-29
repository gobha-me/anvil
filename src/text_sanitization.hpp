#pragma once

#include <string>
#include <string_view>

namespace anvil::server {

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
