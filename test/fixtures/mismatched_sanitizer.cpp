#include "plugin_api.hpp"

namespace {

constexpr auto mismatched_tag = [] {
  auto tag = anvil::current_abi_tag;
  tag.sanitizer_mask ^=
      static_cast<uint32_t>(anvil::AbiSanitizer::address);
  return tag;
}();

} // namespace

extern "C" ANVIL_TEST_EXPORT const anvil::AnvilAbiTag anvil_abi_tag =
    mismatched_tag;
