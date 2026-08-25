#include <anvil/sdk/types.hpp>

#include <stdint.h>

#if defined(__GNUC__) || defined(__clang__)
#define ANVIL_SDK_TEST_EXPORT __attribute__((visibility("default")))
#else
#define ANVIL_SDK_TEST_EXPORT
#endif

extern "C" ANVIL_SDK_TEST_EXPORT auto
anvil_sdk_str_len(anvil::Str value) noexcept -> uint64_t {
  return value.len;
}

extern "C" ANVIL_SDK_TEST_EXPORT auto
anvil_sdk_sum(anvil::Span<const uint32_t> values) noexcept -> uint64_t {
  uint64_t total{};
  for (uint64_t index = 0; index < values.len; ++index)
    total += values.data[index];
  return total;
}

extern "C" ANVIL_SDK_TEST_EXPORT auto
anvil_sdk_version(anvil::Version value) noexcept -> anvil::Version {
  return value;
}

extern "C" ANVIL_SDK_TEST_EXPORT auto
anvil_sdk_plugin_kind(anvil::PluginKind value) noexcept -> anvil::PluginKind {
  return value;
}

extern "C" ANVIL_SDK_TEST_EXPORT auto
anvil_sdk_capability_tier(anvil::CapabilityTier value) noexcept
    -> anvil::CapabilityTier {
  return value;
}
