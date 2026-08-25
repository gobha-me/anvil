#include <anvil/sdk/types.hpp>

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <cstdint>
#include <type_traits>

extern "C" auto anvil_sdk_str_len(anvil::Str value) noexcept -> std::uint64_t;
extern "C" auto anvil_sdk_sum(anvil::Span<const std::uint32_t> values) noexcept
    -> std::uint64_t;
extern "C" auto anvil_sdk_version(anvil::Version value) noexcept
    -> anvil::Version;
extern "C" auto anvil_sdk_plugin_kind(anvil::PluginKind value) noexcept
    -> anvil::PluginKind;
extern "C" auto anvil_sdk_capability_tier(anvil::CapabilityTier value) noexcept
    -> anvil::CapabilityTier;

static_assert(std::is_aggregate_v<anvil::Str>);
static_assert(std::is_trivially_copyable_v<anvil::Str>);
static_assert(std::is_standard_layout_v<anvil::Str>);
static_assert(std::is_aggregate_v<anvil::Span<std::uint32_t>>);
static_assert(std::is_trivially_copyable_v<anvil::Span<std::uint32_t>>);
static_assert(std::is_standard_layout_v<anvil::Span<std::uint32_t>>);
static_assert(std::is_aggregate_v<anvil::Version>);
static_assert(std::is_trivially_copyable_v<anvil::Version>);
static_assert(std::is_standard_layout_v<anvil::Version>);
static_assert(
    std::is_same_v<std::underlying_type_t<anvil::PluginKind>, std::uint32_t>);
static_assert(std::is_same_v<std::underlying_type_t<anvil::CapabilityTier>,
                             std::uint32_t>);

TEST_CASE("SDK value types cross a shared-library boundary unchanged") {
  constexpr char text[]{"boundary"};
  CHECK(anvil_sdk_str_len(anvil::Str{text, 8}) == 8);

  constexpr std::array<std::uint32_t, 4> values{1, 2, 3, 4};
  CHECK(anvil_sdk_sum(anvil::Span<const std::uint32_t>{values.data(),
                                                       values.size()}) == 10);

  const auto version = anvil_sdk_version(anvil::Version{1, 2, 3});
  CHECK(version.major == 1);
  CHECK(version.minor == 2);
  CHECK(version.patch == 3);

  CHECK(anvil_sdk_plugin_kind(anvil::PluginKind::door) ==
        anvil::PluginKind::door);
  CHECK(anvil_sdk_capability_tier(anvil::CapabilityTier::graphics) ==
        anvil::CapabilityTier::graphics);
}

TEST_CASE("Span expresses mutability through its element type") {
  std::array<std::uint32_t, 2> values{4, 8};
  auto writable = anvil::Span<std::uint32_t>{values.data(), values.size()};
  writable.data[0] = 16;

  const auto readonly =
      anvil::Span<const std::uint32_t>{values.data(), values.size()};
  CHECK(readonly.data[0] == 16);
  CHECK(readonly.len == 2);
}

TEST_CASE("enum wire values are stable") {
  CHECK(static_cast<std::uint32_t>(anvil::PluginKind::door) == 0);
  CHECK(static_cast<std::uint32_t>(anvil::PluginKind::board_service) == 1);
  CHECK(static_cast<std::uint32_t>(anvil::PluginKind::verifier) == 2);

  CHECK(static_cast<std::uint32_t>(anvil::CapabilityTier::teletype) == 0);
  CHECK(static_cast<std::uint32_t>(anvil::CapabilityTier::ansi) == 1);
  CHECK(static_cast<std::uint32_t>(anvil::CapabilityTier::modern) == 2);
  CHECK(static_cast<std::uint32_t>(anvil::CapabilityTier::graphics) == 3);
}
