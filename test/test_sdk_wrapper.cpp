#include <anvil/loader.hpp>
#include <anvil/sdk.hpp>

#include <catch2/catch_test_macros.hpp>

#include <array>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <vector>

namespace anvil {

IPlugin::~IPlugin() noexcept = default;
IDoor::~IDoor() noexcept = default;

} // namespace anvil

namespace {

constexpr anvil::loader::AbiRequirement<anvil::AnvilAbiTag> kRequirement{
    anvil::current_abi_tag,
    anvil::loader::verify_abi_tag,
    anvil::kAbiTagPrefixSize,
    anvil::loader::abi_tag_declared_size,
};

[[nodiscard]] auto context(anvil::UserId user) -> anvil::DoorContext {
  return anvil::DoorContext{
      sizeof(anvil::DoorContext),
      user,
      nullptr,
      anvil::Capabilities{sizeof(anvil::Capabilities),
                          anvil::CapabilityTier::modern, 120, 40},
      nullptr,
      anvil::ResourceLimits{sizeof(anvil::ResourceLimits), 16U * 1024U * 1024U,
                            10'000'000U, 64U * 1024U, 4U * 1024U * 1024U,
                            60'000'000'000U},
  };
}

} // namespace

TEST_CASE("string conversions preserve bytes and reject invalid borrows") {
  const std::string owned{"embedded\0null", 13};
  const auto raw = anvil::sdk::as_str(owned);
  CHECK(raw.data == owned.data());
  CHECK(raw.len == owned.size());
  CHECK(anvil::sdk::as_string_view(raw) == std::string_view{owned});

  constexpr char literal[]{"literal"};
  CHECK(anvil::sdk::as_string_view(anvil::sdk::as_str(literal)) == "literal");
  CHECK(anvil::sdk::as_string_view(anvil::Str{nullptr, 0}).empty());
  CHECK_THROWS_AS(anvil::sdk::as_string_view(anvil::Str{nullptr, 1}),
                  std::invalid_argument);
  CHECK_THROWS_AS(anvil::sdk::as_str(static_cast<const char *>(nullptr)),
                  std::invalid_argument);
}

TEST_CASE("range conversions preserve constness and reject invalid borrows") {
  std::vector<std::uint32_t> mutable_values{1, 2, 3};
  const std::array<std::uint32_t, 2> const_values{4, 5};

  const auto mutable_raw = anvil::sdk::as_span(mutable_values);
  const auto const_raw = anvil::sdk::as_span(const_values);
  static_assert(
      std::is_same_v<decltype(mutable_raw), const anvil::Span<std::uint32_t>>);
  static_assert(std::is_same_v<decltype(const_raw),
                               const anvil::Span<const std::uint32_t>>);

  auto mutable_view = anvil::sdk::as_std_span(mutable_raw);
  mutable_view[1] = 9;
  CHECK(mutable_values[1] == 9);
  CHECK(anvil::sdk::as_std_span(const_raw)[1] == 5);
  CHECK_THROWS_AS(
      anvil::sdk::as_std_span(anvil::Span<std::uint32_t>{nullptr, 1}),
      std::invalid_argument);
}

TEST_CASE("the wrapper exposes stable manifests and validates hostile calls") {
  auto loaded = anvil::loader::load<anvil::IPlugin>(ANVIL_FIXTURE_sdk_wrapper,
                                                    kRequirement);
  REQUIRE(loaded.has_value());
  REQUIRE(loaded->instance);

  CHECK(loaded->instance->manifest(nullptr) ==
        anvil::PluginStatus::invalid_argument);
  anvil::PluginManifest plugin{};
  REQUIRE(loaded->instance->manifest(&plugin) == anvil::PluginStatus::ok);
  CHECK(anvil::sdk::as_string_view(plugin.id.value) == "org.example.wrapper");
  const auto borrowed_name = anvil::sdk::as_string_view(plugin.name);
  CHECK(borrowed_name == "Wrapper example");
  CHECK(plugin.version.major == 0);
  CHECK(plugin.version.minor == 6);

  auto *door = dynamic_cast<anvil::IDoor *>(loaded->instance.get());
  REQUIRE(door != nullptr);
  CHECK(door->door_manifest(nullptr) == anvil::PluginStatus::invalid_argument);
  anvil::DoorManifest manifest{};
  REQUIRE(door->door_manifest(&manifest) == anvil::PluginStatus::ok);
  CHECK(manifest.min_tier == anvil::CapabilityTier::ansi);
  CHECK(manifest.persists_state == 1);

  CHECK(door->run(nullptr) == anvil::PluginStatus::invalid_argument);
  auto invalid = context(anvil::UserId{7});
  invalid.struct_size = sizeof(anvil::DoorContext) - 1;
  CHECK(door->run(&invalid) == anvil::PluginStatus::invalid_argument);

  invalid = context(anvil::UserId{7});
  invalid.caps.struct_size = sizeof(anvil::Capabilities) - 1;
  CHECK(door->run(&invalid) == anvil::PluginStatus::invalid_argument);
  invalid = context(anvil::UserId{7});
  invalid.limits.struct_size = sizeof(anvil::ResourceLimits) - 1;
  CHECK(door->run(&invalid) == anvil::PluginStatus::invalid_argument);
  CHECK(borrowed_name == "Wrapper example");
}

TEST_CASE(
    "an escaping author exception becomes a status and the host survives") {
  auto loaded = anvil::loader::load<anvil::IPlugin>(ANVIL_FIXTURE_sdk_wrapper,
                                                    kRequirement);
  REQUIRE(loaded.has_value());
  auto *door = dynamic_cast<anvil::IDoor *>(loaded->instance.get());
  REQUIRE(door != nullptr);

  auto throwing = context(anvil::UserId{13});
  CHECK(door->run(&throwing) == anvil::PluginStatus::exception);

  auto healthy = context(anvil::UserId{7});
  CHECK(door->run(&healthy) == anvil::PluginStatus::ok);
  anvil::PluginManifest plugin{};
  CHECK(loaded->instance->manifest(&plugin) == anvil::PluginStatus::ok);
}

TEST_CASE("a throwing plugin constructor becomes a null factory result") {
  auto loaded = anvil::loader::load<anvil::IPlugin>(
      ANVIL_FIXTURE_wrapper_throwing_factory, kRequirement);
  REQUIRE_FALSE(loaded.has_value());
  CHECK(loaded.error().code == anvil::loader::ErrorCode::factory_returned_null);
}
