#include <anvil/sdk/abi.hpp>
#include <anvil/sdk/plugin.hpp>
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
extern "C" auto anvil_sdk_plugin_manifest(anvil::PluginManifest value) noexcept
    -> anvil::PluginManifest;
extern "C" auto anvil_sdk_door_manifest(anvil::DoorManifest value) noexcept
    -> anvil::DoorManifest;
extern "C" auto anvil_sdk_door_context(anvil::DoorContext value) noexcept
    -> anvil::DoorContext;
extern "C" const anvil::AnvilAbiTag anvil_abi_tag;

static_assert(std::is_aggregate_v<anvil::Str>);
static_assert(std::is_trivially_copyable_v<anvil::Str>);
static_assert(std::is_standard_layout_v<anvil::Str>);
static_assert(std::is_aggregate_v<anvil::Span<std::uint32_t>>);
static_assert(std::is_trivially_copyable_v<anvil::Span<std::uint32_t>>);
static_assert(std::is_standard_layout_v<anvil::Span<std::uint32_t>>);
static_assert(std::is_aggregate_v<anvil::Version>);
static_assert(std::is_trivially_copyable_v<anvil::Version>);
static_assert(std::is_standard_layout_v<anvil::Version>);
static_assert(std::is_aggregate_v<anvil::AnvilAbiTag>);
static_assert(std::is_trivially_copyable_v<anvil::AnvilAbiTag>);
static_assert(std::is_standard_layout_v<anvil::AnvilAbiTag>);
static_assert(std::is_aggregate_v<anvil::InterfaceVersion>);
static_assert(std::is_trivially_copyable_v<anvil::InterfaceVersion>);
static_assert(std::is_standard_layout_v<anvil::InterfaceVersion>);
static_assert(std::is_aggregate_v<anvil::PluginId>);
static_assert(std::is_trivially_copyable_v<anvil::PluginId>);
static_assert(std::is_standard_layout_v<anvil::PluginId>);
static_assert(std::is_aggregate_v<anvil::UserId>);
static_assert(std::is_trivially_copyable_v<anvil::UserId>);
static_assert(std::is_standard_layout_v<anvil::UserId>);
static_assert(std::is_aggregate_v<anvil::Capabilities>);
static_assert(std::is_trivially_copyable_v<anvil::Capabilities>);
static_assert(std::is_standard_layout_v<anvil::Capabilities>);
static_assert(std::is_aggregate_v<anvil::ResourceLimits>);
static_assert(std::is_trivially_copyable_v<anvil::ResourceLimits>);
static_assert(std::is_standard_layout_v<anvil::ResourceLimits>);
static_assert(std::is_aggregate_v<anvil::PluginManifest>);
static_assert(std::is_trivially_copyable_v<anvil::PluginManifest>);
static_assert(std::is_standard_layout_v<anvil::PluginManifest>);
static_assert(std::is_aggregate_v<anvil::DoorManifest>);
static_assert(std::is_trivially_copyable_v<anvil::DoorManifest>);
static_assert(std::is_standard_layout_v<anvil::DoorManifest>);
static_assert(std::is_aggregate_v<anvil::DoorContext>);
static_assert(std::is_trivially_copyable_v<anvil::DoorContext>);
static_assert(std::is_standard_layout_v<anvil::DoorContext>);
static_assert(
    std::is_same_v<std::underlying_type_t<anvil::AbiCompiler>, std::uint32_t>);
static_assert(std::is_same_v<std::underlying_type_t<anvil::AbiStandardLibrary>,
                             std::uint32_t>);
static_assert(
    std::is_same_v<std::underlying_type_t<anvil::AbiSanitizer>, std::uint32_t>);
static_assert(
    std::is_same_v<std::underlying_type_t<anvil::PluginKind>, std::uint32_t>);
static_assert(std::is_same_v<std::underlying_type_t<anvil::CapabilityTier>,
                             std::uint32_t>);
static_assert(
    std::is_same_v<std::underlying_type_t<anvil::PluginStatus>, std::uint32_t>);

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

TEST_CASE("plugin contract records cross a shared-library boundary unchanged") {
  constexpr char id[]{"org.example.clock"};
  constexpr char name[]{"Clock"};
  constexpr char description[]{"A quiet clock door"};
  constexpr char author[]{"Example Author"};

  const auto plugin = anvil_sdk_plugin_manifest(anvil::PluginManifest{
      sizeof(anvil::PluginManifest),
      anvil::PluginId{anvil::Str{id, sizeof(id) - 1}},
      anvil::Str{name, sizeof(name) - 1},
      anvil::Str{description, sizeof(description) - 1},
      anvil::Str{author, sizeof(author) - 1},
      anvil::Version{2, 3, 4},
      anvil::PluginKind::door,
  });

  CHECK(plugin.struct_size == sizeof(anvil::PluginManifest));
  CHECK(plugin.id.value.data == id);
  CHECK(plugin.id.value.len == sizeof(id) - 1);
  CHECK(plugin.name.data == name);
  CHECK(plugin.name.len == sizeof(name) - 1);
  CHECK(plugin.description.data == description);
  CHECK(plugin.author.data == author);
  CHECK(plugin.version.major == 2);
  CHECK(plugin.version.minor == 3);
  CHECK(plugin.version.patch == 4);
  CHECK(plugin.kind == anvil::PluginKind::door);

  const auto door = anvil_sdk_door_manifest(anvil::DoorManifest{
      sizeof(anvil::DoorManifest), anvil::CapabilityTier::modern, 1, 0, 1, 0});
  CHECK(door.struct_size == sizeof(anvil::DoorManifest));
  CHECK(door.min_tier == anvil::CapabilityTier::modern);
  CHECK(door.persists_state == 1);
  CHECK(door.has_leaderboard == 0);
  CHECK(door.audio_enhanced == 1);
  CHECK(door.reserved == 0);
}

TEST_CASE("door context preserves opaque services, capabilities, and limits") {
  auto *const session = reinterpret_cast<anvil::ISession *>(0x1000U);
  auto *const state = reinterpret_cast<anvil::IStateStore *>(0x2000U);
  const auto context = anvil_sdk_door_context(anvil::DoorContext{
      sizeof(anvil::DoorContext),
      anvil::UserId{42},
      session,
      anvil::Capabilities{sizeof(anvil::Capabilities),
                          anvil::CapabilityTier::graphics, 120, 40},
      state,
      anvil::ResourceLimits{sizeof(anvil::ResourceLimits), 64U << 20U,
                            5'000'000, 1'000'000, 32U << 20U,
                            3'600'000'000'000},
  });

  CHECK(context.struct_size == sizeof(anvil::DoorContext));
  CHECK(context.user.value == 42);
  CHECK(context.session == session);
  CHECK(context.caps.struct_size == sizeof(anvil::Capabilities));
  CHECK(context.caps.tier == anvil::CapabilityTier::graphics);
  CHECK(context.caps.columns == 120);
  CHECK(context.caps.rows == 40);
  CHECK(context.state == state);
  CHECK(context.limits.struct_size == sizeof(anvil::ResourceLimits));
  CHECK(context.limits.memory_bytes == (64U << 20U));
  CHECK(context.limits.cpu_time_ns == 5'000'000);
  CHECK(context.limits.output_bytes_per_second == 1'000'000);
  CHECK(context.limits.image_bytes == (32U << 20U));
  CHECK(context.limits.duration_ns == 3'600'000'000'000);
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

  CHECK(static_cast<std::uint32_t>(anvil::PluginStatus::ok) == 0);
  CHECK(static_cast<std::uint32_t>(anvil::PluginStatus::invalid_argument) == 1);
  CHECK(static_cast<std::uint32_t>(anvil::PluginStatus::exception) == 2);

  CHECK(static_cast<std::uint32_t>(anvil::AbiCompiler::unknown) == 0);
  CHECK(static_cast<std::uint32_t>(anvil::AbiCompiler::gcc) == 1);
  CHECK(static_cast<std::uint32_t>(anvil::AbiCompiler::clang) == 2);
  CHECK(static_cast<std::uint32_t>(anvil::AbiStandardLibrary::unknown) == 0);
  CHECK(static_cast<std::uint32_t>(anvil::AbiStandardLibrary::libstdcxx) == 1);
  CHECK(static_cast<std::uint32_t>(anvil::AbiStandardLibrary::libcxx) == 2);
  CHECK(static_cast<std::uint32_t>(anvil::AbiSanitizer::address) == 1);
  CHECK(static_cast<std::uint32_t>(anvil::AbiSanitizer::undefined) == 2);
  CHECK(static_cast<std::uint32_t>(anvil::AbiSanitizer::thread) == 4);
}

TEST_CASE("the SDK macro exports the translation unit's complete ABI tag") {
  CHECK(anvil_abi_tag.magic == anvil::kAbiMagic);
  CHECK(anvil_abi_tag.struct_size == sizeof(anvil::AnvilAbiTag));
  CHECK(anvil_abi_tag.interface_major == anvil::kPluginInterfaceMajor);
  CHECK(anvil_abi_tag.interface_minor == anvil::kPluginInterfaceMinor);
  CHECK(anvil_abi_tag.sanitizer_mask == anvil::current_abi_tag.sanitizer_mask);
  CHECK(anvil_abi_tag.compiler == anvil::current_abi_tag.compiler);
  CHECK(anvil_abi_tag.compiler_major == anvil::current_abi_tag.compiler_major);
  CHECK(anvil_abi_tag.compiler_minor == anvil::current_abi_tag.compiler_minor);
  CHECK(anvil_abi_tag.compiler_patch == anvil::current_abi_tag.compiler_patch);
  CHECK(anvil_abi_tag.standard_library ==
        anvil::current_abi_tag.standard_library);
  CHECK(anvil_abi_tag.standard_library_version ==
        anvil::current_abi_tag.standard_library_version);
  CHECK(anvil_abi_tag.language_standard ==
        anvil::current_abi_tag.language_standard);
}

TEST_CASE("the published interface version matches the ABI tag") {
  CHECK(anvil::kPluginInterfaceVersion.major ==
        anvil::current_abi_tag.interface_major);
  CHECK(anvil::kPluginInterfaceVersion.minor ==
        anvil::current_abi_tag.interface_minor);
}

TEST_CASE("the current ABI tag describes its build toolchain") {
#if defined(__clang__)
  CHECK(anvil::current_abi_tag.compiler == anvil::AbiCompiler::clang);
  CHECK(anvil::current_abi_tag.compiler_major == __clang_major__);
#elif defined(__GNUC__)
  CHECK(anvil::current_abi_tag.compiler == anvil::AbiCompiler::gcc);
  CHECK(anvil::current_abi_tag.compiler_major == __GNUC__);
#endif

#if defined(_LIBCPP_VERSION)
  CHECK(anvil::current_abi_tag.standard_library ==
        anvil::AbiStandardLibrary::libcxx);
  CHECK(anvil::current_abi_tag.standard_library_version == _LIBCPP_VERSION);
#elif defined(__GLIBCXX__)
  CHECK(anvil::current_abi_tag.standard_library ==
        anvil::AbiStandardLibrary::libstdcxx);
  CHECK(anvil::current_abi_tag.standard_library_version == __GLIBCXX__);
#endif

  [[maybe_unused]] const auto mask = anvil::current_abi_tag.sanitizer_mask;
#if defined(__SANITIZE_ADDRESS__)
  CHECK((mask & static_cast<std::uint32_t>(anvil::AbiSanitizer::address)) != 0);
#endif
#if defined(__SANITIZE_THREAD__)
  CHECK((mask & static_cast<std::uint32_t>(anvil::AbiSanitizer::thread)) != 0);
#endif
#if defined(ANVIL_ABI_SANITIZER_UNDEFINED) && ANVIL_ABI_SANITIZER_UNDEFINED
  CHECK((mask & static_cast<std::uint32_t>(anvil::AbiSanitizer::undefined)) !=
        0);
#endif

#if defined(__clang__)
#if __has_feature(address_sanitizer)
  CHECK((mask & static_cast<std::uint32_t>(anvil::AbiSanitizer::address)) != 0);
#endif
#if __has_feature(undefined_behavior_sanitizer)
  CHECK((mask & static_cast<std::uint32_t>(anvil::AbiSanitizer::undefined)) !=
        0);
#endif
#if __has_feature(thread_sanitizer)
  CHECK((mask & static_cast<std::uint32_t>(anvil::AbiSanitizer::thread)) != 0);
#endif
#endif
}
