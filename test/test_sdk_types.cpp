#include <anvil/sdk/abi.hpp>
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
