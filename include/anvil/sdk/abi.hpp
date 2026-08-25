#pragma once

#include <stdint.h>
#include <version>

namespace anvil {

inline constexpr uint32_t kAbiMagic{0x414E564CUL};
inline constexpr uint16_t kPluginInterfaceMajor{1};
inline constexpr uint16_t kPluginInterfaceMinor{1};

struct InterfaceVersion {
  uint16_t major;
  uint16_t minor;
};

inline constexpr InterfaceVersion kPluginInterfaceVersion{
    kPluginInterfaceMajor, kPluginInterfaceMinor};

enum class AbiCompiler : uint32_t {
  unknown = 0,
  gcc = 1,
  clang = 2,
};

enum class AbiStandardLibrary : uint32_t {
  unknown = 0,
  libstdcxx = 1,
  libcxx = 2,
};

enum class AbiSanitizer : uint32_t {
  address = 1U << 0U,
  undefined = 1U << 1U,
  thread = 1U << 2U,
};

// magic and struct_size are the fixed prefix used to recognize every version
// of the tag. Toolchain fields are telemetry; they are not compatibility gates.
struct AnvilAbiTag {
  uint32_t magic;
  uint32_t struct_size;
  uint16_t interface_major;
  uint16_t interface_minor;
  uint32_t sanitizer_mask;
  AbiCompiler compiler;
  uint32_t compiler_major;
  uint32_t compiler_minor;
  uint32_t compiler_patch;
  AbiStandardLibrary standard_library;
  uint32_t standard_library_version;
  uint64_t language_standard;
};

static_assert(__is_trivially_copyable(AnvilAbiTag));
static_assert(__is_standard_layout(AnvilAbiTag));
static_assert(__is_trivially_copyable(InterfaceVersion));
static_assert(__is_standard_layout(InterfaceVersion));
static_assert(__builtin_offsetof(InterfaceVersion, major) == 0);
static_assert(__builtin_offsetof(InterfaceVersion, minor) == 2);
static_assert(sizeof(InterfaceVersion) == 4);
static_assert(alignof(InterfaceVersion) == alignof(uint16_t));
static_assert(__builtin_offsetof(AnvilAbiTag, magic) == 0);
static_assert(__builtin_offsetof(AnvilAbiTag, struct_size) == 4);
static_assert(__builtin_offsetof(AnvilAbiTag, interface_major) == 8);
static_assert(__builtin_offsetof(AnvilAbiTag, interface_minor) == 10);
static_assert(__builtin_offsetof(AnvilAbiTag, sanitizer_mask) == 12);
static_assert(__builtin_offsetof(AnvilAbiTag, compiler) == 16);
static_assert(__builtin_offsetof(AnvilAbiTag, compiler_major) == 20);
static_assert(__builtin_offsetof(AnvilAbiTag, compiler_minor) == 24);
static_assert(__builtin_offsetof(AnvilAbiTag, compiler_patch) == 28);
static_assert(__builtin_offsetof(AnvilAbiTag, standard_library) == 32);
static_assert(__builtin_offsetof(AnvilAbiTag, standard_library_version) == 36);
static_assert(__builtin_offsetof(AnvilAbiTag, language_standard) == 40);
static_assert(sizeof(AnvilAbiTag) == 48);
static_assert(alignof(AnvilAbiTag) == alignof(uint64_t));
static_assert(sizeof(AbiCompiler) == sizeof(uint32_t));
static_assert(sizeof(AbiStandardLibrary) == sizeof(uint32_t));
static_assert(sizeof(AbiSanitizer) == sizeof(uint32_t));

// Every supported tag version preserves this prefix. Later fields may be
// appended, but a loader must not read them unless both the declaration and
// the ELF symbol contain the complete field.
inline constexpr uint32_t kAbiTagPrefixSize{
    __builtin_offsetof(AnvilAbiTag, sanitizer_mask) +
    sizeof(AnvilAbiTag::sanitizer_mask)};
static_assert(kAbiTagPrefixSize == 16);

} // namespace anvil

#if defined(__clang__)
#define ANVIL_DETAIL_COMPILER ::anvil::AbiCompiler::clang
#define ANVIL_DETAIL_COMPILER_MAJOR __clang_major__
#define ANVIL_DETAIL_COMPILER_MINOR __clang_minor__
#define ANVIL_DETAIL_COMPILER_PATCH __clang_patchlevel__
#elif defined(__GNUC__)
#define ANVIL_DETAIL_COMPILER ::anvil::AbiCompiler::gcc
#define ANVIL_DETAIL_COMPILER_MAJOR __GNUC__
#define ANVIL_DETAIL_COMPILER_MINOR __GNUC_MINOR__
#define ANVIL_DETAIL_COMPILER_PATCH __GNUC_PATCHLEVEL__
#else
#define ANVIL_DETAIL_COMPILER ::anvil::AbiCompiler::unknown
#define ANVIL_DETAIL_COMPILER_MAJOR 0
#define ANVIL_DETAIL_COMPILER_MINOR 0
#define ANVIL_DETAIL_COMPILER_PATCH 0
#endif

#if defined(_LIBCPP_VERSION)
#define ANVIL_DETAIL_STANDARD_LIBRARY ::anvil::AbiStandardLibrary::libcxx
#define ANVIL_DETAIL_STANDARD_LIBRARY_VERSION _LIBCPP_VERSION
#elif defined(__GLIBCXX__)
#define ANVIL_DETAIL_STANDARD_LIBRARY ::anvil::AbiStandardLibrary::libstdcxx
#define ANVIL_DETAIL_STANDARD_LIBRARY_VERSION __GLIBCXX__
#else
#define ANVIL_DETAIL_STANDARD_LIBRARY ::anvil::AbiStandardLibrary::unknown
#define ANVIL_DETAIL_STANDARD_LIBRARY_VERSION 0
#endif

#if defined(__has_feature)
#if __has_feature(address_sanitizer)
#define ANVIL_DETAIL_ADDRESS_SANITIZER (1U << 0U)
#endif
#if __has_feature(undefined_behavior_sanitizer)
#define ANVIL_DETAIL_UNDEFINED_SANITIZER (1U << 1U)
#endif
#if __has_feature(thread_sanitizer)
#define ANVIL_DETAIL_THREAD_SANITIZER (1U << 2U)
#endif
#endif

#if defined(__SANITIZE_ADDRESS__) && !defined(ANVIL_DETAIL_ADDRESS_SANITIZER)
#define ANVIL_DETAIL_ADDRESS_SANITIZER (1U << 0U)
#endif
#if defined(ANVIL_ABI_SANITIZER_UNDEFINED) && ANVIL_ABI_SANITIZER_UNDEFINED && \
    !defined(ANVIL_DETAIL_UNDEFINED_SANITIZER)
#define ANVIL_DETAIL_UNDEFINED_SANITIZER (1U << 1U)
#endif
#if defined(__SANITIZE_THREAD__) && !defined(ANVIL_DETAIL_THREAD_SANITIZER)
#define ANVIL_DETAIL_THREAD_SANITIZER (1U << 2U)
#endif

#if !defined(ANVIL_DETAIL_ADDRESS_SANITIZER)
#define ANVIL_DETAIL_ADDRESS_SANITIZER 0U
#endif
#if !defined(ANVIL_DETAIL_UNDEFINED_SANITIZER)
#define ANVIL_DETAIL_UNDEFINED_SANITIZER 0U
#endif
#if !defined(ANVIL_DETAIL_THREAD_SANITIZER)
#define ANVIL_DETAIL_THREAD_SANITIZER 0U
#endif

namespace anvil {

// Internal linkage is intentional: a host and a foreign DSO compute this value
// independently from the toolchain that compiles each translation unit.
constexpr AnvilAbiTag current_abi_tag{
    kAbiMagic,
    sizeof(AnvilAbiTag),
    kPluginInterfaceMajor,
    kPluginInterfaceMinor,
    ANVIL_DETAIL_ADDRESS_SANITIZER | ANVIL_DETAIL_UNDEFINED_SANITIZER |
        ANVIL_DETAIL_THREAD_SANITIZER,
    ANVIL_DETAIL_COMPILER,
    ANVIL_DETAIL_COMPILER_MAJOR,
    ANVIL_DETAIL_COMPILER_MINOR,
    ANVIL_DETAIL_COMPILER_PATCH,
    ANVIL_DETAIL_STANDARD_LIBRARY,
    ANVIL_DETAIL_STANDARD_LIBRARY_VERSION,
    __cplusplus,
};

} // namespace anvil

// Invoke once at global scope in the plugin translation unit.
#if defined(__GNUC__) || defined(__clang__)
#define ANVIL_PLUGIN_ABI_TAG()                                                 \
  extern "C" __attribute__((visibility(                                        \
      "default"))) constinit const ::anvil::AnvilAbiTag anvil_abi_tag =        \
      ::anvil::current_abi_tag
#else
#define ANVIL_PLUGIN_ABI_TAG()                                                 \
  extern "C" constinit const ::anvil::AnvilAbiTag anvil_abi_tag =              \
      ::anvil::current_abi_tag
#endif

#undef ANVIL_DETAIL_COMPILER
#undef ANVIL_DETAIL_COMPILER_MAJOR
#undef ANVIL_DETAIL_COMPILER_MINOR
#undef ANVIL_DETAIL_COMPILER_PATCH
#undef ANVIL_DETAIL_STANDARD_LIBRARY
#undef ANVIL_DETAIL_STANDARD_LIBRARY_VERSION
#undef ANVIL_DETAIL_ADDRESS_SANITIZER
#undef ANVIL_DETAIL_UNDEFINED_SANITIZER
#undef ANVIL_DETAIL_THREAD_SANITIZER
