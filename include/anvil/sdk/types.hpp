#pragma once

#include <stdint.h>

namespace anvil {

// Borrowed UTF-8 bytes. The owner must keep data alive for the duration named
// by the interface contract that carries the view.
struct Str {
  const char *data;
  uint64_t len;
};

// A borrowed contiguous range. Only layout-stable element types may cross the
// plugin boundary; constness is expressed by T, as in Span<const T>.
template <typename T>
  requires(__is_trivially_copyable(T) && __is_standard_layout(T))
struct Span {
  T *data;
  uint64_t len;
};

struct Version {
  uint16_t major;
  uint16_t minor;
  uint16_t patch;
};

enum class PluginKind : uint32_t {
  door = 0,
  board_service = 1,
  verifier = 2,
};

enum class CapabilityTier : uint32_t {
  teletype = 0,
  ansi = 1,
  modern = 2,
  graphics = 3,
};

static_assert(__is_trivially_copyable(Str));
static_assert(__is_standard_layout(Str));
static_assert(__builtin_offsetof(Str, data) == 0);
static_assert(__builtin_offsetof(Str, len) == sizeof(const char *));
static_assert(sizeof(Str::len) == sizeof(uint64_t));
static_assert(sizeof(Str) == sizeof(const char *) + sizeof(uint64_t));
static_assert(alignof(Str) == (alignof(const char *) > alignof(uint64_t)
                                   ? alignof(const char *)
                                   : alignof(uint64_t)));

static_assert(__is_trivially_copyable(Span<uint8_t>));
static_assert(__is_standard_layout(Span<uint8_t>));
static_assert(__builtin_offsetof(Span<uint8_t>, data) == 0);
static_assert(__builtin_offsetof(Span<uint8_t>, len) == sizeof(uint8_t *));
static_assert(sizeof(Span<uint8_t>::len) == sizeof(uint64_t));
static_assert(sizeof(Span<uint8_t>) == sizeof(uint8_t *) + sizeof(uint64_t));
static_assert(alignof(Span<uint8_t>) == (alignof(uint8_t *) > alignof(uint64_t)
                                             ? alignof(uint8_t *)
                                             : alignof(uint64_t)));

static_assert(__is_trivially_copyable(Version));
static_assert(__is_standard_layout(Version));
static_assert(__builtin_offsetof(Version, major) == 0);
static_assert(__builtin_offsetof(Version, minor) == sizeof(uint16_t));
static_assert(__builtin_offsetof(Version, patch) == 2 * sizeof(uint16_t));
static_assert(sizeof(Version) == 3 * sizeof(uint16_t));
static_assert(alignof(Version) == alignof(uint16_t));

static_assert(sizeof(PluginKind) == sizeof(uint32_t));
static_assert(alignof(PluginKind) == alignof(uint32_t));
static_assert(sizeof(CapabilityTier) == sizeof(uint32_t));
static_assert(alignof(CapabilityTier) == alignof(uint32_t));

} // namespace anvil
