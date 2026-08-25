#pragma once

#include <anvil/sdk/types.hpp>

#include <stdint.h>

namespace anvil {

// Borrowed stable plugin identifier. The host copies value into its own
// storage before retaining a manifest.
struct PluginId {
  Str value;
};

// Opaque host user identifier. Plugins may compare and retain the value but
// must not infer database layout from it.
struct UserId {
  uint64_t value;
};

// Session traits observed by the host. Later fields may be appended after
// struct_size when the plugin interface minor version advances.
struct Capabilities {
  uint32_t struct_size;
  CapabilityTier tier;
  uint32_t columns;
  uint32_t rows;
};

// Per-session accidental-failure bounds. These are interface-cleanliness
// controls, not a sandbox: an in-process plugin can bypass them.
struct ResourceLimits {
  uint32_t struct_size;
  uint64_t memory_bytes;
  uint64_t cpu_time_ns;
  uint64_t output_bytes_per_second;
  uint64_t image_bytes;
  uint64_t duration_ns;
};

// The callable service interfaces are defined with the behavior that owns
// them. Keeping the pointers opaque here avoids freezing unfinished vtables.
class ISession;
class IStateStore;

struct PluginManifest {
  uint32_t struct_size;
  PluginId id;
  Str name;
  Str description;
  Str author;
  Version version;
  PluginKind kind;
};

struct DoorManifest {
  uint32_t struct_size;
  CapabilityTier min_tier;
  uint8_t persists_state;
  uint8_t has_leaderboard;
  uint8_t audio_enhanced;
  uint8_t reserved;
};

struct DoorContext {
  uint32_t struct_size;
  UserId user;
  ISession *session;
  Capabilities caps;
  IStateStore *state;
  ResourceLimits limits;
};

static_assert(__is_trivially_copyable(PluginId));
static_assert(__is_standard_layout(PluginId));
static_assert(__builtin_offsetof(PluginId, value) == 0);
static_assert(sizeof(PluginId) == sizeof(Str));
static_assert(alignof(PluginId) == alignof(Str));

static_assert(__is_trivially_copyable(UserId));
static_assert(__is_standard_layout(UserId));
static_assert(__builtin_offsetof(UserId, value) == 0);
static_assert(sizeof(UserId) == sizeof(uint64_t));
static_assert(alignof(UserId) == alignof(uint64_t));

static_assert(__is_trivially_copyable(Capabilities));
static_assert(__is_standard_layout(Capabilities));
static_assert(__builtin_offsetof(Capabilities, struct_size) == 0);
static_assert(__builtin_offsetof(Capabilities, tier) == 4);
static_assert(__builtin_offsetof(Capabilities, columns) == 8);
static_assert(__builtin_offsetof(Capabilities, rows) == 12);
static_assert(sizeof(Capabilities) == 16);
static_assert(alignof(Capabilities) == alignof(uint32_t));

static_assert(__is_trivially_copyable(ResourceLimits));
static_assert(__is_standard_layout(ResourceLimits));
static_assert(__builtin_offsetof(ResourceLimits, struct_size) == 0);
static_assert(__builtin_offsetof(ResourceLimits, memory_bytes) ==
              (sizeof(void *) == 8 ? 8 : 4));
static_assert(__builtin_offsetof(ResourceLimits, cpu_time_ns) ==
              (sizeof(void *) == 8 ? 16 : 12));
static_assert(__builtin_offsetof(ResourceLimits, output_bytes_per_second) ==
              (sizeof(void *) == 8 ? 24 : 20));
static_assert(__builtin_offsetof(ResourceLimits, image_bytes) ==
              (sizeof(void *) == 8 ? 32 : 28));
static_assert(__builtin_offsetof(ResourceLimits, duration_ns) ==
              (sizeof(void *) == 8 ? 40 : 36));
static_assert(sizeof(ResourceLimits) == (sizeof(void *) == 8 ? 48 : 44));
static_assert(alignof(ResourceLimits) == alignof(uint64_t));

static_assert(__is_trivially_copyable(PluginManifest));
static_assert(__is_standard_layout(PluginManifest));
static_assert(__builtin_offsetof(PluginManifest, struct_size) == 0);
static_assert(__builtin_offsetof(PluginManifest, id) ==
              (sizeof(void *) == 8 ? 8 : 4));
static_assert(__builtin_offsetof(PluginManifest, name) ==
              (sizeof(void *) == 8 ? 24 : 16));
static_assert(__builtin_offsetof(PluginManifest, description) ==
              (sizeof(void *) == 8 ? 40 : 28));
static_assert(__builtin_offsetof(PluginManifest, author) ==
              (sizeof(void *) == 8 ? 56 : 40));
static_assert(__builtin_offsetof(PluginManifest, version) ==
              (sizeof(void *) == 8 ? 72 : 52));
static_assert(__builtin_offsetof(PluginManifest, kind) ==
              (sizeof(void *) == 8 ? 80 : 60));
static_assert(sizeof(PluginManifest) == (sizeof(void *) == 8 ? 88 : 64));
static_assert(alignof(PluginManifest) == alignof(Str));

static_assert(__is_trivially_copyable(DoorManifest));
static_assert(__is_standard_layout(DoorManifest));
static_assert(__builtin_offsetof(DoorManifest, struct_size) == 0);
static_assert(__builtin_offsetof(DoorManifest, min_tier) == 4);
static_assert(__builtin_offsetof(DoorManifest, persists_state) == 8);
static_assert(__builtin_offsetof(DoorManifest, has_leaderboard) == 9);
static_assert(__builtin_offsetof(DoorManifest, audio_enhanced) == 10);
static_assert(__builtin_offsetof(DoorManifest, reserved) == 11);
static_assert(sizeof(DoorManifest) == 12);
static_assert(alignof(DoorManifest) == alignof(uint32_t));

static_assert(__is_trivially_copyable(DoorContext));
static_assert(__is_standard_layout(DoorContext));
static_assert(__builtin_offsetof(DoorContext, struct_size) == 0);
static_assert(__builtin_offsetof(DoorContext, user) ==
              (sizeof(void *) == 8 ? 8 : 4));
static_assert(__builtin_offsetof(DoorContext, session) ==
              (sizeof(void *) == 8 ? 16 : 12));
static_assert(__builtin_offsetof(DoorContext, caps) ==
              (sizeof(void *) == 8 ? 24 : 16));
static_assert(__builtin_offsetof(DoorContext, state) ==
              (sizeof(void *) == 8 ? 40 : 32));
static_assert(__builtin_offsetof(DoorContext, limits) ==
              (sizeof(void *) == 8 ? 48 : 36));
static_assert(sizeof(DoorContext) == (sizeof(void *) == 8 ? 96 : 80));
static_assert(alignof(DoorContext) == alignof(uint64_t));

} // namespace anvil
