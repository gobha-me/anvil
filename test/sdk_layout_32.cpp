#include <anvil/sdk/abi.hpp>
#include <anvil/sdk/plugin.hpp>
#include <anvil/sdk/types.hpp>

#include <stdint.h>

static_assert(sizeof(void *) == 4);
static_assert(sizeof(anvil::Str) == 12);
static_assert(sizeof(anvil::Span<const uint32_t>) == 12);
static_assert(sizeof(anvil::Version) == 6);
static_assert(sizeof(anvil::InterfaceVersion) == 4);
static_assert(sizeof(anvil::PluginKind) == 4);
static_assert(sizeof(anvil::CapabilityTier) == 4);
static_assert(sizeof(anvil::AnvilAbiTag) == 48);
static_assert(__builtin_offsetof(anvil::AnvilAbiTag, language_standard) == 40);
static_assert(sizeof(anvil::PluginId) == 12);
static_assert(sizeof(anvil::UserId) == 8);
static_assert(sizeof(anvil::Capabilities) == 16);
static_assert(sizeof(anvil::ResourceLimits) == 44);
static_assert(sizeof(anvil::PluginManifest) == 64);
static_assert(sizeof(anvil::DoorManifest) == 12);
static_assert(sizeof(anvil::DoorContext) == 80);
static_assert(__builtin_offsetof(anvil::DoorContext, session) == 12);
static_assert(__builtin_offsetof(anvil::DoorContext, state) == 32);
static_assert(__builtin_offsetof(anvil::DoorContext, limits) == 36);

auto main() -> int { return 0; }
