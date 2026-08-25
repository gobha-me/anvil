#include <anvil/sdk/types.hpp>

#include <stdint.h>

static_assert(sizeof(void *) == 4);
static_assert(sizeof(anvil::Str) == 12);
static_assert(sizeof(anvil::Span<const uint32_t>) == 12);
static_assert(sizeof(anvil::Version) == 6);
static_assert(sizeof(anvil::PluginKind) == 4);
static_assert(sizeof(anvil::CapabilityTier) == 4);

auto main() -> int { return 0; }
