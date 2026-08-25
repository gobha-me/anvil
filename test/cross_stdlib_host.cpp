#include <anvil/loader.hpp>
#include <anvil/sdk.hpp>

#include <cstdint>
#include <iostream>
#include <string_view>

namespace anvil {

IPlugin::~IPlugin() noexcept = default;
IDoor::~IDoor() noexcept = default;

} // namespace anvil

namespace {

[[nodiscard]] auto fail(std::string_view message) -> int {
  std::cerr << message << '\n';
  return 1;
}

[[nodiscard]] auto make_context(std::uint64_t user) -> anvil::DoorContext {
  return anvil::DoorContext{
      sizeof(anvil::DoorContext),
      anvil::UserId{user},
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

auto main(int argc, char **argv) -> int {
  if (argc != 2) {
    return fail("usage: anvil_cross_stdlib_host <plugin>");
  }

  const auto requirement = anvil::loader::AbiRequirement<anvil::AnvilAbiTag>{
      anvil::current_abi_tag,
      anvil::loader::verify_abi_tag,
      anvil::kAbiTagPrefixSize,
      anvil::loader::abi_tag_declared_size,
  };
  auto loaded = anvil::loader::load<anvil::IPlugin>(argv[1], requirement);
  if (!loaded) {
    std::cerr << loaded.error().message() << '\n';
    return 1;
  }

  anvil::PluginManifest plugin{};
  if (loaded->instance->manifest(&plugin) != anvil::PluginStatus::ok ||
      anvil::sdk::as_string_view(plugin.id.value) != "org.example.wrapper") {
    return fail("plugin manifest did not cross the boundary intact");
  }

  auto *door = dynamic_cast<anvil::IDoor *>(loaded->instance.get());
  if (door == nullptr) {
    return fail("cross-DSO IDoor downcast failed");
  }

  anvil::DoorManifest door_manifest{};
  if (door->door_manifest(&door_manifest) != anvil::PluginStatus::ok ||
      door_manifest.min_tier != anvil::CapabilityTier::ansi) {
    return fail("door manifest did not cross the boundary intact");
  }

  auto throwing = make_context(13);
  if (door->run(&throwing) != anvil::PluginStatus::exception) {
    return fail("an escaping exception was not converted to a status");
  }
  auto healthy = make_context(7);
  if (door->run(&healthy) != anvil::PluginStatus::ok) {
    return fail("the host did not remain usable after a plugin exception");
  }

  return 0;
}
