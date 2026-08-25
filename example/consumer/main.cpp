#include <anvil/loader.hpp>
#include <anvil/sdk/abi.hpp>
#include <anvil/sdk/plugin.hpp>
#include <anvil/sdk/types.hpp>

#include <cstdint>
namespace {

struct Plugin {
  virtual ~Plugin() = default;
};

} // namespace

auto main() -> int {
  const auto text = anvil::Str{"external consumer", 17};
  const auto version = anvil::Version{0, 5, 0};
  const auto manifest = anvil::PluginManifest{
      sizeof(anvil::PluginManifest),
      anvil::PluginId{anvil::Str{"org.example.consumer", 20}},
      anvil::Str{"Consumer", 8},
      anvil::Str{"Installed SDK contract check", 28},
      anvil::Str{"Anvil", 5},
      version,
      anvil::PluginKind::door,
  };
  if (text.len != 17 || version.minor != 5 ||
      manifest.struct_size != sizeof(anvil::PluginManifest) ||
      manifest.id.value.len != 20 ||
      anvil::PluginKind::door == anvil::PluginKind::verifier) {
    return 1;
  }

  const auto result = anvil::loader::load<Plugin>(
      "/anvil/consumer/this-plugin-does-not-exist.so",
      anvil::loader::AbiRequirement<anvil::AnvilAbiTag>{
          anvil::current_abi_tag, anvil::loader::verify_abi_tag,
          anvil::kAbiTagPrefixSize, anvil::loader::abi_tag_declared_size});

  return !result && result.error().code == anvil::loader::ErrorCode::open_failed
             ? 0
             : 1;
}
