#include <anvil/loader.hpp>
#include <anvil/sdk/abi.hpp>
#include <anvil/sdk/types.hpp>

#include <cstdint>
namespace {

struct Plugin {
  virtual ~Plugin() = default;
};

} // namespace

auto main() -> int {
  const auto text = anvil::Str{"external consumer", 17};
  const auto version = anvil::Version{0, 3, 0};
  if (text.len != 17 || version.minor != 3 ||
      anvil::PluginKind::door == anvil::PluginKind::verifier) {
    return 1;
  }

  const auto result = anvil::loader::load<Plugin>(
      "/anvil/consumer/this-plugin-does-not-exist.so",
      anvil::loader::AbiRequirement<anvil::AnvilAbiTag>{
          anvil::current_abi_tag, anvil::loader::verify_abi_tag});

  return !result && result.error().code == anvil::loader::ErrorCode::open_failed
             ? 0
             : 1;
}
