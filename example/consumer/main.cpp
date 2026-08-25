#include <anvil/loader.hpp>
#include <anvil/sdk.hpp>

#include <string>
#include <vector>

namespace anvil {

IPlugin::~IPlugin() noexcept = default;
IDoor::~IDoor() noexcept = default;

} // namespace anvil

auto main() -> int {
  const std::string text{"external consumer"};
  const auto borrowed = anvil::sdk::as_str(text);
  std::vector<unsigned int> values{1, 2, 3};
  const auto range = anvil::sdk::as_span(values);
  if (anvil::sdk::as_string_view(borrowed) != text || range.len != 3) {
    return 1;
  }

  auto result = anvil::loader::load<anvil::IPlugin>(
      ANVIL_CONSUMER_PLUGIN,
      anvil::loader::AbiRequirement<anvil::AnvilAbiTag>{
          anvil::current_abi_tag, anvil::loader::verify_abi_tag,
          anvil::kAbiTagPrefixSize, anvil::loader::abi_tag_declared_size});
  if (!result) {
    return 1;
  }

  anvil::PluginManifest manifest{};
  if (result->instance->manifest(&manifest) != anvil::PluginStatus::ok ||
      anvil::sdk::as_string_view(manifest.id.value) != "org.example.consumer") {
    return 1;
  }

  auto *door = dynamic_cast<anvil::IDoor *>(result->instance.get());
  return door == nullptr ? 1 : 0;
}
