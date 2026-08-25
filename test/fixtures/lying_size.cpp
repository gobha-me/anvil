#include "plugin_api.hpp"

namespace {

struct PrefixAbiTag {
  uint32_t magic;
  uint32_t struct_size;
  uint16_t interface_major;
  uint16_t interface_minor;
  uint32_t sanitizer_mask;
};

static_assert(sizeof(PrefixAbiTag) == anvil::kAbiTagPrefixSize);

} // namespace

extern "C" ANVIL_TEST_EXPORT const PrefixAbiTag anvil_abi_tag{
    anvil::kAbiMagic,
    sizeof(anvil::AnvilAbiTag),
    anvil::kPluginInterfaceMajor,
    anvil::kPluginInterfaceMinor,
    anvil::current_abi_tag.sanitizer_mask,
};

extern "C" ANVIL_TEST_EXPORT auto anvil_plugin_create() noexcept
    -> TestPlugin * {
  return nullptr;
}

extern "C" ANVIL_TEST_EXPORT auto
anvil_plugin_destroy(TestPlugin *plugin) noexcept -> void {
  delete plugin;
}
