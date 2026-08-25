#include "plugin_api.hpp"

extern "C" ANVIL_TEST_EXPORT const std::uint32_t anvil_abi_tag =
    kExpectedTag.magic;

extern "C" ANVIL_TEST_EXPORT auto anvil_plugin_create() noexcept
    -> TestPlugin * {
  return nullptr;
}

extern "C" ANVIL_TEST_EXPORT auto
anvil_plugin_destroy(TestPlugin *plugin) noexcept -> void {
  delete plugin;
}
